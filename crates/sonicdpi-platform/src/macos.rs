//! macOS backend — pf rdr-to + transparent TCP proxy.
//!
//! Background: `IPPROTO_DIVERT` was removed from the XNU kernel and
//! `pf`'s `divert-to` is half-broken on Sequoia/Tahoe per Apple dev
//! forum reports. The pragmatic path that ships today (zapret-mac,
//! byedpi) is:
//!
//!   1. Install a pf anchor that redirects target TCP traffic to a
//!      local listener (e.g. 127.0.0.1:7443).
//!   2. Accept on that listener; recover the original destination via
//!      the `DIOCNATLOOK` ioctl on `/dev/pf`.
//!   3. Open an upstream TCP socket to the original destination and
//!      proxy bytes back and forth, applying ClientHello-mangling
//!      strategies on the FIRST chunk we forward upstream.
//!
//! Limitations of this v0.2 macOS backend:
//!   * **TCP only.** UDP (Discord voice, YouTube QUIC) is NOT
//!     intercepted. The production path is to ship a NetworkExtension
//!     System Extension (`NEFilterPacketProvider`) packaged in a
//!     `.app` bundle with the
//!     `com.apple.developer.networking.networkextension` entitlement.
//!   * Privilege: requires root (or `/dev/pf` rw access) to load the
//!     pf anchor and run the DIOCNATLOOK ioctl.

use crate::{Interceptor, InterceptorConfig};
use anyhow::{Context, Result};
use sonicdpi_engine::{proxy, Engine};
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpListener, TcpStream};
use std::os::unix::io::AsRawFd;
use std::process::Command;
use std::time::Duration;

pub struct PfRdrInterceptor {
    listener_port: u16,
    anchor_loaded: bool,
}

const ANCHOR: &str = "sonicdpi";

impl Interceptor for PfRdrInterceptor {
    fn open(cfg: &InterceptorConfig) -> Result<Self> {
        ensure_root().context("macOS pf rdr-to requires root or /dev/pf rw")?;
        let listener_port = 7443;
        load_pf_anchor(cfg, listener_port)?;
        Ok(Self {
            listener_port,
            anchor_loaded: true,
        })
    }

    fn run(
        &mut self,
        engine: std::sync::Arc<Engine>,
        stop_flag: std::sync::Arc<dyn Fn() -> bool + Send + Sync>,
    ) -> Result<()> {
        let listener = TcpListener::bind(("127.0.0.1", self.listener_port))
            .context("transparent proxy bind")?;
        listener
            .set_nonblocking(true)
            .context("listener nonblocking")?;
        tracing::info!(
            port = self.listener_port,
            "macOS transparent proxy listening"
        );

        while !stop_flag() {
            match listener.accept() {
                Ok((conn, peer)) => {
                    let _ = conn.set_nonblocking(false);
                    let engine = engine.clone();
                    std::thread::spawn(move || {
                        if let Err(e) = handle_conn(conn, peer, &engine) {
                            tracing::warn!(error = %e, "macOS proxy connection error");
                        }
                    });
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(50));
                }
                Err(e) => tracing::warn!(error = %e, "accept"),
            }
        }
        Ok(())
    }

    fn close(&mut self) -> Result<()> {
        if self.anchor_loaded {
            let _ = unload_pf_anchor();
            self.anchor_loaded = false;
        }
        Ok(())
    }
}

fn ensure_root() -> Result<()> {
    let uid = unsafe { libc::getuid() };
    if uid != 0 {
        anyhow::bail!("not running as root");
    }
    Ok(())
}

fn load_pf_anchor(cfg: &InterceptorConfig, listener_port: u16) -> Result<()> {
    let mut conf = String::new();
    if !cfg.tcp_ports.is_empty() {
        let ports = cfg
            .tcp_ports
            .iter()
            .map(u16::to_string)
            .collect::<Vec<_>>()
            .join(", ");
        conf.push_str(&format!(
            "rdr on en0 inet  proto tcp from any to any port {{ {ports} }} -> 127.0.0.1 port {listener_port}\n\
             rdr on en0 inet6 proto tcp from any to any port {{ {ports} }} -> 127.0.0.1 port {listener_port}\n"
        ));
    }
    let path = format!("/tmp/sonicdpi_anchor_{ANCHOR}.conf");
    std::fs::write(&path, &conf)?;
    let st = Command::new("pfctl")
        .args(["-a", ANCHOR, "-f", &path])
        .status()?;
    if !st.success() {
        anyhow::bail!("pfctl exited with {st}");
    }
    let _ = Command::new("pfctl").args(["-e"]).status();
    tracing::info!(anchor = ANCHOR, "pf anchor loaded");
    Ok(())
}

fn unload_pf_anchor() -> Result<()> {
    let _ = Command::new("pfctl")
        .args(["-a", ANCHOR, "-F", "all"])
        .status();
    tracing::info!(anchor = ANCHOR, "pf anchor flushed");
    Ok(())
}

// ----- per-connection handler ------------------------------------

fn handle_conn(client: TcpStream, peer: SocketAddr, engine: &Engine) -> Result<()> {
    let local = client.local_addr().context("local_addr")?;
    let orig_dst = pf_natlook(peer, local).context("DIOCNATLOOK")?;
    tracing::debug!(?peer, ?orig_dst, "recovered original destination");

    let upstream = TcpStream::connect_timeout(&orig_dst, Duration::from_secs(10))
        .context("upstream connect")?;
    let _ = upstream.set_nodelay(true);

    // Read first chunk from client (typically the ClientHello).
    let mut client_r = client.try_clone()?;
    let mut client_w = client;
    let mut up_r = upstream.try_clone()?;
    let mut up_w = upstream;

    let mut first = vec![0u8; 16 * 1024];
    let n = client_r.read(&mut first)?;
    first.truncate(n);

    // Wrap the first chunk as a synthetic Packet so the engine can
    // identify the target. The platform here is "transparent proxy",
    // so we don't have IP/TCP headers for the payload — we synthesize
    // a fake outbound packet just to feed the SNI matcher.
    if n > 0 {
        let plan = engine_mangle_first_chunk_writes(&first, engine);
        for write in plan.writes {
            up_w.write_all(&write.bytes)?;
            up_w.flush().ok();
            if !write.delay_after.is_zero() {
                std::thread::sleep(write.delay_after);
            }
        }
    }

    // Bidirectional splice.
    let t1 = std::thread::spawn(move || {
        let _ = std::io::copy(&mut client_r, &mut up_w);
    });
    let t2 = std::thread::spawn(move || {
        let _ = std::io::copy(&mut up_r, &mut client_w);
    });
    let _ = t1.join();
    let _ = t2.join();
    Ok(())
}

/// Apply byte-level mangling to the first chunk read from the client.
/// Engine returns a series of writes (with optional inter-write
/// delays) which we splice to the upstream socket. Strategies that
/// require IP-layer manipulation (fake-multidisorder with TTL/MD5SIG
/// fooling) are not available in this path — `process_first_chunk`
/// transparently falls back to multisplit or passthrough.
fn engine_mangle_first_chunk_writes(first: &[u8], engine: &Engine) -> proxy::ProxyPlan {
    proxy::process_first_chunk(first, engine.profile())
}

// ----- DIOCNATLOOK ioctl ------------------------------------------

#[repr(C)]
#[allow(non_camel_case_types)]
struct pfioc_natlook {
    saddr: pf_addr,
    daddr: pf_addr,
    rsaddr: pf_addr,
    rdaddr: pf_addr,
    sxport: pf_port,
    dxport: pf_port,
    rsxport: pf_port,
    rdxport: pf_port,
    af: u8,
    proto: u8,
    proto_variant: u8,
    direction: u8,
}

#[repr(C)]
#[derive(Copy, Clone)]
union pf_addr {
    v4: [u8; 4],
    v6: [u8; 16],
    raw: [u8; 16],
}

#[repr(C)]
#[derive(Copy, Clone)]
union pf_port {
    port: u16,
    icmp_id: u16,
    raw: [u8; 4],
}

const PF_OUT: u8 = 2;
const DIOCNATLOOK: libc::c_ulong = 0xC0544417; // approximate; verified empirically against macOS Sequoia

fn pf_natlook(client: SocketAddr, local: SocketAddr) -> Result<SocketAddr> {
    let pf = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/pf")
        .context("open /dev/pf (root required)")?;
    let mut nl: pfioc_natlook = unsafe { std::mem::zeroed() };
    match (client.ip(), local.ip()) {
        (IpAddr::V4(c), IpAddr::V4(l)) => {
            nl.af = libc::AF_INET as u8;
            nl.saddr.v4 = c.octets();
            nl.daddr.v4 = l.octets();
            nl.sxport.port = client.port().to_be();
            nl.dxport.port = local.port().to_be();
        }
        (IpAddr::V6(c), IpAddr::V6(l)) => {
            nl.af = libc::AF_INET6 as u8;
            nl.saddr.v6 = c.octets();
            nl.daddr.v6 = l.octets();
            nl.sxport.port = client.port().to_be();
            nl.dxport.port = local.port().to_be();
        }
        _ => anyhow::bail!("mixed-family natlook"),
    }
    nl.proto = libc::IPPROTO_TCP as u8;
    nl.direction = PF_OUT;

    let rc = unsafe { libc::ioctl(pf.as_raw_fd(), DIOCNATLOOK, &mut nl) };
    if rc != 0 {
        return Err(std::io::Error::last_os_error()).context("DIOCNATLOOK");
    }
    let port = u16::from_be(unsafe { nl.rdxport.port });
    let ip = match nl.af as i32 {
        libc::AF_INET => IpAddr::V4(Ipv4Addr::from(unsafe { nl.rdaddr.v4 })),
        libc::AF_INET6 => IpAddr::V6(Ipv6Addr::from(unsafe { nl.rdaddr.v6 })),
        _ => anyhow::bail!("unknown af in natlook reply"),
    };
    Ok(SocketAddr::new(ip, port))
}

