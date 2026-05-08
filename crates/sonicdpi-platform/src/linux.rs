//! Linux backend — NFQUEUE via the pure-Rust `nfq` crate.
//!
//! Rules are installed with `nft` at startup and torn down on close.
//! We use the `inet` family for IPv4+IPv6 in one rule.
//!
//! Privilege: `CAP_NET_ADMIN` (or root). Set with
//! `setcap cap_net_admin=eip ./sonicdpi` or `AmbientCapabilities=` in
//! the systemd unit.

use crate::{Interceptor, InterceptorConfig};
use anyhow::{Context, Result};
use parking_lot::Mutex;
use socket2::{Domain, Protocol, Socket, Type};
use sonicdpi_engine::{Action, Direction, Engine};
use std::process::Command;
use std::sync::OnceLock;

const QUEUE_NUM: u16 = 0;
const NFT_TABLE: &str = "sonicdpi";

pub struct NfqInterceptor {
    queue: Option<nfq::Queue>,
    rules_installed: bool,
}

impl Interceptor for NfqInterceptor {
    fn open(cfg: &InterceptorConfig) -> Result<Self> {
        ensure_capabilities()?;
        install_nft_rules(cfg).context("nftables rule install failed")?;

        let mut q = nfq::Queue::open().context("nfq::Queue::open failed")?;
        q.bind(QUEUE_NUM).context("nfq bind failed")?;
        q.set_copy_range(QUEUE_NUM, 0xffff)?;

        Ok(Self {
            queue: Some(q),
            rules_installed: true,
        })
    }

    fn run(
        &mut self,
        engine: std::sync::Arc<Engine>,
        stop_flag: std::sync::Arc<dyn Fn() -> bool + Send + Sync>,
    ) -> Result<()> {
        let q = self.queue.as_mut().context("queue closed")?;
        while !stop_flag() {
            let mut msg = match q.recv() {
                Ok(m) => m,
                Err(e) => {
                    tracing::warn!(error = %e, "nfq recv");
                    continue;
                }
            };
            let bytes = msg.get_payload().to_vec();
            // OUTPUT chain → outbound by definition.
            let action = crate::dispatch(&engine, bytes, Direction::Outbound);
            match action {
                Action::Pass | Action::PassModified => {
                    msg.set_verdict(nfq::Verdict::Accept);
                }
                Action::Drop => msg.set_verdict(nfq::Verdict::Drop),
                Action::InjectThenPass(fakes) => {
                    for f in fakes {
                        send_raw_packet(&f.bytes)?;
                    }
                    msg.set_verdict(nfq::Verdict::Accept);
                }
                Action::Replace(replacements) => {
                    for r in replacements {
                        send_raw_packet(&r.bytes)?;
                    }
                    msg.set_verdict(nfq::Verdict::Drop);
                }
            }
            if let Err(e) = q.verdict(msg) {
                tracing::warn!(error = %e, "nfq verdict");
            }
        }
        Ok(())
    }

    fn close(&mut self) -> Result<()> {
        if self.rules_installed {
            let _ = uninstall_nft_rules();
            self.rules_installed = false;
        }
        if let Some(q) = self.queue.take() {
            drop(q);
        }
        Ok(())
    }
}

fn ensure_capabilities() -> Result<()> {
    let perm = caps::has_cap(
        None,
        caps::CapSet::Permitted,
        caps::Capability::CAP_NET_ADMIN,
    )
    .unwrap_or(false);
    if !perm {
        anyhow::bail!(
            "missing CAP_NET_ADMIN. Run as root or `sudo setcap cap_net_admin=eip ./sonicdpi`"
        );
    }
    Ok(())
}

fn install_nft_rules(cfg: &InterceptorConfig) -> Result<()> {
    let mut rules = String::new();
    rules.push_str(&format!(
        "table inet {NFT_TABLE} {{\n\
         \tchain out {{\n\
         \t\ttype filter hook output priority -150;\n"
    ));
    if !cfg.tcp_ports.is_empty() {
        let ports = cfg
            .tcp_ports
            .iter()
            .map(u16::to_string)
            .collect::<Vec<_>>()
            .join(", ");
        rules.push_str(&format!(
            "\t\ttcp dport {{ {ports} }} ct state new,established queue num {QUEUE_NUM} bypass\n"
        ));
    }
    for r in &cfg.udp_ports {
        if r.lo == r.hi {
            rules.push_str(&format!(
                "\t\tudp dport {} queue num {QUEUE_NUM} bypass\n",
                r.lo
            ));
        } else {
            rules.push_str(&format!(
                "\t\tudp dport {}-{} queue num {QUEUE_NUM} bypass\n",
                r.lo, r.hi
            ));
        }
    }
    rules.push_str("\t}\n}\n");

    // Atomic install: flush old, load new.
    let _ = Command::new("nft")
        .args(["delete", "table", "inet", NFT_TABLE])
        .status();
    let mut child = Command::new("nft")
        .args(["-f", "-"])
        .stdin(std::process::Stdio::piped())
        .spawn()
        .context("spawn nft")?;
    use std::io::Write;
    child
        .stdin
        .as_mut()
        .context("nft stdin")?
        .write_all(rules.as_bytes())?;
    let st = child.wait()?;
    if !st.success() {
        anyhow::bail!("nft -f exited with {st}");
    }
    tracing::info!(table = NFT_TABLE, "nftables rules installed");
    Ok(())
}

fn uninstall_nft_rules() -> Result<()> {
    let _ = Command::new("nft")
        .args(["delete", "table", "inet", NFT_TABLE])
        .status();
    tracing::info!("nftables rules removed");
    Ok(())
}

/// Cached raw sockets. Opened once per (family × protocol) on first
/// use and reused for every subsequent fake packet on the hot path.
/// Holding the FD across packets avoids syscall overhead and keeps
/// the kernel from log-spamming about repeated SOCK_RAW opens.
static V4_SOCK: OnceLock<Mutex<Socket>> = OnceLock::new();
struct V6Sock {
    /// One socket per next-header (TCP=6, UDP=17). Lazy.
    by_proto: parking_lot::Mutex<std::collections::HashMap<u8, Socket>>,
}
static V6: OnceLock<V6Sock> = OnceLock::new();

fn v4_sock() -> Result<&'static Mutex<Socket>> {
    if let Some(s) = V4_SOCK.get() {
        return Ok(s);
    }
    let sock = Socket::new(
        Domain::IPV4,
        Type::RAW,
        Some(Protocol::from(libc::IPPROTO_RAW)),
    )
    .context("AF_INET SOCK_RAW")?;
    sock.set_header_included_v4(true).ok();
    let _ = V4_SOCK.set(Mutex::new(sock));
    Ok(V4_SOCK.get().expect("just set"))
}

fn v6_sock_for(proto: u8) -> Result<()> {
    let v6 = V6.get_or_init(|| V6Sock {
        by_proto: parking_lot::Mutex::new(Default::default()),
    });
    let mut m = v6.by_proto.lock();
    if !m.contains_key(&proto) {
        let s = Socket::new(Domain::IPV6, Type::RAW, Some(Protocol::from(proto as i32)))
            .context("AF_INET6 SOCK_RAW")?;
        m.insert(proto, s);
    }
    Ok(())
}

/// Send a fully-formed IP packet on a raw socket. The kernel does NOT
/// re-queue packets to our NFQUEUE if `--queue-bypass` is set on the
/// rule, so this is the right primitive for emitting decoys without
/// looping back into ourselves.
fn send_raw_packet(bytes: &[u8]) -> Result<()> {
    use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};

    if bytes.is_empty() {
        return Ok(());
    }
    let version = bytes[0] >> 4;
    match version {
        4 => {
            if bytes.len() < 20 {
                anyhow::bail!("ipv4 packet too short");
            }
            let dst = Ipv4Addr::new(bytes[16], bytes[17], bytes[18], bytes[19]);
            let sock = v4_sock()?.lock();
            let dst_addr = SocketAddr::V4(SocketAddrV4::new(dst, 0));
            sock.send_to(bytes, &dst_addr.into())
                .context("raw send_to v4")?;
        }
        6 => {
            if bytes.len() < 40 {
                anyhow::bail!("ipv6 packet too short");
            }
            let mut a = [0u8; 16];
            a.copy_from_slice(&bytes[24..40]);
            let dst = Ipv6Addr::from(a);
            let next_header = bytes[6];
            v6_sock_for(next_header)?;
            let v6 = V6.get().expect("set above");
            let m = v6.by_proto.lock();
            let sock = m.get(&next_header).context("v6 sock")?;
            let payload = &bytes[40..];
            let dst_addr = SocketAddr::V6(SocketAddrV6::new(dst, 0, 0, 0));
            sock.send_to(payload, &dst_addr.into())
                .context("raw send_to v6")?;
        }
        v => anyhow::bail!("unknown IP version {v}"),
    }
    Ok(())
}
