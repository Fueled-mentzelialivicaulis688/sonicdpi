//! Windows backend — WinDivert.
//!
//! Opens a single NETWORK-layer handle with a filter that captures all
//! TCP/UDP traffic to our target ports. Each captured packet is run
//! through the engine; based on the resulting `Action` we either
//! reinject as-is, mangle, drop, or inject extra fakes.
//!
//! Privilege: Administrator on first run (driver service install).
//! WinDivert64.sys is bundled via the `vendored` feature of the
//! `windivert` crate.
//!
//! Note on shutdown: `recv()` is blocking and there's no built-in
//! timeout. The CLI catches Ctrl-C and the process exits, releasing
//! the driver handle. Cooperative-stop polling between packets is
//! good enough at v0.2 — graceful shutdown via `WinDivert::shutdown`
//! from a side thread is a v0.3 polish item.

use crate::{Interceptor, InterceptorConfig};
use anyhow::{Context, Result};
use sonicdpi_engine::{Action, Direction, Engine};
use std::sync::Arc;
use windivert::layer::NetworkLayer;
use windivert::packet::WinDivertPacket;
use windivert::prelude::WinDivertFlags;
use windivert::WinDivert;

pub struct WinDivertInterceptor {
    handle: Option<WinDivert<NetworkLayer>>,
}

impl Interceptor for WinDivertInterceptor {
    fn open(cfg: &InterceptorConfig) -> Result<Self> {
        if !is_elevated() {
            anyhow::bail!(
                "Administrator privileges required. Re-launch from an elevated PowerShell or use `sonicdpi install` to register the system service."
            );
        }
        let filter = build_filter(cfg);
        tracing::info!(filter_len = filter.len(), filter = %filter, "opening WinDivert (about to call network())");

        // The actual native call lives on its own thread with a fat
        // stack so a panic / stack-overflow inside windivert-sys'
        // C bindings doesn't kill the entire process. We `join()` and
        // surface any error as a normal Result.
        let filter_owned = filter.clone();
        let join = std::thread::Builder::new()
            .name("windivert-open".into())
            .stack_size(64 * 1024 * 1024)
            .spawn(move || {
                WinDivert::<NetworkLayer>::network(filter_owned.as_str(), 0, WinDivertFlags::new())
            })
            .map_err(|e| anyhow::anyhow!("spawn windivert-open thread: {e}"))?;

        let handle = match join.join() {
            Ok(Ok(h)) => h,
            Ok(Err(e)) => {
                anyhow::bail!("WinDivert::network failed: {e} (driver loadable? security software? filter syntax?)")
            }
            Err(panic) => {
                let msg = panic
                    .downcast_ref::<&str>()
                    .copied()
                    .or_else(|| panic.downcast_ref::<String>().map(|s| s.as_str()))
                    .unwrap_or("native panic / stack overflow");
                anyhow::bail!("WinDivert::network panicked: {msg}")
            }
        };
        tracing::info!("WinDivert::network() returned OK");

        Ok(Self {
            handle: Some(handle),
        })
    }

    fn run(
        &mut self,
        engine: Arc<Engine>,
        stop_flag: Arc<dyn Fn() -> bool + Send + Sync>,
    ) -> Result<()> {
        let h = self.handle.as_ref().context("interceptor not open")?;
        let mut buf = vec![0u8; 65_535];
        loop {
            if stop_flag() {
                break;
            }
            let pkt = match h.recv(Some(&mut buf)) {
                Ok(p) => p,
                Err(e) => {
                    tracing::warn!(error = ?e, "WinDivert recv error");
                    continue;
                }
            };
            let direction = if pkt.address.outbound() {
                Direction::Outbound
            } else {
                Direction::Inbound
            };
            let bytes = pkt.data.as_ref().to_vec();
            let address = pkt.address.clone();
            let outbound = pkt.address.outbound();

            match crate::dispatch(&engine, bytes, direction) {
                Action::Pass | Action::PassModified => {
                    let _ = h.send(&pkt);
                }
                Action::Drop => {
                    // do nothing — packet is dropped by not re-injecting
                }
                Action::InjectThenPass(fakes) => {
                    for f in fakes {
                        if let Err(e) = inject(h, &address, outbound, f.bytes) {
                            tracing::warn!(error = ?e, "fake inject failed");
                        }
                    }
                    let _ = h.send(&pkt);
                }
                Action::Replace(replacements) => {
                    for r in replacements {
                        if let Err(e) = inject(h, &address, outbound, r.bytes) {
                            tracing::warn!(error = ?e, "replacement inject failed");
                        }
                    }
                    // Original is dropped by not re-injecting.
                }
            }
        }
        Ok(())
    }

    fn close(&mut self) -> Result<()> {
        // Taking the Option drops the handle implicitly when scope ends.
        let _ = self.handle.take();
        Ok(())
    }
}

fn inject(
    handle: &WinDivert<NetworkLayer>,
    template_addr: &windivert::address::WinDivertAddress<NetworkLayer>,
    outbound: bool,
    bytes: Vec<u8>,
) -> Result<()> {
    // Clone the captured packet's address so the synthetic packet
    // inherits the correct interface index, sub-layer, etc. WinDivert
    // requires this for outbound-direction packets to be routed via
    // the same NIC the original came from. We then override only the
    // outbound flag (already correct) and the impostor flag, which
    // tells WinDivert this is OUR fake and should not loop back into
    // our own NETWORK-layer filter.
    let mut pkt = WinDivertPacket {
        address: template_addr.clone(),
        data: std::borrow::Cow::Owned(bytes),
    };
    pkt.address.set_outbound(outbound);
    pkt.address.set_impostor(true);

    handle
        .send(&pkt)
        .map_err(|e| anyhow::anyhow!("WinDivert::send: {e}"))?;
    Ok(())
}

/// Check whether the current process token has elevated privileges.
fn is_elevated() -> bool {
    use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
    use windows_sys::Win32::Security::{
        GetTokenInformation, TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY,
    };
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    unsafe {
        let mut token: HANDLE = std::ptr::null_mut();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
            return false;
        }
        let mut elevation = TOKEN_ELEVATION { TokenIsElevated: 0 };
        let mut ret_len: u32 = 0;
        let ok = GetTokenInformation(
            token,
            TokenElevation,
            &mut elevation as *mut _ as *mut _,
            std::mem::size_of::<TOKEN_ELEVATION>() as u32,
            &mut ret_len,
        );
        let elevated = ok != 0 && elevation.TokenIsElevated != 0;
        CloseHandle(token);
        elevated
    }
}

fn build_filter(cfg: &InterceptorConfig) -> String {
    let mut clauses: Vec<String> = Vec::new();
    if !cfg.tcp_ports.is_empty() {
        let or = cfg
            .tcp_ports
            .iter()
            .map(|p| format!("tcp.DstPort=={p}"))
            .collect::<Vec<_>>()
            .join(" or ");
        clauses.push(format!("({or})"));
    }
    if !cfg.udp_ports.is_empty() {
        let or = cfg
            .udp_ports
            .iter()
            .map(|r| {
                if r.lo == r.hi {
                    format!("udp.DstPort=={}", r.lo)
                } else {
                    format!("(udp.DstPort >= {} and udp.DstPort <= {})", r.lo, r.hi)
                }
            })
            .collect::<Vec<_>>()
            .join(" or ");
        clauses.push(format!("({or})"));
    }
    if cfg.include_inbound {
        format!("!loopback and ({})", clauses.join(" or "))
    } else {
        format!("outbound and !loopback and ({})", clauses.join(" or "))
    }
}
