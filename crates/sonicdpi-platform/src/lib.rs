//! Platform-specific packet interception.
//!
//! Each backend exposes the same `Interceptor` trait. The CLI picks
//! the right one for the current OS at compile time.
//!
//! # Threading model
//!
//! The interceptor runs in a dedicated OS thread (recv is blocking on
//! all three backends). Packets are handed to the engine
//! synchronously and re-injected on the same thread to keep latency
//! predictable.

use anyhow::Result;
use sonicdpi_engine::{Direction, Engine};
use std::sync::Arc;

#[cfg(target_os = "windows")]
mod windows;
#[cfg(target_os = "windows")]
pub use windows::WinDivertInterceptor as DefaultInterceptor;

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
pub use linux::NfqInterceptor as DefaultInterceptor;

#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "macos")]
pub use macos::PfRdrInterceptor as DefaultInterceptor;

/// What the CLI hands a backend at startup.
#[derive(Debug, Clone)]
pub struct InterceptorConfig {
    /// TCP destination ports to intercept (typical: 80, 443).
    pub tcp_ports: Vec<u16>,
    /// UDP destination ports to intercept (443 + Discord voice ranges).
    pub udp_ports: Vec<PortRange>,
    /// Hand the engine inbound traffic too? (Required for some
    /// strategies that need to track server seq numbers.) Default
    /// false in v0.1 — outbound-only is enough for fake/split.
    pub include_inbound: bool,
}

#[derive(Debug, Clone, Copy)]
pub struct PortRange {
    pub lo: u16,
    pub hi: u16,
}

impl PortRange {
    pub fn single(port: u16) -> Self {
        Self { lo: port, hi: port }
    }
}

/// Common interface every backend implements.
pub trait Interceptor: Send {
    /// Open the OS hook. May install firewall rules / load drivers.
    fn open(cfg: &InterceptorConfig) -> Result<Self>
    where
        Self: Sized;

    /// Run forever, dispatching every captured packet through the engine.
    /// Returns when the underlying source is closed or `stop_flag` fires.
    /// `engine` is shared via `Arc` so backends that spawn per-connection
    /// threads (macOS) can hand it across thread boundaries.
    fn run(
        &mut self,
        engine: Arc<Engine>,
        stop_flag: Arc<dyn Fn() -> bool + Send + Sync>,
    ) -> Result<()>;

    /// Tear down firewall rules and close handles.
    fn close(&mut self) -> Result<()>;
}

/// Helper used by all backends: convert `(bytes, direction)` from the
/// OS into an `Engine` decision and back into action bytes.
pub(crate) fn dispatch(
    engine: &Engine,
    bytes: Vec<u8>,
    direction: Direction,
) -> sonicdpi_engine::Action {
    use sonicdpi_engine::Packet;
    match Packet::parse(bytes, direction) {
        Some(mut pkt) => engine.handle(&mut pkt),
        None => sonicdpi_engine::Action::Pass,
    }
}
