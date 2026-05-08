//! macOS NetworkExtension bridge.
//!
//! Apple gates packet filtering on modern macOS through the
//! `NetworkExtension` framework. The packet-filter type that gives us
//! per-packet inspect+modify is `NEFilterPacketProvider` (introduced
//! in macOS 10.15). It must live inside a System Extension bundled
//! into the host `.app`, signed with `Developer ID` and shipped with
//! the entitlement `com.apple.developer.networking.networkextension`
//! (which Apple grants on a per-app review basis).
//!
//! This crate is the Rust core loaded by the Swift `NEFilterPacketProvider`
//! subclass. The FFI surface is intentionally tiny:
//!
//!   - `sonicdpi_nex_init(profile_name, profile_name_len)` — load engine
//!     once on extension startup.
//!   - `sonicdpi_nex_process(bytes, len, direction) -> Verdict` — called
//!     for every packet. Returns one of `PASS / DROP / MODIFIED`. When
//!     `MODIFIED`, the modified payload is read via `sonicdpi_nex_take_modified`.
//!   - `sonicdpi_nex_take_modified(out_buf, out_cap) -> usize` — copies
//!     the last modified packet bytes into Swift-side buffer.
//!   - `sonicdpi_nex_shutdown()` — stop logging, drop engine.
//!
//! The whole module is feature-gated behind `cfg(target_os = "macos")`
//! so this crate compiles into an empty cdylib on Linux/Windows CI runs
//! (we keep it in the workspace for unified `cargo build --workspace`).

#![cfg_attr(not(target_os = "macos"), allow(unused_imports))]

#[cfg(target_os = "macos")]
mod ffi;

#[cfg(target_os = "macos")]
pub use ffi::*;
