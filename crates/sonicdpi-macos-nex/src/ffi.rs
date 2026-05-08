//! C-ABI surface used by the Swift `NEFilterPacketProvider` subclass.
//!
//! Lifetime model: Swift calls `sonicdpi_nex_init` once on
//! `startFilter(completionHandler:)`, then `sonicdpi_nex_process`
//! per packet on the provider's dispatch queue. We hold engine state
//! in a process-global `OnceCell` because `NEFilterPacketProvider` only
//! ever has one live instance per System Extension at a time.

use once_cell::sync::OnceCell;
use parking_lot::Mutex;
use sonicdpi_engine::{Action, Direction, Engine, Packet, Profile};
use std::sync::Arc;

/// Verdict codes returned to the Swift caller. Mirror these in the
/// Swift `enum Verdict`.
#[repr(u8)]
pub enum Verdict {
    Pass = 0,
    Drop = 1,
    Modified = 2,
}

struct State {
    engine: Arc<Engine>,
    /// Holds the *most recently produced* modified packet bytes. The
    /// Swift side calls `sonicdpi_nex_take_modified` immediately after
    /// seeing `Verdict::Modified`. Single-buffer ok because we serialize
    /// access on the provider's dispatch queue (NEFilterPacketProvider
    /// guarantees ordered delivery).
    last_modified: Mutex<Vec<u8>>,
}

static STATE: OnceCell<State> = OnceCell::new();

/// Initialize the engine with a built-in profile name.
/// Returns 0 on success, non-zero on error.
#[no_mangle]
pub unsafe extern "C" fn sonicdpi_nex_init(
    profile_name: *const u8,
    profile_name_len: usize,
) -> i32 {
    if profile_name.is_null() {
        return -1;
    }
    let name_bytes = std::slice::from_raw_parts(profile_name, profile_name_len);
    let name = match std::str::from_utf8(name_bytes) {
        Ok(s) => s,
        Err(_) => return -2,
    };
    let profile = match name {
        "youtube-discord" => Profile::builtin_youtube_discord(),
        "youtube-discord-aggressive" => Profile::builtin_aggressive(),
        "youtube-discord-multidisorder" => Profile::builtin_multidisorder(),
        "youtube-discord-seqovl" => Profile::builtin_alt_seqovl(),
        "youtube-discord-hostfakesplit" => Profile::builtin_alt_hostfakesplit(),
        _ => return -3,
    };
    let engine = Arc::new(Engine::new(profile));
    let state = State {
        engine,
        last_modified: Mutex::new(Vec::new()),
    };
    STATE.set(state).map_err(|_| ()).ok(); // double-init = no-op
    tracing::info!(profile = %name, "macOS NEX engine initialized");
    0
}

/// Inspect (and optionally modify) one packet. Called on the
/// `NEFilterPacketProvider`'s dispatch queue.
///
/// Direction: 0 = outbound (host → world), 1 = inbound.
///
/// Returns one of `Verdict::*`.
///
/// When the return is `Verdict::Modified`, the caller MUST then call
/// `sonicdpi_nex_take_modified(out, cap)` on the same thread to retrieve
/// the new bytes before processing the next packet.
#[no_mangle]
pub unsafe extern "C" fn sonicdpi_nex_process(bytes: *const u8, len: usize, direction: u8) -> u8 {
    let Some(state) = STATE.get() else {
        return Verdict::Pass as u8;
    };
    if bytes.is_null() || len == 0 {
        return Verdict::Pass as u8;
    }

    let dir = if direction == 0 {
        Direction::Outbound
    } else {
        Direction::Inbound
    };

    let owned = std::slice::from_raw_parts(bytes, len).to_vec();
    let Some(mut pkt) = Packet::parse(owned, dir) else {
        return Verdict::Pass as u8;
    };

    match state.engine.handle(&mut pkt) {
        Action::Pass => Verdict::Pass as u8,
        // PassModified = engine mutated `pkt.bytes` in place (e.g.
        // mss-clamp on a SYN). Surface it as MODIFIED with the
        // mutated bytes; Swift will then `take_modified` and inject.
        Action::PassModified => {
            *state.last_modified.lock() = pkt.bytes.clone();
            Verdict::Modified as u8
        }
        Action::Drop => Verdict::Drop as u8,
        Action::Replace(packets) | Action::InjectThenPass(packets) => {
            // For NEX we only support a single replacement packet per
            // input packet (Apple's API model). If the engine wants to
            // emit a burst (e.g. discord-voice-prime sends multiple
            // fakes before the real datagram), the Swift side has to
            // call `packetFlow.writeMessages([NEPacket]...)` separately
            // for each — the API works but takes additional plumbing
            // we'll wire up in a follow-up.
            if let Some(first) = packets.into_iter().next() {
                *state.last_modified.lock() = first.bytes;
                Verdict::Modified as u8
            } else {
                Verdict::Pass as u8
            }
        }
    }
}

/// Copy the last modified packet bytes into the Swift-side buffer.
/// Returns the actual length copied; 0 if no buffered data or buffer
/// too small.
#[no_mangle]
pub unsafe extern "C" fn sonicdpi_nex_take_modified(out_buf: *mut u8, out_cap: usize) -> usize {
    let Some(state) = STATE.get() else {
        return 0;
    };
    let mut buf = state.last_modified.lock();
    if buf.is_empty() || out_buf.is_null() || out_cap < buf.len() {
        return 0;
    }
    std::ptr::copy_nonoverlapping(buf.as_ptr(), out_buf, buf.len());
    let n = buf.len();
    buf.clear();
    n
}

/// Tear down the engine. Swift calls this from
/// `stopFilter(with reason:completionHandler:)`.
#[no_mangle]
pub unsafe extern "C" fn sonicdpi_nex_shutdown() {
    tracing::info!("macOS NEX engine shutdown");
    // OnceCell can't be cleared, but the next process restart re-runs
    // init. NEFilterPacketProvider lifecycle is process-bound, so the
    // System Extension restarts cleanly anyway.
}
