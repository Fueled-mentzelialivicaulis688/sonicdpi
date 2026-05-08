//! What the engine asks the platform backend to do with a packet.

#[derive(Debug, Clone)]
pub enum Action {
    /// Forward the packet unchanged.
    Pass,
    /// Drop the packet.
    Drop,
    /// Forward the (already-mutated-in-place) packet.
    PassModified,
    /// Send these synthetic packets *first*, then the original (or its
    /// mutated form). Used for fake-TTL desync, pre-segments, etc.
    InjectThenPass(Vec<FakePacket>),
    /// Replace the original with a list of crafted packets. Used when
    /// a single segment is split into N fragments.
    Replace(Vec<FakePacket>),
}

#[derive(Debug, Clone)]
pub struct FakePacket {
    /// Full IP+L4+payload bytes ready for re-injection.
    pub bytes: Vec<u8>,
    /// Suggested TTL override; some strategies need TTL=2..5 so the
    /// packet dies between client and DPI box. `None` means use system
    /// default.
    pub ttl_override: Option<u8>,
}
