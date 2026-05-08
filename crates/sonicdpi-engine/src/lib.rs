//! SonicDPI core engine.
//!
//! This crate is platform-agnostic. It receives parsed packets from a
//! platform backend (`sonicdpi-platform`), tracks per-flow state,
//! identifies target traffic (YouTube / Discord), and asks a strategy
//! pipeline what action to take.
//!
//! The design goals are:
//!  - zero allocation on the hot path once a flow is established;
//!  - strategies are composable and configurable from a profile file;
//!  - new evasion tricks can be added without touching platform code.

pub mod action;
pub mod builder;
pub mod dns;
pub mod embedded_fakes;
pub mod fakes;
pub mod flow;
pub mod fooling;
pub mod packet;
pub mod probing;
pub mod profile;
pub mod proxy;
pub mod strategy;
pub mod target;
pub mod tls;

pub use action::{Action, FakePacket};
pub use dns::DnsCache;
pub use flow::{Direction, Flow, FlowKey, FlowTable, L4Proto};
pub use packet::Packet;
pub use profile::Profile;
pub use strategy::{Fooling, Strategy, StrategyPipeline};
pub use target::{Target, TargetSet};

use parking_lot::Mutex;
use std::sync::Arc;

/// The high-level engine an OS backend talks to.
pub struct Engine {
    flows: Arc<Mutex<FlowTable>>,
    pipeline: StrategyPipeline,
    targets: TargetSet,
    dns: Arc<DnsCache>,
    profile: Profile,
}

impl Engine {
    pub fn new(profile: Profile) -> Self {
        Self {
            flows: Arc::new(Mutex::new(FlowTable::new())),
            pipeline: profile.build_pipeline(),
            targets: profile.targets.clone(),
            dns: Arc::new(DnsCache::new()),
            profile,
        }
    }

    pub fn profile(&self) -> &Profile {
        &self.profile
    }

    /// Process a single packet from the OS interceptor.
    /// Returns the action the platform layer must execute.
    pub fn handle(&self, pkt: &mut Packet) -> Action {
        // 1. Always observe DNS responses regardless of flow target,
        //    so the cache stays warm for future flows.
        dns::observe_dns(pkt, &self.targets, &self.dns);

        let key = match pkt.flow_key() {
            Some(k) => k,
            None => return Action::Pass,
        };

        let mut flows = self.flows.lock();
        let flow = flows.entry(key);
        flow.observe(pkt);

        if !flow.target_resolved {
            if let Some(t) = self.targets.identify(pkt, flow) {
                tracing::debug!(target = ?t, dst = %pkt.dst, dst_port = pkt.dst_port, "flow classified by SNI/QUIC/RTP");
                flow.target = Some(t);
            } else if let Some(t) = self.dns.lookup(&pkt.dst) {
                let upgraded = match (t, pkt.proto) {
                    (Target::YouTube, L4Proto::Udp) => Target::YouTubeQuic,
                    _ => t,
                };
                tracing::debug!(target = ?upgraded, dst = %pkt.dst, "flow classified by DNS cache");
                flow.target = Some(upgraded);
            }
            flow.target_resolved = flow.hello_seen || flow.packet_count > 4;
        }

        // 2. INBOUND TCP path: kill-rst before anything else.
        //    On the first inbound TCP packet of a target flow we learn
        //    the server's baseline TTL. Any subsequent inbound RST
        //    arriving with a markedly different TTL is almost
        //    certainly a TSPU-forged reset injected to kill the
        //    connection at handshake time. We drop it; the client
        //    TCP stack never sees the RST and the handshake can
        //    complete normally.
        if matches!(pkt.direction, Direction::Inbound) && pkt.proto == L4Proto::Tcp {
            flow.inbound_count = flow.inbound_count.saturating_add(1);
            let cur_ttl = pkt.ttl();

            // Learn baseline from first non-RST inbound packet (usually SYN-ACK).
            if flow.baseline_inbound_ttl.is_none() && !pkt.is_tcp_rst() && cur_ttl > 0 {
                flow.baseline_inbound_ttl = Some(cur_ttl);
                tracing::debug!(
                    dst = %pkt.dst,
                    dst_port = pkt.dst_port,
                    baseline_ttl = cur_ttl,
                    "kill-rst: learned server baseline TTL"
                );
            }

            // Forged-RST detection — only on target flows (don't disrupt
            // legitimate non-target traffic) within the first ~30
            // inbound packets (the handshake window where TSPU strikes).
            if pkt.is_tcp_rst() && flow.target.is_some() && flow.inbound_count <= 30 {
                if let Some(baseline) = flow.baseline_inbound_ttl {
                    let diff = (cur_ttl as i32 - baseline as i32).unsigned_abs();
                    if diff > 5 {
                        flow.killed_rsts = flow.killed_rsts.saturating_add(1);
                        tracing::info!(
                            dst = %pkt.dst,
                            dst_port = pkt.dst_port,
                            baseline_ttl = baseline,
                            rst_ttl = cur_ttl,
                            diff,
                            killed = flow.killed_rsts,
                            "kill-rst: dropped likely-forged TSPU RST"
                        );
                        return Action::Drop;
                    }
                }
            }
        }

        // Always run the pipeline. Strategies that need a classified
        // target gate themselves on `flow.target`; strategies that
        // don't (e.g., TcpMssClamp on outbound SYN) operate on raw
        // IP/TCP fields and need to fire before SNI is even visible.
        // Cost of running the pipeline on a non-target packet is
        // ~one short-circuit per strategy ≈ a few hundred ns —
        // negligible at typical desktop packet rates.
        self.pipeline.run(pkt, flow)
    }

    pub fn flow_count(&self) -> usize {
        self.flows.lock().len()
    }

    pub fn dns_cache_size(&self) -> usize {
        self.dns.len()
    }
}
