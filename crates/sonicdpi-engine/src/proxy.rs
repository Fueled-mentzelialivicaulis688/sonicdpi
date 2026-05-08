//! Byte-level strategy variants for transparent-proxy mode (macOS).
//!
//! In packet-mode the engine operates on full IP+TCP datagrams and
//! emits modified packets. In proxy-mode (where macOS pf rdr-to has
//! converted the flow into a regular TCP socket) we have a byte
//! stream and can only influence what we *write* and *when*.
//!
//! The two effective transformations in this mode are:
//!   1. **Multisplit**: write the first chunk in two separate `Write`s
//!      with a deliberate sleep between them. The kernel emits two
//!      MSS-bounded segments; many DPIs that only inspect the first
//!      segment fail to see the SNI in the second.
//!   2. **HostFakeSplit**: rewrite the SNI label inside the
//!      ClientHello to a same-length benign domain on the FIRST write,
//!      then send the original on the SECOND write so the server gets
//!      the right SNI on retry. (Only works if the upstream is forgiving
//!      — for TLS 1.3 it usually fails since the server commits after
//!      the first ClientHello. Useful only as an alt strategy.)
//!
//! `process_first_chunk` returns a list of writes the proxy should
//! perform back-to-back, optionally with a small inter-write delay.

use crate::fakes::rewrite_sni_same_length;
use crate::profile::Profile;
use crate::target::{Target, TargetSet};
use crate::tls::{extract_sni, is_client_hello};
use std::time::Duration;

#[derive(Debug, Clone)]
pub struct ProxyWrite {
    pub bytes: Vec<u8>,
    /// Sleep this long *after* writing these bytes before the next chunk.
    pub delay_after: Duration,
}

#[derive(Debug, Clone)]
pub struct ProxyPlan {
    pub writes: Vec<ProxyWrite>,
}

impl ProxyPlan {
    fn passthrough(bytes: Vec<u8>) -> Self {
        Self {
            writes: vec![ProxyWrite {
                bytes,
                delay_after: Duration::ZERO,
            }],
        }
    }
}

/// Decide what to do with the first chunk read from the client. The
/// caller (macOS proxy handler) writes each `ProxyWrite::bytes` to
/// the upstream socket in order, sleeping `delay_after` between them.
pub fn process_first_chunk(first: &[u8], profile: &Profile) -> ProxyPlan {
    let target = match identify(first, &profile.targets) {
        Some(t) => t,
        None => return ProxyPlan::passthrough(first.to_vec()),
    };

    if !is_client_hello(first) {
        return ProxyPlan::passthrough(first.to_vec());
    }

    // Strategy precedence:
    //   1. host-fake-split (rewrite SNI, two writes)
    //   2. multisplit (two writes with delay)
    //   3. passthrough
    if let Some(cfg) = profile.strategies.host_fake_split.first() {
        if let Some(plan) = plan_host_fake_split(first, &cfg.fake_host) {
            tracing::debug!(?target, "proxy: host-fake-split");
            return plan;
        }
    }
    // Use the FIRST configured tls_multisplit (proxy mode is per-host
    // anyway, target_filter is not relevant — the connection has
    // already been classified as a target before we get here).
    if let Some(cfg) = profile.strategies.tls_multisplit.first() {
        if let Some(plan) = plan_multisplit(first, cfg.split_pos) {
            tracing::debug!(?target, "proxy: multisplit");
            return plan;
        }
    }

    ProxyPlan::passthrough(first.to_vec())
}

fn identify(first: &[u8], targets: &TargetSet) -> Option<Target> {
    let host = extract_sni(first)?;
    for (needle, t) in &targets.sni_patterns {
        if host == *needle || host.ends_with(&format!(".{needle}")) {
            return Some(*t);
        }
    }
    None
}

fn plan_multisplit(first: &[u8], split_pos: usize) -> Option<ProxyPlan> {
    if split_pos == 0 || split_pos >= first.len() {
        return None;
    }
    Some(ProxyPlan {
        writes: vec![
            ProxyWrite {
                bytes: first[..split_pos].to_vec(),
                delay_after: Duration::from_millis(20),
            },
            ProxyWrite {
                bytes: first[split_pos..].to_vec(),
                delay_after: Duration::ZERO,
            },
        ],
    })
}

fn plan_host_fake_split(first: &[u8], fake_host: &str) -> Option<ProxyPlan> {
    let renamed = rewrite_sni_same_length(first, fake_host)?;
    Some(ProxyPlan {
        writes: vec![
            ProxyWrite {
                bytes: renamed,
                delay_after: Duration::from_millis(20),
            },
            ProxyWrite {
                bytes: first.to_vec(),
                delay_after: Duration::ZERO,
            },
        ],
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn passthrough_when_no_target_match() {
        let p = Profile::builtin_youtube_discord();
        let plan = process_first_chunk(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n", &p);
        assert_eq!(plan.writes.len(), 1);
    }

    #[test]
    fn multisplit_when_clienthello_to_target() {
        // Build a profile that has tls_multisplit explicitly (the
        // real default profile no longer includes it — May 2026
        // recipe is fake_multidisorder + ozon.ru decoy instead).
        let mut p = Profile::builtin_youtube_discord();
        p.strategies.tls_multisplit = vec![crate::profile::TlsMultisplitCfg {
            split_pos: 1,
            seqovl: 568,
            seqovl_decoy_host: None,
            fake_filler_byte: 0,
            targets: vec![],
        }];
        p.strategies.host_fake_split = vec![];
        let ch = crate::fakes::build_fake_clienthello("rr1.googlevideo.com");
        let plan = process_first_chunk(&ch, &p);
        assert_eq!(plan.writes.len(), 2);
        assert_eq!(plan.writes[0].bytes.len(), 1);
        assert_eq!(plan.writes[1].bytes.len(), ch.len() - 1);
    }
}
