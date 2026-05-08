//! Adaptive profile probing.
//!
//! Each ISP/region needs a different DPI-evasion profile and the
//! community publishes ladders of `general / ALT-N / ALT-M` profiles
//! precisely because no single one works everywhere. This module
//! tracks per-profile success metrics and picks whichever is
//! currently winning.
//!
//! Success metric: a flow that completes the TLS handshake (we see
//! application-data records flowing both ways) within
//! `expected_handshake_ms` is a "win"; one that resets or stalls is
//! a "loss". Wilson lower-bound on the win-rate decides ranking.
//!
//! v0.3 scope: data structures + selection logic. Wiring into the
//! engine's flow lifecycle is added incrementally so the existing
//! single-profile path keeps working.

use parking_lot::RwLock;
use std::sync::Arc;
use std::time::{Duration, Instant};

#[derive(Debug)]
struct ProfileScore {
    name: String,
    wins: u64,
    losses: u64,
    last_used: Instant,
}

impl ProfileScore {
    fn new(name: String) -> Self {
        Self {
            name,
            wins: 0,
            losses: 0,
            last_used: Instant::now(),
        }
    }

    /// Wilson score lower bound at z=1.96 (95% confidence). Treats
    /// new profiles favorably so they get a chance.
    fn rank(&self) -> f64 {
        let n = (self.wins + self.losses) as f64;
        if n < 5.0 {
            return 0.5; // exploration bonus while undersampled
        }
        let p = self.wins as f64 / n;
        let z = 1.96;
        let denom = 1.0 + z * z / n;
        let center = p + z * z / (2.0 * n);
        let margin = z * (p * (1.0 - p) / n + z * z / (4.0 * n * n)).sqrt();
        (center - margin) / denom
    }
}

#[derive(Default)]
pub struct ProbingHarness {
    inner: Arc<RwLock<Vec<ProfileScore>>>,
}

impl ProbingHarness {
    pub fn new(profiles: Vec<String>) -> Self {
        let scores = profiles.into_iter().map(ProfileScore::new).collect();
        Self {
            inner: Arc::new(RwLock::new(scores)),
        }
    }

    /// Pick the highest-ranking profile. Adds a tiny round-robin
    /// preference for less-recently-used profiles to avoid sticking.
    pub fn pick(&self) -> Option<String> {
        let g = self.inner.read();
        if g.is_empty() {
            return None;
        }
        let now = Instant::now();
        let best = g.iter().max_by(|a, b| {
            let a_rank = a.rank() + age_bonus(now, a.last_used);
            let b_rank = b.rank() + age_bonus(now, b.last_used);
            a_rank
                .partial_cmp(&b_rank)
                .unwrap_or(std::cmp::Ordering::Equal)
        })?;
        Some(best.name.clone())
    }

    pub fn record(&self, name: &str, won: bool) {
        let mut g = self.inner.write();
        if let Some(s) = g.iter_mut().find(|s| s.name == name) {
            if won {
                s.wins += 1;
            } else {
                s.losses += 1;
            }
            s.last_used = Instant::now();
        }
    }

    pub fn snapshot(&self) -> Vec<(String, u64, u64, f64)> {
        let g = self.inner.read();
        g.iter()
            .map(|s| (s.name.clone(), s.wins, s.losses, s.rank()))
            .collect()
    }
}

fn age_bonus(now: Instant, last: Instant) -> f64 {
    // Up to +0.05 boost for profiles unused in the last 5 minutes,
    // ensuring we periodically re-probe alts even if `general` is
    // currently winning.
    let secs = now.duration_since(last).as_secs_f64();
    (secs / 6000.0).min(0.05)
}

/// Per-flow probe state. The platform layer creates one when a flow
/// is first associated with a target, and reports the outcome to the
/// harness when the flow ends or stalls.
#[derive(Debug)]
pub struct FlowProbe {
    pub profile: String,
    pub started: Instant,
    pub bytes_in: u64,
    pub bytes_out: u64,
    deadline: Duration,
}

impl FlowProbe {
    pub fn new(profile: String, deadline: Duration) -> Self {
        Self {
            profile,
            started: Instant::now(),
            bytes_in: 0,
            bytes_out: 0,
            deadline,
        }
    }

    pub fn outcome(&self) -> Outcome {
        let age = self.started.elapsed();
        if age < self.deadline && self.bytes_in == 0 {
            return Outcome::Pending;
        }
        // Heuristic: a real handshake shovels >= 256 B in either
        // direction within the deadline window. A connection that
        // got nothing inbound in the deadline = loss.
        if self.bytes_in >= 256 || self.bytes_out >= 4096 {
            Outcome::Win
        } else {
            Outcome::Loss
        }
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum Outcome {
    Pending,
    Win,
    Loss,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pick_returns_some_when_seeded() {
        let h = ProbingHarness::new(vec!["a".into(), "b".into()]);
        assert!(h.pick().is_some());
    }

    #[test]
    fn winner_eventually_dominates() {
        let h = ProbingHarness::new(vec!["a".into(), "b".into()]);
        for _ in 0..50 {
            h.record("a", true);
        }
        for _ in 0..50 {
            h.record("b", false);
        }
        assert_eq!(h.pick().unwrap(), "a");
    }

    #[test]
    fn flow_probe_outcome_loss_on_zero_bytes() {
        let mut p = FlowProbe::new("x".into(), Duration::from_millis(0));
        std::thread::sleep(Duration::from_millis(1));
        p.bytes_in = 0;
        assert_eq!(p.outcome(), Outcome::Loss);
    }

    #[test]
    fn flow_probe_outcome_win_on_inbound() {
        let mut p = FlowProbe::new("x".into(), Duration::from_millis(0));
        p.bytes_in = 1024;
        std::thread::sleep(Duration::from_millis(1));
        assert_eq!(p.outcome(), Outcome::Win);
    }
}
