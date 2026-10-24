use parking_lot::Mutex;
use std::collections::{BTreeSet, HashMap, HashSet};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::endpoint_id::EndpointId;
use crate::error::{P2pError, Result};

pub const DEFAULT_MAX_FUTURE_SKEW_MS: u64 = 5 * 60 * 1000; // 5 minutes
pub const DEFAULT_MAX_PAST_AGE_MS: u64 = 30 * 24 * 60 * 60 * 1000; // 30 days for offline/queued messages
pub const DEFAULT_MAX_CLOCK_SKEW_MS: u64 = DEFAULT_MAX_FUTURE_SKEW_MS;
pub const DEFAULT_CAPACITY: usize = 50_000;

/// Policy defining behavior when `ReplayFilter` reaches capacity while all stored nonces are still within valid age.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum OverflowPolicy {
    /// Strict rejection: refuse new nonces when the filter is full of active, non-expired nonces.
    /// This strictly prevents attackers from bypassing replay protection via eviction flooding.
    #[default]
    Reject,
    /// Evict oldest timestamp when capacity is reached (lossy/best-effort mode).
    EvictOldest,
}

/// Thread-safe filter protecting control and signaling messages against replay attacks.
#[derive(Debug)]
pub struct ReplayFilter {
    inner: Mutex<ReplayInner>,
    max_past_age_ms: u64,
    max_future_skew_ms: u64,
}

#[derive(Debug)]
struct ReplayInner {
    seen: HashSet<[u8; 16]>,
    by_time: BTreeSet<(u64, [u8; 16])>,
    capacity: usize,
    policy: OverflowPolicy,
}

impl Default for ReplayFilter {
    fn default() -> Self {
        Self::with_past_and_future(
            DEFAULT_MAX_PAST_AGE_MS,
            DEFAULT_MAX_FUTURE_SKEW_MS,
            DEFAULT_CAPACITY,
        )
    }
}

impl ReplayFilter {
    pub fn new(max_past_age_ms: u64, capacity: usize) -> Self {
        Self::with_past_and_future(max_past_age_ms, DEFAULT_MAX_FUTURE_SKEW_MS, capacity)
    }

    /// Creates a strict filter where past and future skew limits are identical (e.g. for real-time signaling).
    pub fn new_strict(max_skew_ms: u64, capacity: usize) -> Self {
        Self::with_past_and_future(max_skew_ms, max_skew_ms, capacity)
    }

    pub fn with_past_and_future(
        max_past_age_ms: u64,
        max_future_skew_ms: u64,
        capacity: usize,
    ) -> Self {
        Self::with_past_and_future_and_policy(
            max_past_age_ms,
            max_future_skew_ms,
            capacity,
            OverflowPolicy::Reject,
        )
    }

    pub fn with_past_and_future_and_policy(
        max_past_age_ms: u64,
        max_future_skew_ms: u64,
        capacity: usize,
        policy: OverflowPolicy,
    ) -> Self {
        Self {
            inner: Mutex::new(ReplayInner {
                seen: HashSet::with_capacity(capacity.min(4096)),
                by_time: BTreeSet::new(),
                capacity,
                policy,
            }),
            max_past_age_ms,
            max_future_skew_ms,
        }
    }

    /// Check if timestamp is within bounds and nonce has not been seen before.
    /// If valid, records the nonce to prevent future replays.
    pub fn check_and_record(&self, timestamp_ms: u64, nonce: &[u8; 16]) -> Result<()> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);

        if timestamp_ms.saturating_add(self.max_past_age_ms) < now {
            return Err(P2pError::TimestampSkew {
                timestamp_ms,
                now_ms: now,
            });
        }
        if timestamp_ms > now.saturating_add(self.max_future_skew_ms) {
            return Err(P2pError::TimestampSkew {
                timestamp_ms,
                now_ms: now,
            });
        }

        let mut inner = self.inner.lock();

        if inner.seen.contains(nonce) {
            return Err(P2pError::ReplayDetected(*nonce));
        }

        // Prune expired entries based on cutoff timestamp
        let cutoff = now.saturating_sub(self.max_past_age_ms);
        while let Some(&(ts, old_nonce)) = inner.by_time.first() {
            if ts < cutoff {
                inner.by_time.pop_first();
                inner.seen.remove(&old_nonce);
            } else {
                break;
            }
        }

        // Handle capacity limit if active nonces still fill the filter
        if inner.seen.len() >= inner.capacity {
            match inner.policy {
                OverflowPolicy::Reject => {
                    return Err(P2pError::ReplayFilterFull {
                        capacity: inner.capacity,
                    });
                }
                OverflowPolicy::EvictOldest => {
                    if let Some((_, old_nonce)) = inner.by_time.pop_first() {
                        inner.seen.remove(&old_nonce);
                    }
                }
            }
        }

        inner.seen.insert(*nonce);
        inner.by_time.insert((timestamp_ms, *nonce));

        Ok(())
    }

    pub fn len(&self) -> usize {
        self.inner.lock().seen.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn capacity(&self) -> usize {
        self.inner.lock().capacity
    }
}

/// Thread-safe per-peer replay filter preventing a single peer
/// from exhausting the replay memory of other peers.
#[derive(Debug)]
pub struct PeerReplayFilter {
    filters: parking_lot::RwLock<HashMap<EndpointId, ReplayFilter>>,
    max_past_age_ms: u64,
    max_future_skew_ms: u64,
    per_peer_capacity: usize,
    max_peers: usize,
    policy: OverflowPolicy,
}

impl PeerReplayFilter {
    pub const DEFAULT_MAX_PEERS: usize = 10_000;
    pub const DEFAULT_PER_PEER_CAPACITY: usize = 1_000;

    pub fn new(per_peer_capacity: usize, max_peers: usize) -> Self {
        Self::with_policy(
            per_peer_capacity,
            max_peers,
            DEFAULT_MAX_PAST_AGE_MS,
            DEFAULT_MAX_FUTURE_SKEW_MS,
            OverflowPolicy::Reject,
        )
    }

    pub fn with_policy(
        per_peer_capacity: usize,
        max_peers: usize,
        max_past_age_ms: u64,
        max_future_skew_ms: u64,
        policy: OverflowPolicy,
    ) -> Self {
        Self {
            filters: parking_lot::RwLock::new(HashMap::new()),
            max_past_age_ms,
            max_future_skew_ms,
            per_peer_capacity,
            max_peers,
            policy,
        }
    }

    pub fn check_and_record(
        &self,
        peer: &EndpointId,
        timestamp_ms: u64,
        nonce: &[u8; 16],
    ) -> Result<()> {
        {
            let map = self.filters.read();
            if let Some(filter) = map.get(peer) {
                return filter.check_and_record(timestamp_ms, nonce);
            }
        }

        let mut map = self.filters.write();
        if map.len() >= self.max_peers && !map.contains_key(peer) {
            return Err(P2pError::PeerBookFull(self.max_peers));
        }

        let filter = map.entry(*peer).or_insert_with(|| {
            ReplayFilter::with_past_and_future_and_policy(
                self.max_past_age_ms,
                self.max_future_skew_ms,
                self.per_peer_capacity,
                self.policy,
            )
        });

        filter.check_and_record(timestamp_ms, nonce)
    }

    pub fn peer_count(&self) -> usize {
        self.filters.read().len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_replay_fresh_nonce() {
        let filter = ReplayFilter::default();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;

        let n1 = [1u8; 16];
        let n2 = [2u8; 16];
        assert!(filter.check_and_record(now, &n1).is_ok());
        assert!(filter.check_and_record(now, &n2).is_ok());
    }

    #[test]
    fn test_replay_detected() {
        let filter = ReplayFilter::default();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;

        let n = [42u8; 16];
        assert!(filter.check_and_record(now, &n).is_ok());
        assert!(matches!(
            filter.check_and_record(now, &n),
            Err(P2pError::ReplayDetected(_))
        ));
    }

    #[test]
    fn test_replay_capacity_overflow_rejects_and_prevents_replay() {
        // Reproduce the scenario: capacity = 2, messages A -> B -> C -> A
        let filter = ReplayFilter::with_past_and_future_and_policy(
            DEFAULT_MAX_PAST_AGE_MS,
            DEFAULT_MAX_FUTURE_SKEW_MS,
            2,
            OverflowPolicy::Reject,
        );
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;

        let a = [1u8; 16];
        let b = [2u8; 16];
        let c = [3u8; 16];

        // A and B accepted
        assert!(filter.check_and_record(now, &a).is_ok());
        assert!(filter.check_and_record(now, &b).is_ok());

        // C rejected because capacity is full of active, non-expired nonces
        let c_res = filter.check_and_record(now, &c);
        assert!(matches!(c_res, Err(P2pError::ReplayFilterFull { .. })));

        // Replaying A MUST STILL BE DETECTED AND REJECTED!
        let a_replay = filter.check_and_record(now, &a);
        assert!(matches!(a_replay, Err(P2pError::ReplayDetected(_))));
    }

    #[test]
    fn test_peer_replay_filter_isolation() {
        let peer_filter = PeerReplayFilter::new(2, 100);
        let peer1 = EndpointId([1u8; 32]);
        let peer2 = EndpointId([2u8; 32]);

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;

        let n1 = [1u8; 16];
        let n2 = [2u8; 16];
        let n3 = [3u8; 16];

        // Peer 1 fills its capacity
        assert!(peer_filter.check_and_record(&peer1, now, &n1).is_ok());
        assert!(peer_filter.check_and_record(&peer1, now, &n2).is_ok());
        assert!(matches!(
            peer_filter.check_and_record(&peer1, now, &n3),
            Err(P2pError::ReplayFilterFull { .. })
        ));

        // Peer 2 is completely unaffected by Peer 1's full buffer!
        assert!(peer_filter.check_and_record(&peer2, now, &n1).is_ok());
        assert!(peer_filter.check_and_record(&peer2, now, &n2).is_ok());
    }
}
