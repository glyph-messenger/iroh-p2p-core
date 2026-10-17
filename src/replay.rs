use parking_lot::Mutex;
use std::collections::{HashSet, VecDeque};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::error::{P2pError, Result};

pub const DEFAULT_MAX_FUTURE_SKEW_MS: u64 = 5 * 60 * 1000; // 5 minutes
pub const DEFAULT_MAX_PAST_AGE_MS: u64 = 15 * 60 * 1000; // 15 minutes
pub const DEFAULT_CAPACITY: usize = 20_000;

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
    queue: VecDeque<(u64, [u8; 16])>,
    capacity: usize,
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

    pub fn with_past_and_future(
        max_past_age_ms: u64,
        max_future_skew_ms: u64,
        capacity: usize,
    ) -> Self {
        Self {
            inner: Mutex::new(ReplayInner {
                seen: HashSet::with_capacity(capacity.min(4096)),
                queue: VecDeque::with_capacity(capacity.min(4096)),
                capacity,
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

        let cutoff = now.saturating_sub(self.max_past_age_ms);
        while let Some(&(ts, old_nonce)) = inner.queue.front() {
            if ts < cutoff || inner.queue.len() >= inner.capacity {
                inner.queue.pop_front();
                inner.seen.remove(&old_nonce);
            } else {
                break;
            }
        }

        inner.seen.insert(*nonce);
        inner.queue.push_back((timestamp_ms, *nonce));

        Ok(())
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
}
