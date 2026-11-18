// SPDX-License-Identifier: GPL-3.0-only
//! Pure scheduling state. Time is supplied by the caller in monotonic milliseconds.

use anyhow::{ensure, Result};

pub const QUIET_MS: u64 = 1_500;
pub const INITIAL_BACKOFF_MS: u64 = 2_000;
pub const MAX_BACKOFF_MS: u64 = 5 * 60_000;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Flight {
    pub work_id: String,
    pub generation: u64,
}

#[derive(Clone, Debug)]
pub struct Scheduler {
    pub dirty_generation: u64,
    pub last_confirmed_uploaded_generation: u64,
    pub needs_reconcile: bool,
    pub content_dirty: bool,
    pub paused: bool,
    pub flight: Option<Flight>,
    quiet_until: u64,
    retry_at: u64,
    failures: u32,
}

impl Scheduler {
    /// Restart always requires a real audit, even when the saved counters match.
    pub fn new(dirty: u64, confirmed: u64, now: u64) -> Result<Self> {
        ensure!(dirty >= confirmed, "invalid tracking generation ordering");
        Ok(Self {
            dirty_generation: dirty,
            last_confirmed_uploaded_generation: confirmed,
            needs_reconcile: true,
            content_dirty: true,
            paused: false,
            flight: None,
            quiet_until: now.saturating_add(QUIET_MS),
            retry_at: now,
            failures: 0,
        })
    }

    pub fn hint(&mut self, now: u64) -> Result<()> {
        self.bump()?;
        self.needs_reconcile = true;
        self.quiet_until = now.saturating_add(QUIET_MS);
        Ok(())
    }

    /// Periodic audits do not repeatedly postpone a real event's quiet period.
    pub fn require_reconcile(&mut self) {
        self.needs_reconcile = true;
    }

    pub fn can_reconcile(&self, now: u64) -> bool {
        !self.paused && self.needs_reconcile && now >= self.quiet_until.max(self.retry_at)
    }

    /// `changed_since_observation` is separate from `dirty_since_confirmation`.
    /// Scanning the same dirty bytes twice must not establish a saved baseline.
    pub fn observed(
        &mut self,
        dirty_since_confirmation: bool,
        changed_since_observation: bool,
    ) -> Result<()> {
        if changed_since_observation {
            self.bump()?;
        }
        self.content_dirty = dirty_since_confirmation;
        self.needs_reconcile = false;
        Ok(())
    }

    pub fn ready(&self, now: u64, authorized: bool) -> bool {
        authorized
            && !self.paused
            && !self.needs_reconcile
            && self.content_dirty
            && self.flight.is_none()
            && now >= self.quiet_until.max(self.retry_at)
    }

    pub fn begin(&mut self, work_id: String, now: u64) -> Result<Flight> {
        ensure!(!self.paused, "tracking scope is paused");
        ensure!(!self.needs_reconcile, "source reconciliation is required");
        ensure!(self.flight.is_none(), "one upload per software is allowed");
        ensure!(now >= self.retry_at, "upload is in backoff");
        let flight = Flight {
            work_id,
            generation: self.dirty_generation,
        };
        self.flight = Some(flight.clone());
        Ok(flight)
    }

    /// Confirmation never infers cleanliness. A fresh content comparison follows.
    /// Partial success cannot advance the whole-software confirmation counter.
    pub fn complete(
        &mut self,
        work_id: &str,
        generation: u64,
        success: bool,
        fully_confirmed: bool,
        now: u64,
    ) -> Result<()> {
        let flight = self
            .flight
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("unknown upload"))?;
        ensure!(
            flight.work_id == work_id && flight.generation == generation,
            "upload completion does not match the original work/generation"
        );
        self.flight = None;
        if success {
            self.failures = 0;
            self.retry_at = now;
            if fully_confirmed {
                self.last_confirmed_uploaded_generation =
                    self.last_confirmed_uploaded_generation.max(generation);
            }
        } else {
            self.backoff(now);
        }
        self.needs_reconcile = true;
        Ok(())
    }

    pub fn failed(&mut self, now: u64) {
        self.needs_reconcile = true;
        self.content_dirty = true;
        self.backoff(now);
    }

    pub fn revoke(&mut self) {
        self.paused = true;
        self.needs_reconcile = true;
        self.content_dirty = true;
    }

    pub fn resume(&mut self, now: u64) {
        self.paused = false;
        self.needs_reconcile = true;
        self.quiet_until = now.saturating_add(QUIET_MS);
        // Resuming a grant is not a way around a network/source failure backoff.
    }

    pub fn retry_at(&self) -> u64 {
        self.retry_at
    }

    fn bump(&mut self) -> Result<()> {
        self.dirty_generation = self
            .dirty_generation
            .checked_add(1)
            .ok_or_else(|| anyhow::anyhow!("tracking generation exhausted"))?;
        Ok(())
    }

    fn backoff(&mut self, now: u64) {
        self.failures = self.failures.saturating_add(1);
        let multiplier = 1_u64 << self.failures.saturating_sub(1).min(16);
        let delay = INITIAL_BACKOFF_MS
            .saturating_mul(multiplier)
            .min(MAX_BACKOFF_MS);
        self.retry_at = now.saturating_add(delay);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn restart_and_overflow_cannot_use_zero_events_as_cleanliness() {
        let mut s = Scheduler::new(8, 8, 0).unwrap();
        assert!(!s.ready(10_000, true));
        assert!(s.needs_reconcile);
        s.observed(false, false).unwrap();
        assert!(!s.content_dirty);
        s.hint(10_000).unwrap(); // Includes an overflow/remount hint.
        assert!(s.needs_reconcile);
        assert!(!s.ready(11_499, true));
        s.observed(true, true).unwrap();
        assert!(s.ready(11_500, true));
        assert_eq!(s.last_confirmed_uploaded_generation, 8);
    }

    #[test]
    fn rapid_changes_coalesce_and_a_continuously_writing_app_does_not_flood() {
        let mut s = Scheduler::new(0, 0, 0).unwrap();
        for now in 0..10_000 {
            s.hint(now).unwrap();
            assert!(!s.can_reconcile(now));
            assert!(!s.ready(now, true));
        }
        assert!(!s.can_reconcile(11_498));
        assert!(s.can_reconcile(11_499));
        s.observed(true, true).unwrap();
        let first = s.begin("one".into(), 11_499).unwrap();
        assert!(s.begin("two".into(), 11_499).is_err());
        s.hint(11_600).unwrap();
        s.complete("one", first.generation, true, true, 12_000)
            .unwrap();
        assert!(s.dirty_generation > s.last_confirmed_uploaded_generation);
        assert!(!s.ready(13_100, true)); // Must reconcile the in-flight mutation.
        s.observed(true, true).unwrap();
        assert!(s.ready(13_100, true));
    }

    #[test]
    fn failed_network_and_unstable_sources_back_off_without_sleep() {
        let mut s = Scheduler::new(0, 0, 0).unwrap();
        s.observed(true, true).unwrap();
        let work = s.begin("network".into(), 1_500).unwrap();
        s.complete("network", work.generation, false, false, 2_000)
            .unwrap();
        assert_eq!(s.retry_at(), 4_000);
        assert!(!s.can_reconcile(3_999));
        s.failed(4_000);
        assert_eq!(s.retry_at(), 8_000);
        for _ in 0..30 {
            let now = s.retry_at();
            s.failed(now);
            assert!(s.retry_at() - now <= MAX_BACKOFF_MS);
        }
    }

    #[test]
    fn revoked_grant_and_partial_success_cannot_clear_unselected_data() {
        let mut s = Scheduler::new(4, 2, 0).unwrap();
        s.observed(true, false).unwrap();
        assert!(!s.ready(1_500, false));
        let work = s.begin("partial".into(), 1_500).unwrap();
        s.complete("partial", work.generation, true, false, 2_000)
            .unwrap();
        assert_eq!(s.last_confirmed_uploaded_generation, 2);
        assert!(s.content_dirty);
        s.revoke();
        assert!(!s.can_reconcile(99_000));
        assert!(!s.ready(99_000, true));
    }

    #[test]
    fn stale_or_forged_completions_do_not_consume_the_real_flight() {
        let mut s = Scheduler::new(4, 2, 0).unwrap();
        s.observed(true, false).unwrap();
        s.begin("real".into(), 1_500).unwrap();
        assert!(s.complete("other", 4, true, true, 2_000).is_err());
        assert!(s.complete("real", 3, true, true, 2_000).is_err());
        assert_eq!(s.flight.as_ref().unwrap().work_id, "real");
        assert_eq!(s.last_confirmed_uploaded_generation, 2);
    }

    #[test]
    fn repeated_scans_are_not_upload_confirmations() {
        let mut s = Scheduler::new(2, 0, 0).unwrap();
        for _ in 0..100 {
            s.observed(true, false).unwrap();
        }
        assert_eq!(s.dirty_generation, 2);
        assert_eq!(s.last_confirmed_uploaded_generation, 0);
        assert!(s.content_dirty);
    }
}
