// SPDX-License-Identifier: GPL-3.0-only
//! Serialize EVERY native vault operation around the process-wide macOS flag.
//! A migration operation may enable UI; ordinary operations never inherit it.
use anyhow::{ensure, Result};
use std::sync::Mutex;

pub(super) struct InteractionGate {
    poisoned: Mutex<bool>,
}

impl InteractionGate {
    pub const fn new() -> Self {
        Self {
            poisoned: Mutex::new(false),
        }
    }

    pub fn run<T>(
        &self,
        interactive: bool,
        set: impl Fn(bool) -> Result<()>,
        operation: impl FnOnce() -> Result<T>,
    ) -> Result<T> {
        let mut poisoned = self
            .poisoned
            .lock()
            .map_err(|_| anyhow::anyhow!("native vault interaction gate failed"))?;
        ensure!(
            !*poisoned,
            "native vault interaction reset failed; restart is required"
        );
        let reset = Reset {
            set: &set,
            poisoned: &mut poisoned,
            armed: true,
        };
        if let Err(error) = set(interactive) {
            let _ = reset.finish();
            return Err(error);
        }
        let result = operation();
        reset.finish()?;
        result
    }
}

struct Reset<'a, F: Fn(bool) -> Result<()>> {
    set: &'a F,
    poisoned: &'a mut bool,
    armed: bool,
}
impl<F: Fn(bool) -> Result<()>> Reset<'_, F> {
    fn finish(mut self) -> Result<()> {
        let result = (self.set)(false);
        self.armed = false;
        if result.is_err() {
            *self.poisoned = true;
        }
        result
    }
}
impl<F: Fn(bool) -> Result<()>> Drop for Reset<'_, F> {
    fn drop(&mut self) {
        if self.armed && (self.set)(false).is_err() {
            *self.poisoned = true;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{
        atomic::{AtomicBool, Ordering},
        mpsc, Arc,
    };

    #[test]
    fn interactive_and_background_calls_never_share_the_interactive_window() {
        let gate = Arc::new(InteractionGate::new());
        let allowed = Arc::new(AtomicBool::new(false));
        let (entered_tx, entered_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let first_gate = gate.clone();
        let first_allowed = allowed.clone();
        let interactive = std::thread::spawn(move || {
            first_gate
                .run(
                    true,
                    |state| {
                        first_allowed.store(state, Ordering::SeqCst);
                        Ok(())
                    },
                    || {
                        assert!(first_allowed.load(Ordering::SeqCst));
                        entered_tx.send(()).unwrap();
                        release_rx.recv().unwrap();
                        assert!(first_allowed.load(Ordering::SeqCst));
                        Ok(())
                    },
                )
                .unwrap();
        });
        entered_rx.recv().unwrap();
        let (attempt_tx, attempt_rx) = mpsc::channel();
        let second_allowed = allowed.clone();
        let background = std::thread::spawn(move || {
            attempt_tx.send(()).unwrap();
            gate.run(
                false,
                |state| {
                    second_allowed.store(state, Ordering::SeqCst);
                    Ok(())
                },
                || {
                    assert!(!second_allowed.load(Ordering::SeqCst));
                    Ok(())
                },
            )
            .unwrap();
        });
        attempt_rx.recv().unwrap();
        assert!(allowed.load(Ordering::SeqCst));
        release_tx.send(()).unwrap();
        interactive.join().unwrap();
        background.join().unwrap();
        assert!(!allowed.load(Ordering::SeqCst));
    }

    #[test]
    fn cancellation_and_panic_restore_noninteractive_mode() {
        let gate = InteractionGate::new();
        let allowed = AtomicBool::new(false);
        let set = |state| {
            allowed.store(state, Ordering::SeqCst);
            Ok(())
        };
        assert!(gate
            .run::<()>(true, set, || anyhow::bail!("synthetic cancellation"))
            .is_err());
        assert!(!allowed.load(Ordering::SeqCst));
        let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            gate.run::<()>(true, set, || panic!("synthetic panic"))
        }));
        assert!(panic.is_err());
        assert!(!allowed.load(Ordering::SeqCst));
    }

    #[test]
    fn failed_reset_blocks_further_native_operations() {
        let gate = InteractionGate::new();
        assert!(gate
            .run(
                true,
                |state| {
                    ensure!(state, "synthetic reset failure");
                    Ok(())
                },
                || Ok(())
            )
            .is_err());
        let called = AtomicBool::new(false);
        assert!(gate
            .run(
                false,
                |_| Ok(()),
                || {
                    called.store(true, Ordering::SeqCst);
                    Ok(())
                }
            )
            .is_err());
        assert!(!called.load(Ordering::SeqCst));
    }
}
