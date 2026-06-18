// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Greenbone AG

//! Shared graceful-shutdown runtime state for the REST gateway.

use std::sync::{
    atomic::{AtomicU8, AtomicUsize, Ordering},
    Arc,
};

use tokio::sync::{watch, Notify};

const PHASE_RUNNING: u8 = 0;
const PHASE_DRAINING: u8 = 1;
const PHASE_STOPPED: u8 = 2;

/// Lifecycle phase of the REST gateway process.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ShutdownPhase {
    /// The gateway is accepting new requests normally.
    Running,
    /// The gateway is draining in-flight requests and rejecting new work.
    Draining,
    /// The gateway has finished shutdown processing.
    Stopped,
}

impl ShutdownPhase {
    fn from_u8(value: u8) -> Self {
        match value {
            PHASE_DRAINING => Self::Draining,
            PHASE_STOPPED => Self::Stopped,
            _ => Self::Running,
        }
    }
}

/// Shared shutdown runtime used by the server loop and REST middleware.
pub struct ShutdownRuntime {
    phase: AtomicU8,
    in_flight: AtomicUsize,
    phase_tx: watch::Sender<ShutdownPhase>,
    drained: Notify,
}

impl ShutdownRuntime {
    /// Create a runtime in the normal `Running` phase.
    pub fn new() -> Self {
        let (phase_tx, _phase_rx) = watch::channel(ShutdownPhase::Running);
        Self {
            phase: AtomicU8::new(PHASE_RUNNING),
            in_flight: AtomicUsize::new(0),
            phase_tx,
            drained: Notify::new(),
        }
    }

    /// Current shutdown phase.
    pub fn phase(&self) -> ShutdownPhase {
        ShutdownPhase::from_u8(self.phase.load(Ordering::Acquire))
    }

    /// Returns whether the gateway has entered drain/stop mode.
    pub fn is_shutting_down(&self) -> bool {
        self.phase() != ShutdownPhase::Running
    }

    /// Returns the number of requests currently being processed.
    pub fn in_flight_requests(&self) -> usize {
        self.in_flight.load(Ordering::Acquire)
    }

    /// Transition from `Running` to `Draining`.
    pub fn begin_shutdown(&self) -> bool {
        if self
            .phase
            .compare_exchange(
                PHASE_RUNNING,
                PHASE_DRAINING,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_ok()
        {
            let _ = self.phase_tx.send(ShutdownPhase::Draining);
            if self.in_flight_requests() == 0 {
                self.drained.notify_waiters();
            }
            true
        } else {
            false
        }
    }

    /// Mark shutdown complete.
    pub fn mark_stopped(&self) {
        self.phase.store(PHASE_STOPPED, Ordering::Release);
        let _ = self.phase_tx.send(ShutdownPhase::Stopped);
        self.drained.notify_waiters();
    }

    /// Wait until shutdown begins.
    pub async fn wait_for_shutdown_start(&self) {
        if self.is_shutting_down() {
            return;
        }

        let mut rx = self.phase_tx.subscribe();
        loop {
            if *rx.borrow() != ShutdownPhase::Running {
                return;
            }
            if rx.changed().await.is_err() {
                return;
            }
        }
    }

    /// Wait until all accepted requests have completed.
    pub async fn wait_for_zero_in_flight(&self) {
        loop {
            if self.in_flight_requests() == 0 {
                return;
            }
            self.drained.notified().await;
        }
    }

    /// Attempt to accept a new request into the drain tracker.
    pub fn try_track_request(self: &Arc<Self>) -> Option<InFlightRequest> {
        if self.is_shutting_down() {
            return None;
        }

        self.in_flight.fetch_add(1, Ordering::AcqRel);

        if self.is_shutting_down() {
            self.finish_request();
            return None;
        }

        Some(InFlightRequest {
            runtime: Arc::clone(self),
        })
    }

    fn finish_request(&self) {
        let previous = self.in_flight.fetch_sub(1, Ordering::AcqRel);
        debug_assert!(previous > 0, "in-flight request count underflow");
        if previous == 1 && self.is_shutting_down() {
            self.drained.notify_waiters();
        }
    }
}

impl Default for ShutdownRuntime {
    fn default() -> Self {
        Self::new()
    }
}

/// Guard returned when a request has been admitted into the in-flight set.
pub struct InFlightRequest {
    runtime: Arc<ShutdownRuntime>,
}

impl Drop for InFlightRequest {
    fn drop(&mut self) {
        self.runtime.finish_request();
    }
}

#[cfg(test)]
#[path = "shutdown_test.rs"]
mod shutdown_test;
