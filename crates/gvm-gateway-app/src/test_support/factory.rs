// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Greenbone AG

use std::{
    future::Future,
    io,
    sync::{Arc, Mutex, OnceLock},
};

use gvm_gateway_domain::SessionManager;
use tokio::sync::{Mutex as AsyncMutex, MutexGuard as AsyncMutexGuard};
use tracing::instrument::WithSubscriber;
use tracing_subscriber::{
    fmt::{self, format::FmtSpan},
    prelude::*,
};

use crate::{test_support::mocks::*, GatewayService};

/// Builds a service with permissive mocks for tests that only care about service wiring.
pub(crate) fn create_test_service() -> GatewayService {
    GatewayService::new(
        Arc::new(MockSystemPort {
            ready: true,
            gmp_version: "22.7".to_string(),
        }),
        Arc::new(MockAlertPort),
        Arc::new(MockSchedulePort),
        Arc::new(MockCredentialPort),
        Arc::new(MockPortListPort),
        Arc::new(MockFeedPort),
        Arc::new(MockIdentityPort),
        Arc::new(MockTargetPort::default()),
        Arc::new(MockTaskPort),
        Arc::new(MockAuthPort::default()),
        Arc::new(MockReportPort),
        Arc::new(MockResultPort),
        Arc::new(MockScanConfigPort),
        Arc::new(MockScannerPort),
        Arc::new(MockSupportingResourcePort),
        Arc::new(SessionManager::default()),
    )
}

#[derive(Clone, Default)]
struct TestWriter {
    buffer: Arc<Mutex<Vec<u8>>>,
}

impl<'a> fmt::MakeWriter<'a> for TestWriter {
    type Writer = TestWriterGuard;

    fn make_writer(&'a self) -> Self::Writer {
        TestWriterGuard {
            buffer: Arc::clone(&self.buffer),
        }
    }
}

struct TestWriterGuard {
    buffer: Arc<Mutex<Vec<u8>>>,
}

impl io::Write for TestWriterGuard {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.buffer.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Captures tracing output so tests can assert on audit and span behavior.
pub(crate) struct TraceCapture {
    buffer: Arc<Mutex<Vec<u8>>>,
    subscriber: tracing::Dispatch,
}

impl TraceCapture {
    /// Runs a future with this capture's subscriber as the scoped default.
    pub(crate) async fn run<F>(&self, future: F) -> F::Output
    where
        F: Future,
    {
        // Audit callsite interest is process-global, while these captures are
        // scoped per future. Rebuild so parallel tests cannot leave audit
        // events disabled before this subscriber runs.
        tracing::dispatcher::with_default(
            &self.subscriber,
            tracing::callsite::rebuild_interest_cache,
        );
        let output = future.with_subscriber(self.subscriber.clone()).await;
        tracing::callsite::rebuild_interest_cache();
        output
    }

    /// Returns captured trace output as UTF-8 text.
    pub(crate) fn output(&self) -> String {
        String::from_utf8(self.buffer.lock().unwrap().clone()).unwrap()
    }
}

/// Creates an isolated tracing capture for one test.
pub(crate) fn capture_tracing() -> TraceCapture {
    let buffer = Arc::new(Mutex::new(Vec::new()));
    let writer = TestWriter {
        buffer: buffer.clone(),
    };
    let subscriber = tracing_subscriber::registry().with(
        tracing_subscriber::fmt::layer()
            .with_writer(writer)
            .with_ansi(false)
            .with_span_events(FmtSpan::CLOSE),
    );

    TraceCapture {
        buffer,
        subscriber: tracing::Dispatch::new(subscriber),
    }
}

/// Serializes tests that assert on tracing output.
///
/// `tracing` callsite interest is process-global enough that several scoped
/// subscribers running in parallel can make target-specific assertions flaky.
pub(crate) async fn lock_tracing() -> AsyncMutexGuard<'static, ()> {
    static LOCK: OnceLock<AsyncMutex<()>> = OnceLock::new();
    ensure_tracing_callsites_stay_enabled();

    LOCK.get_or_init(|| AsyncMutex::new(())).lock().await
}

fn ensure_tracing_callsites_stay_enabled() {
    static INIT: OnceLock<()> = OnceLock::new();
    INIT.get_or_init(|| {
        let subscriber = tracing_subscriber::registry().with(
            tracing_subscriber::fmt::layer()
                .with_writer(io::sink)
                .with_ansi(false)
                .with_span_events(FmtSpan::CLOSE),
        );

        // These tests assert captured audit and span output. A sink global
        // subscriber keeps callsite interest enabled even while other tests
        // exercise the same callsites without a scoped capture subscriber.
        let _ = tracing::subscriber::set_global_default(subscriber);
    });
}
