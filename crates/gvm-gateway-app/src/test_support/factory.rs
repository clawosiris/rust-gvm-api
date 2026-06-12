// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Greenbone AG

use std::{
    future::Future,
    io,
    sync::{Arc, Mutex, OnceLock},
};

use gvm_gateway_domain::SessionManager;
use tokio::sync::{Mutex as AsyncMutex, MutexGuard as AsyncMutexGuard};
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
}

impl TraceCapture {
    /// Runs a future while the global test subscriber writes to this capture's
    /// cleared buffer.
    pub(crate) async fn run<F>(&self, future: F) -> F::Output
    where
        F: Future,
    {
        future.await
    }

    /// Returns captured trace output as UTF-8 text.
    pub(crate) fn output(&self) -> String {
        String::from_utf8(self.buffer.lock().unwrap().clone()).unwrap()
    }
}

/// Clears and returns the shared tracing capture for one test.
pub(crate) fn capture_tracing() -> TraceCapture {
    static BUFFER: OnceLock<Arc<Mutex<Vec<u8>>>> = OnceLock::new();
    static SUBSCRIBER: OnceLock<()> = OnceLock::new();

    let buffer = Arc::clone(BUFFER.get_or_init(|| Arc::new(Mutex::new(Vec::new()))));
    SUBSCRIBER.get_or_init(|| {
        let writer = TestWriter {
            buffer: Arc::clone(&buffer),
        };
        let subscriber = tracing_subscriber::registry().with(
            tracing_subscriber::fmt::layer()
                .with_writer(writer)
                .with_ansi(false)
                .with_span_events(FmtSpan::CLOSE),
        );
        let _ = tracing::subscriber::set_global_default(subscriber);
    });
    buffer.lock().unwrap().clear();

    TraceCapture { buffer }
}

/// Serializes tests that assert on the shared tracing output buffer.
///
/// The test subscriber is process-global, so capture tests must not run
/// concurrently with each other.
pub(crate) async fn lock_tracing() -> AsyncMutexGuard<'static, ()> {
    static LOCK: OnceLock<AsyncMutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| AsyncMutex::new(())).lock().await
}
