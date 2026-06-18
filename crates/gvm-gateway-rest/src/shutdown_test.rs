// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Greenbone AG

use super::*;

#[tokio::test]
async fn shutdown_runtime_rejects_new_requests_after_draining_starts() {
    let runtime = Arc::new(ShutdownRuntime::new());
    let _request = runtime.try_track_request().unwrap();

    assert!(runtime.begin_shutdown());
    assert!(runtime.is_shutting_down());
    assert!(runtime.try_track_request().is_none());
}

#[tokio::test]
async fn shutdown_runtime_waits_for_in_flight_requests_to_finish() {
    let runtime = Arc::new(ShutdownRuntime::new());
    let request = runtime.try_track_request().unwrap();

    runtime.begin_shutdown();
    let waiter = tokio::spawn({
        let runtime = Arc::clone(&runtime);
        async move { runtime.wait_for_zero_in_flight().await }
    });

    tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    assert!(!waiter.is_finished());

    drop(request);
    waiter.await.unwrap();
}
