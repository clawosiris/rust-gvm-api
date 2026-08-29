// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Greenbone AG

use gvm_client::GmpClient;
use gvm_connection::UnixSocketConnection;
use gvm_gmp::{
    commands::{authentication::authenticate, credentials::GetCredentialsOpts},
    responses::AuthenticateResponse,
};
use gvm_mock_server::{Fault, FaultKind, GmpVersion as MockVersion, MockGmpServer, ServerMode};

use super::SessionClient;

#[tokio::test]
async fn session_client_reconnect_restores_authenticated_socket_after_disconnect() {
    let server = MockGmpServer::builder()
        .mode(ServerMode::Stateful)
        .version(MockVersion::V22_8)
        .inject_fault(Fault::after_commands(3, FaultKind::Disconnect))
        .unix_socket_auto()
        .build()
        .await
        .unwrap();

    let connection = UnixSocketConnection::with_path(server.socket_path().unwrap());
    let mut client = GmpClient::connect(connection).await.unwrap();
    let response = client.call(authenticate("admin", "admin")).await.unwrap();
    AuthenticateResponse::from_response(&response).expect("initial authentication");

    let session_client = SessionClient::new(client, "admin".to_string(), "admin".to_string());
    let mut guard = session_client.lock().await.expect("session lock");

    guard
        .get_credentials(GetCredentialsOpts::default())
        .await
        .expect("first credential read should succeed before the injected disconnect");
    guard
        .get_credentials(GetCredentialsOpts::default())
        .await
        .expect_err("second credential read should observe the injected disconnect");

    // Regression coverage for the August 29, 2026 credential-store follow-up:
    // once gvmd closes an authenticated GMP socket, the cached session client
    // must be able to re-authenticate in place so later commands can proceed.
    guard
        .reconnect(server.socket_path().unwrap(), "admin", "admin")
        .await
        .expect("reconnect should replace the stale GMP client");
    guard
        .get_credentials(GetCredentialsOpts::default())
        .await
        .expect("credential reads should succeed after reconnect");

    server.shutdown().await;
}
