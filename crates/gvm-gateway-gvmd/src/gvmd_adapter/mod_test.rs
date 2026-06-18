use super::*;

#[test]
fn safe_session_id_uses_session_token_digest() {
    let token = "gvm_sess_1234567890abcdef";

    let session_id = safe_session_id(token);

    assert_eq!(session_id, SessionTokenDigest::from_token(token).safe_id());
    assert!(!session_id.contains(token));
    assert!(!session_id.contains("90abcdef"));
}

#[test]
fn gvmd_adapter_session_client_fails_without_session() {
    let adapter = GvmdAdapter::unix_socket("/tmp/nonexistent.sock");
    let result = adapter.session_client("missing-token");
    assert!(matches!(result, Err(GatewayError::SessionInvalidated(_))));
}
