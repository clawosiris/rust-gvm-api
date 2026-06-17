use super::*;

#[test]
fn safe_session_id_uses_documented_token_suffix() {
    let token = "gvm_sess_1234567890abcdef";

    let session_id = safe_session_id(token);

    assert_eq!(session_id, "session:90abcdef");
    assert!(!session_id.contains(token));
}

#[test]
fn gvmd_adapter_session_client_fails_without_session() {
    let adapter = GvmdAdapter::unix_socket("/tmp/nonexistent.sock");
    let result = adapter.session_client("missing-token");
    assert!(matches!(result, Err(GatewayError::SessionInvalidated(_))));
}
