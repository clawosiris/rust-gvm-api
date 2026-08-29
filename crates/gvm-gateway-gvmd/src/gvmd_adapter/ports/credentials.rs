// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Greenbone AG
use super::super::*;

#[async_trait]
impl CredentialPort for GvmdAdapter {
    async fn list_credential_stores(
        &self,
        session_token: &str,
    ) -> Result<Vec<CredentialStore>, GatewayError> {
        let client = self.session_client(session_token)?;
        let (username, password) = client.auth_pair_owned();
        let mut guard = client.lock().await?;
        let parsed = match guard.get_credential_stores().await {
            Ok(parsed) => parsed,
            Err(error) if credential_store_capability_unavailable(&error) => {
                if let Err(_reconnect_error) = guard
                    .reconnect(&self.socket_path, &username, &password)
                    .await
                {
                    // The current request already established a stable
                    // capability-absence result; keep returning 501 even if
                    // gvmd refuses the best-effort socket refresh.
                }
                return Err(unsupported_credential_store_error());
            }
            Err(error) => return Err(map_gvm_error(error)),
        };
        drop(guard);

        Ok(parsed
            .items
            .into_iter()
            .map(|store| CredentialStore {
                id: store.id,
                name: store.name,
                provider: store.type_,
                default: None,
                writable: None,
            })
            .collect())
    }

    async fn list_credentials(
        &self,
        session_token: &str,
        query: &CredentialQuery,
    ) -> Result<CredentialPage, GatewayError> {
        let client = self.session_client(session_token)?;
        let filter_id = query
            .filter_id
            .as_deref()
            .map(|value| {
                EntityId::new(value)
                    .map_err(|_| GatewayError::InvalidInput("invalid filterId".to_string()))
            })
            .transpose()?;
        let filter_string = self
            .paginated_filter_resolving_filter_id(
                session_token,
                None,
                query.filter_string.as_deref(),
                filter_id.as_ref(),
                query.page,
                query.per_page,
                &[],
            )
            .await?;
        let response = client
            .lock()
            .await?
            .call(get_credentials(GetCredentialsOpts {
                filter_string,
                filter_id: None,
                trash: None,
                details: Some(true),
            }))
            .await
            .map_err(map_gvm_error)?;
        let parsed = GetCredentialsResponse::from_response(&response).map_err(map_parse_error)?;
        let items = parsed
            .items
            .into_iter()
            .map(credential_from_gmp)
            .collect::<Vec<_>>();
        let total = gvmd_total(parsed.counts.filtered, parsed.counts.total, items.len());
        Ok(CredentialPage {
            data: items,
            pagination: paged_pagination(total, query.page, query.per_page),
        })
    }

    async fn create_credential(
        &self,
        session_token: &str,
        input: CreateCredentialInput,
    ) -> Result<String, GatewayError> {
        let client = self.session_client(session_token)?;
        let response = client
            .lock()
            .await?
            .call(create_credential(
                &input.name,
                CredentialOpts {
                    comment: input.comment,
                    credential_type: Some(parse_credential_type(&input.credential_type)?),
                    login: input.login,
                    password: input.password,
                    private_key: input.private_key,
                    key_phrase: None,
                    public_key: None,
                    certificate: input.certificate,
                    community: input.community,
                    auth_algorithm: input
                        .auth_algorithm
                        .as_deref()
                        .map(parse_snmp_auth_algorithm)
                        .transpose()?,
                    privacy_password: input.privacy_password,
                    privacy_algorithm: input
                        .privacy_algorithm
                        .as_deref()
                        .map(parse_snmp_privacy_algorithm)
                        .transpose()?,
                    allow_insecure: None,
                    kdc: None,
                    kdcs: vec![],
                    realm: None,
                    ..Default::default()
                },
            ))
            .await
            .map_err(map_gvm_error)?;
        let parsed = CreateCredentialResponse::from_response(&response).map_err(map_parse_error)?;
        Ok(parsed.id.to_string())
    }

    async fn get_credential(
        &self,
        session_token: &str,
        id: &str,
    ) -> Result<Credential, GatewayError> {
        let client = self.session_client(session_token)?;
        let response = client
            .lock()
            .await?
            .call(get_credential(&parse_entity_id(id)?))
            .await
            .map_err(map_gvm_error)?;
        let parsed = GetCredentialsResponse::from_response(&response).map_err(map_parse_error)?;
        parsed
            .items
            .into_iter()
            .next()
            .map(credential_from_gmp)
            .ok_or_else(|| GatewayError::NotFound(format!("credential {id} not found")))
    }

    async fn modify_credential(
        &self,
        session_token: &str,
        id: &str,
        input: ModifyCredentialInput,
    ) -> Result<Credential, GatewayError> {
        let client = self.session_client(session_token)?;
        let response = client
            .lock()
            .await?
            .call(modify_credential(
                &parse_entity_id(id)?,
                ModifyCredentialOpts {
                    name: input.name,
                    comment: input.comment,
                    login: input.login,
                    password: input.password,
                    private_key: input.private_key,
                    key_phrase: None,
                    public_key: None,
                    certificate: input.certificate,
                    community: input.community,
                    auth_algorithm: input
                        .auth_algorithm
                        .as_deref()
                        .map(parse_snmp_auth_algorithm)
                        .transpose()?,
                    privacy_password: input.privacy_password,
                    privacy_algorithm: input
                        .privacy_algorithm
                        .as_deref()
                        .map(parse_snmp_privacy_algorithm)
                        .transpose()?,
                    allow_insecure: None,
                    kdc: None,
                    kdcs: vec![],
                    realm: None,
                },
            ))
            .await
            .map_err(map_gvm_error)?;
        let _ = ActionResponse::from_response(&response).map_err(map_parse_error)?;
        drop(client);
        self.get_credential(session_token, id).await
    }

    async fn delete_credential(
        &self,
        session_token: &str,
        id: &str,
        ultimate: bool,
    ) -> Result<(), GatewayError> {
        let client = self.session_client(session_token)?;
        let response = client
            .lock()
            .await?
            .call(delete_credential(&parse_entity_id(id)?, ultimate))
            .await
            .map_err(map_gvm_error)?;
        let _ = ActionResponse::from_response(&response).map_err(map_parse_error)?;
        Ok(())
    }
}

pub(super) fn credential_store_capability_unavailable(error: &gvm_client::GvmError) -> bool {
    match error {
        gvm_client::GvmError::UnsupportedCommand { command, .. } => {
            command == "get_credential_stores"
        }
        gvm_client::GvmError::Server {
            status: 503,
            message,
        }
        | gvm_client::GvmError::Parse(gvm_gmp::responses::ParseError::ServerError {
            status: 503,
            message,
        }) => credential_store_command_disabled(message),
        _ => false,
    }
}

fn credential_store_command_disabled(message: &str) -> bool {
    message.to_ascii_lowercase().contains("command disabled")
}

pub(super) fn unsupported_credential_store_error() -> GatewayError {
    GatewayError::NotImplemented(
        "credential stores are not available because gvmd does not expose `get_credential_stores` on this backend instance; the proxy does not synthesize credential store entries".to_string(),
    )
}
