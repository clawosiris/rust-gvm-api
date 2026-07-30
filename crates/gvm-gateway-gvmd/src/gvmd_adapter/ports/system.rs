// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Greenbone AG
use super::super::*;

#[async_trait]
impl SystemPort for GvmdAdapter {
    async fn readiness(&self) -> Result<ReadinessStatus, GatewayError> {
        match self.probe_version().await {
            Ok(_) => Ok(ReadinessStatus {
                status: "ready",
                reason: None,
            }),
            Err(error) => Ok(ReadinessStatus {
                status: "notReady",
                reason: Some(error.detail().to_string()),
            }),
        }
    }

    async fn gmp_version(&self) -> Result<String, GatewayError> {
        self.probe_version().await
    }

    async fn get_aggregates(
        &self,
        session_token: &str,
        query: &AggregatesQuery,
    ) -> Result<Aggregates, GatewayError> {
        let client = self.session_client(session_token)?;
        let response = client
            .lock()
            .await?
            .call(get_aggregates_cmd(
                &query.resource_type,
                GetAggregatesOpts {
                    group_column: query.group_column.clone(),
                    sort_criteria: None,
                    data_columns: query.data_columns.clone(),
                    filter: query.filter.clone(),
                    filter_id: None,
                    text_columns: None,
                    first_group: None,
                    max_groups: None,
                    mode: None,
                },
            ))
            .await
            .map_err(map_gvm_error)?;
        let parsed = GetAggregatesResponse::from_response(&response).map_err(map_parse_error)?;
        Ok(aggregates_from_gmp(parsed))
    }
}
