// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Greenbone AG

//! Feed DTOs and handlers for the REST adapter.

#![allow(missing_docs)]

use aide::transform::TransformOperation;
use axum::{
    extract::{OriginalUri, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use gvm_gateway_app::GatewayService;
use schemars::JsonSchema;
use serde::Serialize;

use crate::{
    error::RestError,
    open_enum::open_string_enum,
    openapi::{ok_json, problem_response},
    router::bearer_token,
};

pub use gvm_gateway_domain::Feed;

open_string_enum! {
    /// Feed catalog type.
    pub(crate) enum FeedType {
        Nvt => "NVT",
        Cert => "CERT",
        Scap => "SCAP",
        GvmdData => "GVMD_DATA",
    }
}

#[derive(Clone, Debug, Serialize, JsonSchema)]
#[schemars(rename = "Feed")]
pub(crate) struct FeedResponse {
    #[serde(rename = "type")]
    feed_type: FeedType,
    name: String,
    version: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    description: Option<String>,
    #[serde(rename = "currentlySyncing")]
    currently_syncing: bool,
}

impl From<Feed> for FeedResponse {
    fn from(feed: Feed) -> Self {
        Self {
            feed_type: FeedType::parse(&feed.feed_type),
            name: feed.name,
            version: feed.version,
            description: feed.description,
            currently_syncing: feed.currently_syncing,
        }
    }
}

#[derive(Clone, Debug, Serialize, JsonSchema)]
#[schemars(rename = "FeedList")]
pub(crate) struct FeedListResponse {
    data: Vec<FeedResponse>,
}

pub async fn list_feeds(
    State(service): State<GatewayService>,
    headers: HeaderMap,
    uri: OriginalUri,
) -> Response {
    let instance = uri.path().to_string();
    let session = match bearer_token(&headers) {
        Ok(session) => session,
        Err(error) => return RestError::from_gateway_error(error, instance).into_response(),
    };
    match service.list_feeds(&session).await {
        Ok(feeds) => (
            StatusCode::OK,
            Json(FeedListResponse {
                data: feeds.into_iter().map(FeedResponse::from).collect(),
            }),
        )
            .into_response(),
        Err(error) => RestError::from_gateway_error(error, instance).into_response(),
    }
}

pub async fn sync_feeds(
    State(service): State<GatewayService>,
    headers: HeaderMap,
    uri: OriginalUri,
) -> Response {
    let instance = uri.path().to_string();
    let session = match bearer_token(&headers) {
        Ok(session) => session,
        Err(error) => return RestError::from_gateway_error(error, instance).into_response(),
    };
    match service.sync_feeds(&session).await {
        Ok(()) => StatusCode::ACCEPTED.into_response(),
        Err(error) => RestError::from_gateway_error(error, instance).into_response(),
    }
}

pub(crate) fn list_feeds_docs(op: TransformOperation<'_>) -> TransformOperation<'_> {
    let op = op
        .id("getFeeds")
        .tag("Feeds")
        .summary("Get feed status")
        .description("Returns feed status for all feed types.")
        .security_requirement("bearerAuth")
        .response_with::<200, Json<FeedListResponse>, _>(ok_json("Feed status"));
    problem_response::<401>(op, "Authentication required or session expired")
}

pub(crate) fn sync_feeds_docs(op: TransformOperation<'_>) -> TransformOperation<'_> {
    let op = op
        .id("syncFeeds")
        .tag("Feeds")
        .summary("Trigger feed synchronization")
        .description("Triggers feed synchronization as a documented action-style exception.")
        .security_requirement("bearerAuth")
        .response_with::<202, (), _>(|response| {
            response.description("Feed synchronization accepted")
        });
    let op = problem_response::<401>(op, "Authentication required or session expired");
    problem_response::<409>(op, "Feed synchronization already in progress")
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::{FeedResponse, FeedType};
    use gvm_gateway_domain::Feed;

    fn feed_with_type(feed_type: &str) -> Feed {
        Feed {
            feed_type: feed_type.to_string(),
            name: "Feed".to_string(),
            version: "202606100000".to_string(),
            description: None,
            currently_syncing: false,
        }
    }

    #[test]
    fn feed_type_deserialization_preserves_unknown_values() {
        // Feed catalogs can gain new families; clients should still receive the
        // exact backend value through the open-enum wrapper.
        let parsed: FeedType =
            serde_json::from_value(json!("COMMUNITY_DATA")).expect("feed type should parse");

        assert_eq!(
            serde_json::to_value(parsed).unwrap(),
            json!("COMMUNITY_DATA")
        );
    }

    #[test]
    fn feed_response_preserves_known_and_unknown_types() {
        // Response mapping keeps the public `type` value verbatim for both the
        // current rust-gvm enum set and backend-added feed families.
        let known = serde_json::to_value(FeedResponse::from(feed_with_type("NVT")))
            .expect("feed response should serialize");
        let unknown = serde_json::to_value(FeedResponse::from(feed_with_type("COMMUNITY_DATA")))
            .expect("feed response should serialize");

        assert_eq!(known["type"], json!("NVT"));
        assert_eq!(unknown["type"], json!("COMMUNITY_DATA"));
    }
}
