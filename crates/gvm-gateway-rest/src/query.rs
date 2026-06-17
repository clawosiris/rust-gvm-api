// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Greenbone AG

//! Shared standards-compliant REST query parsing helpers.

use std::borrow::Cow;

use gvm_gateway_domain::GatewayError;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::targets::validate_uuid;

/// Normalized list query fields shared by multiple collection handlers.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct CollectionQueryParams {
    pub(crate) filter_string: Option<String>,
    pub(crate) filter_id: Option<String>,
    pub(crate) page: u32,
    pub(crate) per_page: u32,
}

/// Normalized filter-only query fields.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct FilterOnlyQueryParams {
    pub(crate) filter_string: Option<String>,
    pub(crate) filter_id: Option<String>,
}

/// Query parameters shared by delete endpoints that support gvmd trashcan semantics.
#[derive(Clone, Debug, Default, Deserialize, JsonSchema, Serialize)]
pub(crate) struct DeleteResourceQueryParams {
    /// Whether gvmd should delete the resource permanently instead of trashing it.
    ultimate: Option<bool>,
}

pub(crate) fn decoded_query_pairs(
    query: &str,
) -> impl Iterator<Item = (Cow<'_, str>, Cow<'_, str>)> + '_ {
    form_urlencoded::parse(query.as_bytes())
}

pub(crate) fn parse_collection_query(query: &str) -> Result<CollectionQueryParams, GatewayError> {
    let mut filter_string = None;
    let mut filter_id = None;
    let mut page = None;
    let mut per_page = None;

    for (key, value) in decoded_query_pairs(query) {
        match key.as_ref() {
            "filter" => filter_string = Some(value.into_owned()),
            "filterId" => {
                validate_uuid("filterId", value.as_ref())?;
                filter_id = Some(value.into_owned());
            }
            "page" => {
                page = Some(value.parse::<u32>().map_err(|_| {
                    GatewayError::InvalidInput("page must be a positive integer".to_string())
                })?);
            }
            "perPage" | "per_page" => {
                let parsed_per_page = value.parse::<u32>().map_err(|_| {
                    GatewayError::InvalidInput("perPage must be a positive integer".to_string())
                })?;
                if parsed_per_page == 0 || parsed_per_page > 1000 {
                    return Err(GatewayError::InvalidInput(
                        "perPage must be between 1 and 1000".to_string(),
                    ));
                }
                per_page = Some(parsed_per_page);
            }
            _ => {}
        }
    }

    let page = page.unwrap_or(1);
    if page == 0 {
        return Err(GatewayError::InvalidInput(
            "page must be greater than or equal to 1".to_string(),
        ));
    }

    Ok(CollectionQueryParams {
        filter_string,
        filter_id,
        page,
        per_page: per_page.unwrap_or(25),
    })
}

pub(crate) fn parse_filter_only_query(query: &str) -> Result<FilterOnlyQueryParams, GatewayError> {
    let mut filter_string = None;
    let mut filter_id = None;

    for (key, value) in decoded_query_pairs(query) {
        match key.as_ref() {
            "filter" => filter_string = Some(value.into_owned()),
            "filterId" => {
                validate_uuid("filterId", value.as_ref())?;
                filter_id = Some(value.into_owned());
            }
            _ => {}
        }
    }

    Ok(FilterOnlyQueryParams {
        filter_string,
        filter_id,
    })
}

pub(crate) fn parse_delete_resource_query(query: &str) -> Result<bool, GatewayError> {
    let mut ultimate = false;

    for (key, value) in decoded_query_pairs(query) {
        if key == "ultimate" {
            ultimate = value.parse::<bool>().map_err(|_| {
                GatewayError::InvalidInput("ultimate must be true or false".to_string())
            })?;
        }
    }

    Ok(ultimate)
}

#[cfg(test)]
mod tests {
    use gvm_gateway_domain::GatewayError;

    use super::{parse_collection_query, parse_delete_resource_query, parse_filter_only_query};

    #[test]
    fn collection_query_decodes_reserved_characters_and_plus_spaces() {
        let parsed = parse_collection_query(
            "filter=severity%3E5+and+name~%22foo%26bar%3Dbaz%22&perPage=10&page=2",
        )
        .expect("query should decode");

        assert_eq!(
            parsed.filter_string.as_deref(),
            Some("severity>5 and name~\"foo&bar=baz\"")
        );
        assert_eq!(parsed.page, 2);
        assert_eq!(parsed.per_page, 10);
    }

    #[test]
    fn collection_query_decodes_uuid_before_validation() {
        let parsed =
            parse_collection_query("filterId=123e4567%2De89b%2D12d3%2Da456%2D426614174000")
                .expect("encoded uuid should validate after decode");

        assert_eq!(
            parsed.filter_id.as_deref(),
            Some("123e4567-e89b-12d3-a456-426614174000")
        );
    }

    #[test]
    fn filter_only_query_decodes_filter_id_before_validation() {
        let parsed =
            parse_filter_only_query("filterId=123e4567%2De89b%2D12d3%2Da456%2D426614174000")
                .expect("encoded uuid should validate");

        assert_eq!(
            parsed.filter_id.as_deref(),
            Some("123e4567-e89b-12d3-a456-426614174000")
        );
    }

    #[test]
    fn collection_query_rejects_oversized_page_size() {
        let error = parse_collection_query("perPage=1001")
            .expect_err("perPage above the documented maximum should fail");

        assert_eq!(
            error,
            GatewayError::InvalidInput("perPage must be between 1 and 1000".to_string())
        );
    }

    #[test]
    fn delete_resource_query_rejects_invalid_boolean() {
        let error = parse_delete_resource_query("ultimate=not-bool")
            .expect_err("invalid ultimate bool should be rejected");

        match error {
            GatewayError::InvalidInput(detail) => {
                assert_eq!(detail, "ultimate must be true or false");
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }
}
