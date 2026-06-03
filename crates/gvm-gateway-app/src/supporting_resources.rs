// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Greenbone AG

//! Supporting-resource use cases.

use gvm_gateway_domain::{
    Filter, FilterPage, GatewayError, ReportFormat, ReportFormatPage, SupportingResourceQuery, Tag,
    TagPage, Ticket, TicketPage,
};

use crate::GatewayService;

impl GatewayService {
    /// Lists report formats for an authenticated session.
    pub async fn list_report_formats(
        &self,
        session_token: &str,
        query: SupportingResourceQuery,
    ) -> Result<ReportFormatPage, GatewayError> {
        self.execute_with_resource(
            "report_formats.list",
            session_token,
            "list",
            "report_format",
            None,
            |session| async move {
                self.supporting_resources
                    .list_report_formats(&session.token, &query)
                    .await
            },
        )
        .await
    }

    /// Fetches a report format for an authenticated session.
    pub async fn get_report_format(
        &self,
        session_token: &str,
        id: &str,
    ) -> Result<ReportFormat, GatewayError> {
        self.execute_with_resource(
            "report_formats.get",
            session_token,
            "read",
            "report_format",
            Some(id),
            |session| async move {
                self.supporting_resources
                    .get_report_format(&session.token, id)
                    .await
            },
        )
        .await
    }

    /// Lists saved filters for an authenticated session.
    pub async fn list_filters(
        &self,
        session_token: &str,
        query: SupportingResourceQuery,
    ) -> Result<FilterPage, GatewayError> {
        self.execute_with_resource(
            "filters.list",
            session_token,
            "list",
            "filter",
            None,
            |session| async move {
                self.supporting_resources
                    .list_filters(&session.token, &query)
                    .await
            },
        )
        .await
    }

    /// Fetches a saved filter for an authenticated session.
    pub async fn get_filter(&self, session_token: &str, id: &str) -> Result<Filter, GatewayError> {
        self.execute_with_resource(
            "filters.get",
            session_token,
            "read",
            "filter",
            Some(id),
            |session| async move {
                self.supporting_resources
                    .get_filter(&session.token, id)
                    .await
            },
        )
        .await
    }

    /// Lists tags for an authenticated session.
    pub async fn list_tags(
        &self,
        session_token: &str,
        query: SupportingResourceQuery,
    ) -> Result<TagPage, GatewayError> {
        self.execute_with_resource(
            "tags.list",
            session_token,
            "list",
            "tag",
            None,
            |session| async move {
                self.supporting_resources
                    .list_tags(&session.token, &query)
                    .await
            },
        )
        .await
    }

    /// Fetches a tag for an authenticated session.
    pub async fn get_tag(&self, session_token: &str, id: &str) -> Result<Tag, GatewayError> {
        self.execute_with_resource(
            "tags.get",
            session_token,
            "read",
            "tag",
            Some(id),
            |session| async move { self.supporting_resources.get_tag(&session.token, id).await },
        )
        .await
    }

    /// Lists tickets for an authenticated session.
    pub async fn list_tickets(
        &self,
        session_token: &str,
        query: SupportingResourceQuery,
    ) -> Result<TicketPage, GatewayError> {
        self.execute_with_resource(
            "tickets.list",
            session_token,
            "list",
            "ticket",
            None,
            |session| async move {
                self.supporting_resources
                    .list_tickets(&session.token, &query)
                    .await
            },
        )
        .await
    }

    /// Fetches a ticket for an authenticated session.
    pub async fn get_ticket(&self, session_token: &str, id: &str) -> Result<Ticket, GatewayError> {
        self.execute_with_resource(
            "tickets.get",
            session_token,
            "read",
            "ticket",
            Some(id),
            |session| async move {
                self.supporting_resources
                    .get_ticket(&session.token, id)
                    .await
            },
        )
        .await
    }
}
