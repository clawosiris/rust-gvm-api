// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Greenbone AG

//! Report use cases.

use gvm_gateway_domain::{
    GatewayError, GetReportOpts, Report, ReportExport, ReportPage, ReportQuery, ResultPage,
    ResultQuery, TlsCertificatePage,
};

use crate::GatewayService;

impl GatewayService {
    /// Lists reports for an authenticated session.
    pub async fn list_reports(
        &self,
        session_token: &str,
        query: ReportQuery,
    ) -> Result<ReportPage, GatewayError> {
        self.execute_with_resource(
            "reports.list",
            session_token,
            "list",
            "report",
            None,
            |session| async move { self.reports.list_reports(&session.token, &query).await },
        )
        .await
    }

    /// Fetches a report for an authenticated session.
    pub async fn get_report(
        &self,
        session_token: &str,
        id: &str,
        opts: GetReportOpts,
    ) -> Result<Report, GatewayError> {
        self.execute_with_resource(
            "reports.get",
            session_token,
            "read",
            "report",
            Some(id),
            |session| async move { self.reports.get_report(&session.token, id, &opts).await },
        )
        .await
    }

    /// Exports a rendered report for an authenticated session.
    pub async fn export_report(
        &self,
        session_token: &str,
        report_id: &str,
        report_format_id: &str,
    ) -> Result<ReportExport, GatewayError> {
        self.execute_with_resource(
            "reports.export",
            session_token,
            "read",
            "report_export",
            Some(report_id),
            |session| async move {
                self.reports
                    .export_report(&session.token, report_id, report_format_id)
                    .await
            },
        )
        .await
    }

    /// Deletes a report for an authenticated session.
    pub async fn delete_report(&self, session_token: &str, id: &str) -> Result<(), GatewayError> {
        self.execute_with_resource(
            "reports.delete",
            session_token,
            "delete",
            "report",
            Some(id),
            |session| async move { self.reports.delete_report(&session.token, id).await },
        )
        .await
    }

    /// Lists results for a specific report.
    pub async fn get_report_results(
        &self,
        session_token: &str,
        report_id: &str,
        query: ResultQuery,
    ) -> Result<ResultPage, GatewayError> {
        self.execute_with_resource(
            "reports.results.list",
            session_token,
            "list",
            "report_result",
            Some(report_id),
            |session| async move {
                self.reports
                    .get_report_results(&session.token, report_id, &query)
                    .await
            },
        )
        .await
    }

    /// Lists vulnerability findings for a specific report.
    pub async fn get_report_vulnerabilities(
        &self,
        session_token: &str,
        report_id: &str,
        query: ResultQuery,
    ) -> Result<ResultPage, GatewayError> {
        self.execute_with_resource(
            "reports.vulnerabilities.list",
            session_token,
            "list",
            "report_vulnerability",
            Some(report_id),
            |session| async move {
                self.reports
                    .get_report_vulnerabilities(&session.token, report_id, &query)
                    .await
            },
        )
        .await
    }

    /// Lists TLS certificate observations for a specific report.
    pub async fn get_report_tls_certificates(
        &self,
        session_token: &str,
        report_id: &str,
        query: ResultQuery,
    ) -> Result<TlsCertificatePage, GatewayError> {
        self.execute_with_resource(
            "reports.tls_certificates.list",
            session_token,
            "list",
            "report_tls_certificate",
            Some(report_id),
            |session| async move {
                self.reports
                    .get_report_tls_certificates(&session.token, report_id, &query)
                    .await
            },
        )
        .await
    }

    /// Lists report errors for a specific report.
    pub async fn get_report_errors(
        &self,
        session_token: &str,
        report_id: &str,
        query: ResultQuery,
    ) -> Result<ResultPage, GatewayError> {
        self.execute_with_resource(
            "reports.errors.list",
            session_token,
            "list",
            "report_error",
            Some(report_id),
            |session| async move {
                self.reports
                    .get_report_errors(&session.token, report_id, &query)
                    .await
            },
        )
        .await
    }

    /// Lists closed-CVE findings for a specific report.
    pub async fn get_report_closed_cves(
        &self,
        session_token: &str,
        report_id: &str,
        query: ResultQuery,
    ) -> Result<ResultPage, GatewayError> {
        self.execute_with_resource(
            "reports.closed_cves.list",
            session_token,
            "list",
            "report_closed_cve",
            Some(report_id),
            |session| async move {
                self.reports
                    .get_report_closed_cves(&session.token, report_id, &query)
                    .await
            },
        )
        .await
    }
}
