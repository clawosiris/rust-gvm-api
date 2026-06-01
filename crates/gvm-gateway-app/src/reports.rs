// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Greenbone AG

//! Report use cases.

use gvm_gateway_domain::{
    GatewayError, GetReportOpts, Pagination, Report, ReportExport, ReportPage, ReportQuery,
    ResultPage, ResultQuery, ScanResult, TlsCertificate, TlsCertificatePage,
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
                let page = self
                    .reports
                    .get_report_results(&session.token, report_id, &unpaginated_query(&query))
                    .await?;
                Ok(filter_result_page(page, &query, is_vulnerability_result))
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
                let page = self
                    .reports
                    .get_report_results(&session.token, report_id, &unpaginated_query(&query))
                    .await?;
                let certificates = page
                    .data
                    .into_iter()
                    .filter(is_tls_certificate_result)
                    .map(result_to_tls_certificate)
                    .collect::<Vec<_>>();
                Ok(paginate_tls_certificates(certificates, &query))
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
                let page = self
                    .reports
                    .get_report_results(&session.token, report_id, &unpaginated_query(&query))
                    .await?;
                Ok(filter_result_page(page, &query, is_error_result))
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
                let page = self
                    .reports
                    .get_report_results(&session.token, report_id, &unpaginated_query(&query))
                    .await?;
                Ok(filter_result_page(page, &query, is_closed_cve_result))
            },
        )
        .await
    }
}

fn unpaginated_query(query: &ResultQuery) -> ResultQuery {
    ResultQuery {
        filter_string: query.filter_string.clone(),
        filter_id: query.filter_id.clone(),
        page: 1,
        per_page: u32::MAX,
    }
}

fn filter_result_page(
    page: ResultPage,
    query: &ResultQuery,
    predicate: impl Fn(&ScanResult) -> bool,
) -> ResultPage {
    let filtered = page.data.into_iter().filter(predicate).collect::<Vec<_>>();
    paginate_results(filtered, query)
}

fn paginate_results(results: Vec<ScanResult>, query: &ResultQuery) -> ResultPage {
    let total = results.len() as u32;
    let total_pages = if total == 0 {
        0
    } else {
        ((total - 1) / query.per_page) + 1
    };
    let start = ((query.page.saturating_sub(1)) * query.per_page) as usize;

    ResultPage {
        data: results
            .into_iter()
            .skip(start)
            .take(query.per_page as usize)
            .collect(),
        pagination: Pagination {
            page: query.page,
            per_page: query.per_page,
            total,
            total_pages,
        },
    }
}

fn paginate_tls_certificates(
    certificates: Vec<TlsCertificate>,
    query: &ResultQuery,
) -> TlsCertificatePage {
    let total = certificates.len() as u32;
    let total_pages = if total == 0 {
        0
    } else {
        ((total - 1) / query.per_page) + 1
    };
    let start = ((query.page.saturating_sub(1)) * query.per_page) as usize;

    TlsCertificatePage {
        data: certificates
            .into_iter()
            .skip(start)
            .take(query.per_page as usize)
            .collect(),
        pagination: Pagination {
            page: query.page,
            per_page: query.per_page,
            total,
            total_pages,
        },
    }
}

fn is_vulnerability_result(result: &ScanResult) -> bool {
    result.nvt.is_some() || result.severity.is_some()
}

fn is_error_result(result: &ScanResult) -> bool {
    result
        .threat
        .as_deref()
        .is_some_and(|threat| threat.eq_ignore_ascii_case("alarm"))
        || result_text(result).contains("error")
        || result_text(result).contains("failed")
}

fn is_closed_cve_result(result: &ScanResult) -> bool {
    let text = result_text(result);
    text.contains("closed cve") || text.contains("closed-cve") || text.contains("closed cves")
}

fn is_tls_certificate_result(result: &ScanResult) -> bool {
    let text = result_text(result);
    (text.contains("tls") || text.contains("ssl")) && text.contains("certificate")
}

fn result_to_tls_certificate(result: ScanResult) -> TlsCertificate {
    TlsCertificate {
        id: Some(result.id),
        host: result.host,
        port: result.port,
        subject: result.name,
        issuer: None,
        not_before: None,
        not_after: None,
        fingerprint_sha256: None,
    }
}

fn result_text(result: &ScanResult) -> String {
    let mut text = result.name.to_ascii_lowercase();
    if let Some(description) = result.description.as_deref() {
        text.push(' ');
        text.push_str(&description.to_ascii_lowercase());
    }
    text
}
