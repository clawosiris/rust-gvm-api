// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Greenbone AG

use super::super::*;

impl E2eHarness {
    pub async fn list_port_lists(&self, token: &str) -> Result<Vec<PortList>> {
        let response: ListResponse<PortList> = self
            .send_json(
                self.authed(Method::GET, "/api/v1/port-lists", token),
                StatusCode::OK,
                "list port lists",
            )
            .await?;
        Ok(response.data)
    }

    pub async fn create_port_list(
        &self,
        token: &str,
        name: &str,
        port_range: &str,
    ) -> Result<CreatedResource> {
        let body = json!({
            "name": name,
            "comment": "created by compose-backed E2E supporting resource coverage",
            "portRange": port_range,
        });
        self.send_created_json(
            self.authed(Method::POST, "/api/v1/port-lists", token)
                .json(&body),
            "create port list",
        )
        .await
    }

    pub async fn get_port_list(&self, token: &str, port_list_id: &str) -> Result<PortList> {
        self.send_json(
            self.authed(
                Method::GET,
                &format!("/api/v1/port-lists/{port_list_id}"),
                token,
            ),
            StatusCode::OK,
            "get port list",
        )
        .await
    }

    pub async fn update_port_list_comment(
        &self,
        token: &str,
        port_list_id: &str,
        comment: &str,
    ) -> Result<PortList> {
        let body = json!({
            "comment": comment,
        });
        self.send_json(
            self.authed(
                Method::PUT,
                &format!("/api/v1/port-lists/{port_list_id}"),
                token,
            )
            .json(&body),
            StatusCode::OK,
            "update port list",
        )
        .await
    }

    pub async fn delete_port_list(&self, token: &str, port_list_id: &str) -> Result<()> {
        self.send_empty(
            self.authed(
                Method::DELETE,
                &format!("/api/v1/port-lists/{port_list_id}"),
                token,
            ),
            StatusCode::NO_CONTENT,
            "delete port list",
        )
        .await
    }

    pub async fn list_feeds(&self, token: &str) -> Result<Vec<Feed>> {
        let response: UnpaginatedListResponse<Feed> = self
            .send_json(
                self.authed(Method::GET, "/api/v1/feeds", token),
                StatusCode::OK,
                "list feeds",
            )
            .await?;
        Ok(response.data)
    }

    pub async fn list_hosts(&self, token: &str) -> Result<ListResponse<HostResource>> {
        self.send_json(
            self.authed(Method::GET, "/api/v1/hosts?perPage=1000", token),
            StatusCode::OK,
            "list hosts",
        )
        .await
    }

    pub async fn list_hosts_page(
        &self,
        token: &str,
        page: u32,
        per_page: u32,
    ) -> Result<ListResponse<HostResource>> {
        self.send_json(
            self.authed(
                Method::GET,
                &format!("/api/v1/hosts?page={page}&perPage={per_page}"),
                token,
            ),
            StatusCode::OK,
            "list hosts page",
        )
        .await
    }

    pub async fn get_host(&self, token: &str, host_id: &str) -> Result<HostResource> {
        self.send_json(
            self.authed(Method::GET, &format!("/api/v1/hosts/{host_id}"), token),
            StatusCode::OK,
            "get host",
        )
        .await
    }

    pub async fn list_report_formats(&self, token: &str) -> Result<ListResponse<ReportFormat>> {
        self.send_json(
            self.authed(Method::GET, "/api/v1/report-formats?perPage=1000", token),
            StatusCode::OK,
            "list report formats",
        )
        .await
    }

    pub async fn get_report_format(
        &self,
        token: &str,
        report_format_id: &str,
    ) -> Result<ReportFormat> {
        self.send_json(
            self.authed(
                Method::GET,
                &format!("/api/v1/report-formats/{report_format_id}"),
                token,
            ),
            StatusCode::OK,
            "get report format",
        )
        .await
    }

    pub async fn list_filters(&self, token: &str) -> Result<ListResponse<FilterResource>> {
        self.send_json(
            self.authed(Method::GET, "/api/v1/filters?perPage=1000", token),
            StatusCode::OK,
            "list filters",
        )
        .await
    }

    pub async fn get_filter(&self, token: &str, filter_id: &str) -> Result<FilterResource> {
        self.send_json(
            self.authed(Method::GET, &format!("/api/v1/filters/{filter_id}"), token),
            StatusCode::OK,
            "get filter",
        )
        .await
    }

    pub async fn list_tags(&self, token: &str) -> Result<ListResponse<TagResource>> {
        self.send_json(
            self.authed(Method::GET, "/api/v1/tags?perPage=1000", token),
            StatusCode::OK,
            "list tags",
        )
        .await
    }

    pub async fn get_tag(&self, token: &str, tag_id: &str) -> Result<TagResource> {
        self.send_json(
            self.authed(Method::GET, &format!("/api/v1/tags/{tag_id}"), token),
            StatusCode::OK,
            "get tag",
        )
        .await
    }

    pub async fn list_tickets(&self, token: &str) -> Result<ListResponse<Ticket>> {
        self.send_json(
            self.authed(Method::GET, "/api/v1/tickets?perPage=1000", token),
            StatusCode::OK,
            "list tickets",
        )
        .await
    }

    pub async fn get_ticket(&self, token: &str, ticket_id: &str) -> Result<Ticket> {
        self.send_json(
            self.authed(Method::GET, &format!("/api/v1/tickets/{ticket_id}"), token),
            StatusCode::OK,
            "get ticket",
        )
        .await
    }

    pub async fn list_notes(&self, token: &str) -> Result<ListResponse<NoteResource>> {
        self.send_json(
            self.authed(Method::GET, "/api/v1/notes?perPage=1000", token),
            StatusCode::OK,
            "list notes",
        )
        .await
    }

    pub async fn list_notes_filtered(
        &self,
        token: &str,
        filter: &str,
    ) -> Result<ListResponse<NoteResource>> {
        self.send_json(
            self.authed(
                Method::GET,
                &format!("/api/v1/notes?perPage=1000&filter={filter}"),
                token,
            ),
            StatusCode::OK,
            "list notes with filter",
        )
        .await
    }

    pub async fn get_note(&self, token: &str, note_id: &str) -> Result<NoteResource> {
        self.send_json(
            self.authed(Method::GET, &format!("/api/v1/notes/{note_id}"), token),
            StatusCode::OK,
            "get note",
        )
        .await
    }

    pub async fn create_note(
        &self,
        token: &str,
        nvt_oid: &str,
        task_id: &str,
        result_id: &str,
        text: &str,
    ) -> Result<CreatedResource> {
        let body = json!({
            "nvtOid": nvt_oid,
            "taskId": task_id,
            "resultId": result_id,
            "text": text,
            "active": true,
            "orphan": false,
        });
        self.send_created_json(
            self.authed(Method::POST, "/api/v1/notes", token)
                .json(&body),
            "create note",
        )
        .await
    }

    pub async fn update_note(
        &self,
        token: &str,
        note_id: &str,
        text: &str,
        active: bool,
    ) -> Result<NoteResource> {
        let body = json!({
            "text": text,
            "active": active,
        });
        self.send_json(
            self.authed(Method::PUT, &format!("/api/v1/notes/{note_id}"), token)
                .json(&body),
            StatusCode::OK,
            "update note",
        )
        .await
    }

    pub async fn delete_note(&self, token: &str, note_id: &str, ultimate: bool) -> Result<()> {
        self.send_empty(
            self.authed(
                Method::DELETE,
                &format!("/api/v1/notes/{note_id}?ultimate={ultimate}"),
                token,
            ),
            StatusCode::NO_CONTENT,
            "delete note",
        )
        .await
    }

    pub async fn list_overrides(&self, token: &str) -> Result<ListResponse<OverrideResource>> {
        self.send_json(
            self.authed(Method::GET, "/api/v1/overrides?perPage=1000", token),
            StatusCode::OK,
            "list overrides",
        )
        .await
    }

    pub async fn list_overrides_filtered(
        &self,
        token: &str,
        filter: &str,
    ) -> Result<ListResponse<OverrideResource>> {
        self.send_json(
            self.authed(
                Method::GET,
                &format!("/api/v1/overrides?perPage=1000&filter={filter}"),
                token,
            ),
            StatusCode::OK,
            "list overrides with filter",
        )
        .await
    }

    pub async fn get_override(&self, token: &str, override_id: &str) -> Result<OverrideResource> {
        self.send_json(
            self.authed(
                Method::GET,
                &format!("/api/v1/overrides/{override_id}"),
                token,
            ),
            StatusCode::OK,
            "get override",
        )
        .await
    }

    pub async fn create_override(
        &self,
        token: &str,
        nvt_oid: &str,
        task_id: &str,
        result_id: &str,
        text: &str,
        new_severity: &str,
    ) -> Result<CreatedResource> {
        let body = json!({
            "nvtOid": nvt_oid,
            "taskId": task_id,
            "resultId": result_id,
            "text": text,
            "newSeverity": new_severity,
            "active": true,
        });
        self.send_created_json(
            self.authed(Method::POST, "/api/v1/overrides", token)
                .json(&body),
            "create override",
        )
        .await
    }

    pub async fn update_override(
        &self,
        token: &str,
        override_id: &str,
        text: &str,
        new_severity: &str,
        active: bool,
    ) -> Result<OverrideResource> {
        let body = json!({
            "text": text,
            "newSeverity": new_severity,
            "active": active,
        });
        self.send_json(
            self.authed(
                Method::PUT,
                &format!("/api/v1/overrides/{override_id}"),
                token,
            )
            .json(&body),
            StatusCode::OK,
            "update override",
        )
        .await
    }

    pub async fn delete_override(
        &self,
        token: &str,
        override_id: &str,
        ultimate: bool,
    ) -> Result<()> {
        self.send_empty(
            self.authed(
                Method::DELETE,
                &format!("/api/v1/overrides/{override_id}?ultimate={ultimate}"),
                token,
            ),
            StatusCode::NO_CONTENT,
            "delete override",
        )
        .await
    }

    pub async fn list_nvts(&self, token: &str) -> Result<ListResponse<NvtCatalogEntry>> {
        self.send_json(
            self.authed(Method::GET, "/api/v1/nvts?perPage=1000", token),
            StatusCode::OK,
            "list nvts",
        )
        .await
    }

    pub async fn list_nvts_page(
        &self,
        token: &str,
        page: u32,
        per_page: u32,
    ) -> Result<ListResponse<NvtCatalogEntry>> {
        self.send_json(
            self.authed(
                Method::GET,
                &format!("/api/v1/nvts?page={page}&perPage={per_page}"),
                token,
            ),
            StatusCode::OK,
            "list nvts page",
        )
        .await
    }

    pub async fn get_nvt(&self, token: &str, oid: &str) -> Result<NvtCatalogEntry> {
        self.send_json(
            self.authed(Method::GET, &format!("/api/v1/nvts/{oid}"), token),
            StatusCode::OK,
            "get nvt",
        )
        .await
    }

    pub async fn list_nvt_families(&self, token: &str) -> Result<ListResponse<NvtFamily>> {
        self.send_json(
            self.authed(Method::GET, "/api/v1/nvt-families?perPage=1000", token),
            StatusCode::OK,
            "list nvt families",
        )
        .await
    }

    pub async fn list_credential_stores(&self, token: &str) -> Result<Vec<CredentialStore>> {
        let response: UnpaginatedListResponse<CredentialStore> = self
            .send_json(
                self.authed(Method::GET, "/api/v1/credential-stores", token),
                StatusCode::OK,
                "list credential stores",
            )
            .await?;
        Ok(response.data)
    }

    pub async fn list_credentials(&self, token: &str) -> Result<ListResponse<Credential>> {
        self.send_json(
            self.authed(Method::GET, "/api/v1/credentials?perPage=1000", token),
            StatusCode::OK,
            "list credentials",
        )
        .await
    }

    pub async fn create_username_password_credential(
        &self,
        token: &str,
        name: &str,
        login: &str,
        password: &str,
    ) -> Result<CreatedResource> {
        let body = json!({
            "name": name,
            "comment": "created by compose-backed E2E supporting resource coverage",
            "type": "up",
            "login": login,
            "password": password,
        });
        self.send_created_json(
            self.authed(Method::POST, "/api/v1/credentials", token)
                .json(&body),
            "create credential",
        )
        .await
    }

    pub async fn get_credential(&self, token: &str, credential_id: &str) -> Result<Credential> {
        self.send_json(
            self.authed(
                Method::GET,
                &format!("/api/v1/credentials/{credential_id}"),
                token,
            ),
            StatusCode::OK,
            "get credential",
        )
        .await
    }

    pub async fn delete_credential(&self, token: &str, credential_id: &str) -> Result<()> {
        self.send_empty(
            self.authed(
                Method::DELETE,
                &format!("/api/v1/credentials/{credential_id}"),
                token,
            ),
            StatusCode::NO_CONTENT,
            "delete credential",
        )
        .await
    }
}
