// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Greenbone AG

use super::super::*;

impl E2eHarness {
    pub async fn list_schedules(&self, token: &str) -> Result<ListResponse<Schedule>> {
        self.send_json(
            self.authed(Method::GET, "/api/v1/schedules?perPage=1000", token),
            StatusCode::OK,
            "list schedules",
        )
        .await
    }

    pub async fn create_schedule(
        &self,
        token: &str,
        name: &str,
        icalendar: &str,
        timezone: &str,
    ) -> Result<CreatedResource> {
        let body = json!({
            "name": name,
            "comment": "created by compose-backed E2E automation resource coverage",
            "icalendar": icalendar,
            "timezone": timezone,
        });
        self.send_created_json(
            self.authed(Method::POST, "/api/v1/schedules", token)
                .json(&body),
            "create schedule",
        )
        .await
    }

    pub async fn get_schedule(&self, token: &str, schedule_id: &str) -> Result<Schedule> {
        self.send_json(
            self.authed(
                Method::GET,
                &format!("/api/v1/schedules/{schedule_id}"),
                token,
            ),
            StatusCode::OK,
            "get schedule",
        )
        .await
    }

    pub async fn update_schedule(
        &self,
        token: &str,
        schedule_id: &str,
        name: &str,
        comment: &str,
        icalendar: &str,
        timezone: &str,
    ) -> Result<Schedule> {
        let body = json!({
            "name": name,
            "comment": comment,
            "icalendar": icalendar,
            "timezone": timezone,
        });
        self.send_json(
            self.authed(
                Method::PUT,
                &format!("/api/v1/schedules/{schedule_id}"),
                token,
            )
            .json(&body),
            StatusCode::OK,
            "update schedule",
        )
        .await
    }

    pub async fn delete_schedule(&self, token: &str, schedule_id: &str) -> Result<()> {
        self.send_empty(
            self.authed(
                Method::DELETE,
                &format!("/api/v1/schedules/{schedule_id}"),
                token,
            ),
            StatusCode::NO_CONTENT,
            "delete schedule",
        )
        .await
    }

    pub async fn list_alerts(&self, token: &str) -> Result<ListResponse<Alert>> {
        self.send_json(
            self.authed(Method::GET, "/api/v1/alerts?perPage=1000", token),
            StatusCode::OK,
            "list alerts",
        )
        .await
    }

    pub async fn create_alert(&self, token: &str, name: &str) -> Result<CreatedResource> {
        let body = json!({
            "name": name,
            "comment": "created by compose-backed E2E automation resource coverage",
            "event": "task_run_status_changed",
            "condition": "always",
            "method": "syslog",
        });
        self.send_created_json(
            self.authed(Method::POST, "/api/v1/alerts", token)
                .json(&body),
            "create alert",
        )
        .await
    }

    pub async fn get_alert(&self, token: &str, alert_id: &str) -> Result<Alert> {
        self.send_json(
            self.authed(Method::GET, &format!("/api/v1/alerts/{alert_id}"), token),
            StatusCode::OK,
            "get alert",
        )
        .await
    }

    pub async fn delete_alert(&self, token: &str, alert_id: &str) -> Result<()> {
        self.send_empty(
            self.authed(Method::DELETE, &format!("/api/v1/alerts/{alert_id}"), token),
            StatusCode::NO_CONTENT,
            "delete alert",
        )
        .await
    }
}
