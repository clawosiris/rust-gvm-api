// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Greenbone AG

use super::super::*;

impl E2eHarness {
    pub async fn list_users(&self, token: &str) -> Result<ListResponse<User>> {
        self.send_json(
            self.authed(Method::GET, "/api/v1/users?perPage=1000", token),
            StatusCode::OK,
            "list users",
        )
        .await
    }

    pub async fn get_user(&self, token: &str, user_id: &str) -> Result<User> {
        self.send_json(
            self.authed(Method::GET, &format!("/api/v1/users/{user_id}"), token),
            StatusCode::OK,
            "get user",
        )
        .await
    }

    pub async fn list_groups(&self, token: &str) -> Result<ListResponse<Group>> {
        self.send_json(
            self.authed(Method::GET, "/api/v1/groups?perPage=1000", token),
            StatusCode::OK,
            "list groups",
        )
        .await
    }

    pub async fn create_group(&self, token: &str, name: &str) -> Result<CreatedResource> {
        let body = json!({
            "name": name,
            "comment": "created by compose-backed E2E identity/admin coverage",
            "users": [],
        });
        self.send_created_json(
            self.authed(Method::POST, "/api/v1/groups", token)
                .json(&body),
            "create group",
        )
        .await
    }

    pub async fn get_group(&self, token: &str, group_id: &str) -> Result<Group> {
        self.send_json(
            self.authed(Method::GET, &format!("/api/v1/groups/{group_id}"), token),
            StatusCode::OK,
            "get group",
        )
        .await
    }

    pub async fn delete_group(&self, token: &str, group_id: &str) -> Result<()> {
        self.send_empty(
            self.authed(Method::DELETE, &format!("/api/v1/groups/{group_id}"), token),
            StatusCode::NO_CONTENT,
            "delete group",
        )
        .await
    }

    pub async fn list_roles(&self, token: &str) -> Result<ListResponse<Role>> {
        self.send_json(
            self.authed(Method::GET, "/api/v1/roles?perPage=1000", token),
            StatusCode::OK,
            "list roles",
        )
        .await
    }

    pub async fn get_role(&self, token: &str, role_id: &str) -> Result<Role> {
        self.send_json(
            self.authed(Method::GET, &format!("/api/v1/roles/{role_id}"), token),
            StatusCode::OK,
            "get role",
        )
        .await
    }

    pub async fn list_permissions(&self, token: &str) -> Result<ListResponse<Permission>> {
        self.send_json(
            self.authed(Method::GET, "/api/v1/permissions?perPage=1000", token),
            StatusCode::OK,
            "list permissions",
        )
        .await
    }

    pub async fn get_permission(&self, token: &str, permission_id: &str) -> Result<Permission> {
        self.send_json(
            self.authed(
                Method::GET,
                &format!("/api/v1/permissions/{permission_id}"),
                token,
            ),
            StatusCode::OK,
            "get permission",
        )
        .await
    }

    pub async fn list_user_settings(
        &self,
        token: &str,
    ) -> Result<UnpaginatedListResponse<UserSetting>> {
        self.send_json(
            self.authed(Method::GET, "/api/v1/user-settings", token),
            StatusCode::OK,
            "list user settings",
        )
        .await
    }

    pub async fn get_user_setting(&self, token: &str, setting_id: &str) -> Result<UserSetting> {
        self.send_json(
            self.authed(
                Method::GET,
                &format!("/api/v1/user-settings/{setting_id}"),
                token,
            ),
            StatusCode::OK,
            "get user setting",
        )
        .await
    }

    pub async fn update_user_setting(
        &self,
        token: &str,
        setting_id: &str,
        value: &str,
    ) -> Result<UserSetting> {
        let body = json!({
            "value": value,
        });
        self.send_json(
            self.authed(
                Method::PUT,
                &format!("/api/v1/user-settings/{setting_id}"),
                token,
            )
            .json(&body),
            StatusCode::OK,
            "update user setting",
        )
        .await
    }
}
