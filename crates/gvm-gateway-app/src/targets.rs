// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Greenbone AG

//! Target use cases.

use gvm_gateway_domain::{
    CreateOciImageTargetInput, CreateTargetInput, CreateWebApplicationTargetInput, GatewayError,
    ModifyOciImageTargetInput, ModifyTargetInput, ModifyWebApplicationTargetInput, OciImageTarget,
    OciImageTargetPage, SpecializedTargetQuery, Target, TargetPage, TargetQuery,
    WebApplicationTarget, WebApplicationTargetPage,
};

use crate::GatewayService;

impl GatewayService {
    /// Lists targets for an authenticated session.
    pub async fn list_targets(
        &self,
        session_token: &str,
        query: TargetQuery,
    ) -> Result<TargetPage, GatewayError> {
        self.execute_with_resource(
            "targets.list",
            session_token,
            "list",
            "target",
            None,
            |session| async move { self.targets.list_targets(&session.token, &query).await },
        )
        .await
    }

    /// Creates a new target for an authenticated session.
    pub async fn create_target(
        &self,
        session_token: &str,
        input: CreateTargetInput,
    ) -> Result<String, GatewayError> {
        self.execute_with_resource(
            "targets.create",
            session_token,
            "create",
            "target",
            None,
            |session| async move { self.targets.create_target(&session.token, input).await },
        )
        .await
    }

    /// Clones a target for an authenticated session.
    pub async fn clone_target(
        &self,
        session_token: &str,
        id: &str,
    ) -> Result<String, GatewayError> {
        self.execute_with_resource(
            "targets.clone",
            session_token,
            "create",
            "target",
            Some(id),
            |session| async move { self.targets.clone_target(&session.token, id).await },
        )
        .await
    }

    /// Fetches a target for an authenticated session.
    pub async fn get_target(&self, session_token: &str, id: &str) -> Result<Target, GatewayError> {
        self.execute_with_resource(
            "targets.get",
            session_token,
            "read",
            "target",
            Some(id),
            |session| async move { self.targets.get_target(&session.token, id).await },
        )
        .await
    }

    /// Modifies a target for an authenticated session.
    pub async fn modify_target(
        &self,
        session_token: &str,
        id: &str,
        input: ModifyTargetInput,
    ) -> Result<Target, GatewayError> {
        self.execute_with_resource(
            "targets.modify",
            session_token,
            "modify",
            "target",
            Some(id),
            |session| async move { self.targets.modify_target(&session.token, id, input).await },
        )
        .await
    }

    /// Deletes a target for an authenticated session.
    pub async fn delete_target(
        &self,
        session_token: &str,
        id: &str,
        ultimate: bool,
    ) -> Result<(), GatewayError> {
        self.execute_with_resource(
            "targets.delete",
            session_token,
            "delete",
            "target",
            Some(id),
            |session| async move {
                self.targets
                    .delete_target(&session.token, id, ultimate)
                    .await
            },
        )
        .await
    }

    /// Lists OCI image targets for an authenticated session.
    pub async fn list_oci_image_targets(
        &self,
        token: &str,
        query: SpecializedTargetQuery,
    ) -> Result<OciImageTargetPage, GatewayError> {
        self.execute_with_resource(
            "oci_image_targets.list",
            token,
            "list",
            "oci_image_target",
            None,
            |session| async move {
                self.targets
                    .list_oci_image_targets(&session.token, &query)
                    .await
            },
        )
        .await
    }
    /// Creates an OCI image target.
    pub async fn create_oci_image_target(
        &self,
        token: &str,
        input: CreateOciImageTargetInput,
    ) -> Result<String, GatewayError> {
        self.execute_with_resource(
            "oci_image_targets.create",
            token,
            "create",
            "oci_image_target",
            None,
            |session| async move {
                self.targets
                    .create_oci_image_target(&session.token, input)
                    .await
            },
        )
        .await
    }
    /// Clones an OCI image target.
    pub async fn clone_oci_image_target(
        &self,
        token: &str,
        id: &str,
    ) -> Result<String, GatewayError> {
        self.execute_with_resource(
            "oci_image_targets.clone",
            token,
            "create",
            "oci_image_target",
            Some(id),
            |session| async move {
                self.targets
                    .clone_oci_image_target(&session.token, id)
                    .await
            },
        )
        .await
    }
    /// Gets an OCI image target.
    pub async fn get_oci_image_target(
        &self,
        token: &str,
        id: &str,
    ) -> Result<OciImageTarget, GatewayError> {
        self.execute_with_resource(
            "oci_image_targets.get",
            token,
            "read",
            "oci_image_target",
            Some(id),
            |session| async move { self.targets.get_oci_image_target(&session.token, id).await },
        )
        .await
    }
    /// Modifies an OCI image target.
    pub async fn modify_oci_image_target(
        &self,
        token: &str,
        id: &str,
        input: ModifyOciImageTargetInput,
    ) -> Result<OciImageTarget, GatewayError> {
        self.execute_with_resource(
            "oci_image_targets.modify",
            token,
            "modify",
            "oci_image_target",
            Some(id),
            |session| async move {
                self.targets
                    .modify_oci_image_target(&session.token, id, input)
                    .await
            },
        )
        .await
    }
    /// Deletes an OCI image target.
    pub async fn delete_oci_image_target(
        &self,
        token: &str,
        id: &str,
        ultimate: bool,
    ) -> Result<(), GatewayError> {
        self.execute_with_resource(
            "oci_image_targets.delete",
            token,
            "delete",
            "oci_image_target",
            Some(id),
            |session| async move {
                self.targets
                    .delete_oci_image_target(&session.token, id, ultimate)
                    .await
            },
        )
        .await
    }

    /// Lists web application targets for an authenticated session.
    pub async fn list_web_application_targets(
        &self,
        token: &str,
        query: SpecializedTargetQuery,
    ) -> Result<WebApplicationTargetPage, GatewayError> {
        self.execute_with_resource(
            "web_application_targets.list",
            token,
            "list",
            "web_application_target",
            None,
            |session| async move {
                self.targets
                    .list_web_application_targets(&session.token, &query)
                    .await
            },
        )
        .await
    }
    /// Creates a web application target.
    pub async fn create_web_application_target(
        &self,
        token: &str,
        input: CreateWebApplicationTargetInput,
    ) -> Result<String, GatewayError> {
        self.execute_with_resource(
            "web_application_targets.create",
            token,
            "create",
            "web_application_target",
            None,
            |session| async move {
                self.targets
                    .create_web_application_target(&session.token, input)
                    .await
            },
        )
        .await
    }
    /// Clones a web application target.
    pub async fn clone_web_application_target(
        &self,
        token: &str,
        id: &str,
    ) -> Result<String, GatewayError> {
        self.execute_with_resource(
            "web_application_targets.clone",
            token,
            "create",
            "web_application_target",
            Some(id),
            |session| async move {
                self.targets
                    .clone_web_application_target(&session.token, id)
                    .await
            },
        )
        .await
    }
    /// Gets a web application target.
    pub async fn get_web_application_target(
        &self,
        token: &str,
        id: &str,
    ) -> Result<WebApplicationTarget, GatewayError> {
        self.execute_with_resource(
            "web_application_targets.get",
            token,
            "read",
            "web_application_target",
            Some(id),
            |session| async move {
                self.targets
                    .get_web_application_target(&session.token, id)
                    .await
            },
        )
        .await
    }
    /// Modifies a web application target.
    pub async fn modify_web_application_target(
        &self,
        token: &str,
        id: &str,
        input: ModifyWebApplicationTargetInput,
    ) -> Result<WebApplicationTarget, GatewayError> {
        self.execute_with_resource(
            "web_application_targets.modify",
            token,
            "modify",
            "web_application_target",
            Some(id),
            |session| async move {
                self.targets
                    .modify_web_application_target(&session.token, id, input)
                    .await
            },
        )
        .await
    }
    /// Deletes a web application target.
    pub async fn delete_web_application_target(
        &self,
        token: &str,
        id: &str,
        ultimate: bool,
    ) -> Result<(), GatewayError> {
        self.execute_with_resource(
            "web_application_targets.delete",
            token,
            "delete",
            "web_application_target",
            Some(id),
            |session| async move {
                self.targets
                    .delete_web_application_target(&session.token, id, ultimate)
                    .await
            },
        )
        .await
    }
}
