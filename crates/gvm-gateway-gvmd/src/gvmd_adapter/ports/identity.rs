// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Greenbone AG
use super::super::*;

#[async_trait]
impl IdentityPort for GvmdAdapter {
    async fn list_users(
        &self,
        session_token: &str,
        query: &IdentityQuery,
    ) -> Result<UserPage, GatewayError> {
        let filter_id = query
            .filter_id
            .as_deref()
            .map(parse_entity_id)
            .transpose()?;
        let response = self
            .call_with_session(
                session_token,
                "users.list",
                get_users(GetUsersOpts {
                    filter_string: self
                        .paginated_filter_resolving_filter_id(
                            session_token,
                            None,
                            query.filter_string.as_deref(),
                            filter_id.as_ref(),
                            query.page,
                            query.per_page,
                            &[],
                        )
                        .await?,
                    filter_id: None,
                    trash: None,
                    details: Some(true),
                }),
            )
            .await?;
        let parsed = GetUsersResponse::from_response(&response).map_err(map_parse_error)?;
        let items = parsed
            .items
            .into_iter()
            .map(user_from_gmp)
            .collect::<Vec<_>>();
        let total = gvmd_total(parsed.counts.filtered, parsed.counts.total, items.len());

        Ok(UserPage {
            data: items,
            pagination: paged_pagination(total, query.page, query.per_page),
        })
    }

    async fn create_user(
        &self,
        session_token: &str,
        input: CreateUserInput,
    ) -> Result<String, GatewayError> {
        let role_ids = input
            .role_ids
            .into_iter()
            .map(|value| parse_entity_id(&value))
            .collect::<Result<Vec<_>, _>>()?;
        let auth_type = input
            .authentication_type
            .as_deref()
            .map(parse_user_auth_type)
            .transpose()?;
        let response = self
            .call_with_session(
                session_token,
                "users.create",
                create_user(
                    &input.name,
                    UserOpts {
                        comment: input.comment,
                        password: input.password,
                        host_access: input.hosts.map(UserHostAccess::allow),
                        role_ids,
                        auth_type,
                    },
                ),
            )
            .await?;
        let parsed = CreateUserResponse::from_response(&response).map_err(map_parse_error)?;
        Ok(parsed.id.to_string())
    }

    async fn get_user(&self, session_token: &str, id: &str) -> Result<User, GatewayError> {
        Ok(user_from_gmp(self.get_gmp_user(session_token, id).await?))
    }

    async fn modify_user(
        &self,
        session_token: &str,
        id: &str,
        input: ModifyUserInput,
    ) -> Result<User, GatewayError> {
        let user_id = parse_entity_id(id)?;
        let ModifyUserInput {
            name,
            comment,
            password,
            hosts,
            role_ids,
            authentication_type,
        } = input;
        let host_access = match hosts {
            Some(hosts) => Some(UserHostAccess::allow(hosts)),
            None => self.get_gmp_user(session_token, id).await?.host_access(),
        };
        let role_ids = role_ids
            .map(|role_ids| {
                role_ids
                    .into_iter()
                    .map(|value| parse_entity_id(&value))
                    .collect::<Result<Vec<_>, _>>()
                    .map(CollectionUpdate::from)
            })
            .transpose()?
            .unwrap_or_default();
        let auth_type = authentication_type
            .as_deref()
            .map(parse_user_auth_type)
            .transpose()?;
        let response = self
            .call_with_session(
                session_token,
                "users.modify",
                modify_user(
                    &user_id,
                    ModifyUserOpts {
                        new_name: name,
                        comment,
                        password,
                        host_access,
                        role_ids,
                        auth_type,
                    },
                ),
            )
            .await?;
        let _ = ActionResponse::from_response(&response).map_err(map_parse_error)?;
        self.get_user(session_token, id).await
    }

    async fn delete_user(
        &self,
        session_token: &str,
        id: &str,
        ultimate: bool,
    ) -> Result<(), GatewayError> {
        let response = self
            .call_with_session(
                session_token,
                "users.delete",
                delete_user(&parse_entity_id(id)?, ultimate),
            )
            .await?;
        let _ = ActionResponse::from_response(&response).map_err(map_parse_error)?;
        Ok(())
    }

    async fn list_groups(
        &self,
        session_token: &str,
        query: &IdentityQuery,
    ) -> Result<GroupPage, GatewayError> {
        let filter_id = query
            .filter_id
            .as_deref()
            .map(parse_entity_id)
            .transpose()?;
        let response = self
            .call_with_session(
                session_token,
                "groups.list",
                get_groups(GetGroupsOpts {
                    filter_string: self
                        .paginated_filter_resolving_filter_id(
                            session_token,
                            None,
                            query.filter_string.as_deref(),
                            filter_id.as_ref(),
                            query.page,
                            query.per_page,
                            &[],
                        )
                        .await?,
                    filter_id: None,
                    trash: None,
                    details: Some(true),
                }),
            )
            .await?;
        let parsed = GetGroupsResponse::from_response(&response).map_err(map_parse_error)?;
        let items = parsed
            .items
            .into_iter()
            .map(group_from_gmp)
            .collect::<Vec<_>>();
        let total = gvmd_total(parsed.counts.filtered, parsed.counts.total, items.len());

        Ok(GroupPage {
            data: items,
            pagination: paged_pagination(total, query.page, query.per_page),
        })
    }

    async fn create_group(
        &self,
        session_token: &str,
        input: CreateGroupInput,
    ) -> Result<String, GatewayError> {
        let client = self.session_client(session_token)?;
        let response = client
            .lock()
            .await?
            .call(create_group(
                &input.name,
                GroupOpts {
                    comment: input.comment,
                    users: input.users,
                },
            ))
            .await
            .map_err(map_gvm_error)?;
        let parsed = CreateGroupResponse::from_response(&response).map_err(map_parse_error)?;
        Ok(parsed.id.to_string())
    }

    async fn get_group(&self, session_token: &str, id: &str) -> Result<Group, GatewayError> {
        let client = self.session_client(session_token)?;
        let response = client
            .lock()
            .await?
            .call(get_group(&parse_entity_id(id)?))
            .await
            .map_err(map_gvm_error)?;
        let parsed = GetGroupsResponse::from_response(&response).map_err(map_parse_error)?;
        let group = parsed
            .items
            .into_iter()
            .next()
            .ok_or_else(|| GatewayError::NotFound(format!("group {id} not found")))?;
        Ok(group_from_gmp(group))
    }

    async fn modify_group(
        &self,
        session_token: &str,
        id: &str,
        input: ModifyGroupInput,
    ) -> Result<Group, GatewayError> {
        let client = self.session_client(session_token)?;
        let response = client
            .lock()
            .await?
            .call(modify_group(
                &parse_entity_id(id)?,
                GroupOpts {
                    comment: input.comment,
                    users: input.users.unwrap_or_default(),
                },
            ))
            .await
            .map_err(map_gvm_error)?;
        let _ = ActionResponse::from_response(&response).map_err(map_parse_error)?;
        self.get_group(session_token, id).await
    }

    async fn delete_group(
        &self,
        session_token: &str,
        id: &str,
        ultimate: bool,
    ) -> Result<(), GatewayError> {
        let client = self.session_client(session_token)?;
        let response = client
            .lock()
            .await?
            .call(delete_group(&parse_entity_id(id)?, ultimate))
            .await
            .map_err(map_gvm_error)?;
        let _ = ActionResponse::from_response(&response).map_err(map_parse_error)?;
        Ok(())
    }

    async fn list_roles(
        &self,
        session_token: &str,
        query: &IdentityQuery,
    ) -> Result<RolePage, GatewayError> {
        let client = self.session_client(session_token)?;
        let filter_id = query
            .filter_id
            .as_deref()
            .map(parse_entity_id)
            .transpose()?;
        let filter_string = self
            .paginated_filter_resolving_filter_id(
                session_token,
                None,
                query.filter_string.as_deref(),
                filter_id.as_ref(),
                query.page,
                query.per_page,
                &[],
            )
            .await?;
        let response = client
            .lock()
            .await?
            .call(get_roles(GetRolesOpts {
                filter_string,
                filter_id: None,
                trash: None,
                details: Some(true),
            }))
            .await
            .map_err(map_gvm_error)?;
        let parsed = GetRolesResponse::from_response(&response).map_err(map_parse_error)?;
        let items = parsed
            .items
            .into_iter()
            .map(role_from_gmp)
            .collect::<Vec<_>>();
        let total = gvmd_total(parsed.counts.filtered, parsed.counts.total, items.len());

        Ok(RolePage {
            data: items,
            pagination: paged_pagination(total, query.page, query.per_page),
        })
    }

    async fn create_role(
        &self,
        session_token: &str,
        input: CreateRoleInput,
    ) -> Result<String, GatewayError> {
        let client = self.session_client(session_token)?;
        let response = client
            .lock()
            .await?
            .call(create_role(
                &input.name,
                RoleOpts {
                    comment: input.comment,
                    users: input.users,
                },
            ))
            .await
            .map_err(map_gvm_error)?;
        let parsed = CreateRoleResponse::from_response(&response).map_err(map_parse_error)?;
        Ok(parsed.id.to_string())
    }

    async fn get_role(&self, session_token: &str, id: &str) -> Result<Role, GatewayError> {
        let client = self.session_client(session_token)?;
        let response = client
            .lock()
            .await?
            .call(get_role(&parse_entity_id(id)?))
            .await
            .map_err(map_gvm_error)?;
        let parsed = GetRolesResponse::from_response(&response).map_err(map_parse_error)?;
        let role = parsed
            .items
            .into_iter()
            .next()
            .ok_or_else(|| GatewayError::NotFound(format!("role {id} not found")))?;
        Ok(role_from_gmp(role))
    }

    async fn modify_role(
        &self,
        session_token: &str,
        id: &str,
        input: ModifyRoleInput,
    ) -> Result<Role, GatewayError> {
        let client = self.session_client(session_token)?;
        let response = client
            .lock()
            .await?
            .call(modify_role(
                &parse_entity_id(id)?,
                RoleOpts {
                    comment: input.comment,
                    users: input.users.unwrap_or_default(),
                },
            ))
            .await
            .map_err(map_gvm_error)?;
        let _ = ActionResponse::from_response(&response).map_err(map_parse_error)?;
        self.get_role(session_token, id).await
    }

    async fn delete_role(
        &self,
        session_token: &str,
        id: &str,
        ultimate: bool,
    ) -> Result<(), GatewayError> {
        let client = self.session_client(session_token)?;
        let response = client
            .lock()
            .await?
            .call(delete_role(&parse_entity_id(id)?, ultimate))
            .await
            .map_err(map_gvm_error)?;
        let _ = ActionResponse::from_response(&response).map_err(map_parse_error)?;
        Ok(())
    }

    async fn list_permissions(
        &self,
        session_token: &str,
        query: &IdentityQuery,
    ) -> Result<PermissionPage, GatewayError> {
        let client = self.session_client(session_token)?;
        let filter_id = query
            .filter_id
            .as_deref()
            .map(parse_entity_id)
            .transpose()?;
        let filter_string = self
            .paginated_filter_resolving_filter_id(
                session_token,
                None,
                query.filter_string.as_deref(),
                filter_id.as_ref(),
                query.page,
                query.per_page,
                &[],
            )
            .await?;
        let response = client
            .lock()
            .await?
            .call(get_permissions(GetPermissionsOpts {
                filter_string,
                filter_id: None,
                trash: None,
                details: Some(true),
            }))
            .await
            .map_err(map_gvm_error)?;
        let parsed = GetPermissionsResponse::from_response(&response).map_err(map_parse_error)?;
        let items = parsed
            .items
            .into_iter()
            .map(permission_from_gmp)
            .collect::<Vec<_>>();
        let total = gvmd_total(parsed.counts.filtered, parsed.counts.total, items.len());

        Ok(PermissionPage {
            data: items,
            pagination: paged_pagination(total, query.page, query.per_page),
        })
    }

    async fn create_permission(
        &self,
        session_token: &str,
        input: CreatePermissionInput,
    ) -> Result<String, GatewayError> {
        let client = self.session_client(session_token)?;
        let response = client
            .lock()
            .await?
            .call(create_permission(PermissionOpts {
                comment: input.comment,
                name: input.name,
                resource_id: input
                    .resource_id
                    .as_deref()
                    .map(parse_entity_id)
                    .transpose()?,
                resource_type: input.resource_type,
                subject_type: input
                    .subject_type
                    .as_deref()
                    .map(parse_permission_subject_type)
                    .transpose()?,
                subject_id: input
                    .subject_id
                    .as_deref()
                    .map(parse_entity_id)
                    .transpose()?,
            }))
            .await
            .map_err(map_gvm_error)?;
        let parsed = CreatePermissionResponse::from_response(&response).map_err(map_parse_error)?;
        Ok(parsed.id.to_string())
    }

    async fn get_permission(
        &self,
        session_token: &str,
        id: &str,
    ) -> Result<Permission, GatewayError> {
        let client = self.session_client(session_token)?;
        let response = client
            .lock()
            .await?
            .call(get_permission(&parse_entity_id(id)?))
            .await
            .map_err(map_gvm_error)?;
        let parsed = GetPermissionsResponse::from_response(&response).map_err(map_parse_error)?;
        let permission = parsed
            .items
            .into_iter()
            .next()
            .ok_or_else(|| GatewayError::NotFound(format!("permission {id} not found")))?;
        Ok(permission_from_gmp(permission))
    }

    async fn modify_permission(
        &self,
        session_token: &str,
        id: &str,
        input: ModifyPermissionInput,
    ) -> Result<Permission, GatewayError> {
        let client = self.session_client(session_token)?;
        let response = client
            .lock()
            .await?
            .call(modify_permission(
                &parse_entity_id(id)?,
                PermissionOpts {
                    comment: input.comment,
                    name: input.name,
                    resource_id: input
                        .resource_id
                        .as_deref()
                        .map(parse_entity_id)
                        .transpose()?,
                    resource_type: input.resource_type,
                    subject_type: input
                        .subject_type
                        .as_deref()
                        .map(parse_permission_subject_type)
                        .transpose()?,
                    subject_id: input
                        .subject_id
                        .as_deref()
                        .map(parse_entity_id)
                        .transpose()?,
                },
            ))
            .await
            .map_err(map_gvm_error)?;
        let _ = ActionResponse::from_response(&response).map_err(map_parse_error)?;
        self.get_permission(session_token, id).await
    }

    async fn delete_permission(
        &self,
        session_token: &str,
        id: &str,
        ultimate: bool,
    ) -> Result<(), GatewayError> {
        let client = self.session_client(session_token)?;
        let response = client
            .lock()
            .await?
            .call(delete_permission(&parse_entity_id(id)?, ultimate))
            .await
            .map_err(map_gvm_error)?;
        let _ = ActionResponse::from_response(&response).map_err(map_parse_error)?;
        Ok(())
    }

    async fn list_user_settings(
        &self,
        session_token: &str,
        query: &UserSettingQuery,
    ) -> Result<UserSettingList, GatewayError> {
        let client = self.session_client(session_token)?;
        let filter_id = query
            .filter_id
            .as_deref()
            .map(parse_entity_id)
            .transpose()?;
        let filter = self
            .filter_resolving_filter_id(
                session_token,
                None,
                query.filter_string.as_deref(),
                filter_id.as_ref(),
                &[],
            )
            .await?;
        let response = client
            .lock()
            .await?
            .call(get_user_settings(GetUserSettingsOpts {
                filter,
                filter_id: None,
            }))
            .await
            .map_err(map_gvm_error)?;
        let parsed = GetUserSettingsResponse::from_response(&response).map_err(map_parse_error)?;
        let mut items = parsed
            .settings
            .into_iter()
            .map(user_setting_from_gmp)
            .collect::<Vec<_>>();
        items.sort_by(|left, right| left.name.cmp(&right.name));

        Ok(UserSettingList { data: items })
    }

    async fn get_user_setting(
        &self,
        session_token: &str,
        id: &str,
    ) -> Result<UserSetting, GatewayError> {
        let client = self.session_client(session_token)?;
        let response = client
            .lock()
            .await?
            .call(get_user_setting(&parse_entity_id(id)?))
            .await
            .map_err(map_gvm_error)?;
        let parsed = GetUserSettingsResponse::from_response(&response).map_err(map_parse_error)?;
        parsed
            .settings
            .into_iter()
            .next()
            .map(user_setting_from_gmp)
            .ok_or_else(|| GatewayError::NotFound(format!("user setting {id} not found")))
    }

    async fn modify_user_setting(
        &self,
        session_token: &str,
        id: &str,
        input: ModifyUserSettingInput,
    ) -> Result<UserSetting, GatewayError> {
        let client = self.session_client(session_token)?;
        let response = client
            .lock()
            .await?
            .call(modify_user_setting(
                &parse_entity_id(id)?,
                ModifyUserSettingOpts { value: input.value },
            ))
            .await
            .map_err(map_gvm_error)?;
        let _ = ModifyUserSettingResponse::from_response(&response).map_err(map_parse_error)?;
        self.get_user_setting(session_token, id).await
    }
}
