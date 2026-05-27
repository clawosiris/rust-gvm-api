// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Greenbone AG

//! Schedule use cases.

use gvm_gateway_domain::{
    CreateScheduleInput, GatewayError, ModifyScheduleInput, Schedule, SchedulePage, ScheduleQuery,
};

use crate::GatewayService;

impl GatewayService {
    /// Lists supported schedule timezones for an authenticated session.
    pub async fn list_timezones(
        &self,
        session_token: &str,
    ) -> Result<Vec<gvm_gateway_domain::Timezone>, GatewayError> {
        self.execute_with_resource(
            "schedules.timezones.list",
            session_token,
            "list",
            "schedule_timezone",
            None,
            |session| async move { self.schedules.list_timezones(&session.token).await },
        )
        .await
    }

    /// Lists schedules for an authenticated session.
    pub async fn list_schedules(
        &self,
        session_token: &str,
        query: ScheduleQuery,
    ) -> Result<SchedulePage, GatewayError> {
        self.execute_with_resource(
            "schedules.list",
            session_token,
            "list",
            "schedule",
            None,
            |session| async move { self.schedules.list_schedules(&session.token, &query).await },
        )
        .await
    }

    /// Creates a new schedule for an authenticated session.
    pub async fn create_schedule(
        &self,
        session_token: &str,
        input: CreateScheduleInput,
    ) -> Result<String, GatewayError> {
        self.execute_with_resource(
            "schedules.create",
            session_token,
            "create",
            "schedule",
            None,
            |session| async move { self.schedules.create_schedule(&session.token, input).await },
        )
        .await
    }

    /// Fetches a schedule for an authenticated session.
    pub async fn get_schedule(
        &self,
        session_token: &str,
        id: &str,
    ) -> Result<Schedule, GatewayError> {
        self.execute_with_resource(
            "schedules.get",
            session_token,
            "read",
            "schedule",
            Some(id),
            |session| async move { self.schedules.get_schedule(&session.token, id).await },
        )
        .await
    }

    /// Modifies a schedule for an authenticated session.
    pub async fn modify_schedule(
        &self,
        session_token: &str,
        id: &str,
        input: ModifyScheduleInput,
    ) -> Result<Schedule, GatewayError> {
        self.execute_with_resource(
            "schedules.modify",
            session_token,
            "modify",
            "schedule",
            Some(id),
            |session| async move {
                self.schedules
                    .modify_schedule(&session.token, id, input)
                    .await
            },
        )
        .await
    }

    /// Deletes a schedule for an authenticated session.
    pub async fn delete_schedule(&self, session_token: &str, id: &str) -> Result<(), GatewayError> {
        self.execute_with_resource(
            "schedules.delete",
            session_token,
            "delete",
            "schedule",
            Some(id),
            |session| async move { self.schedules.delete_schedule(&session.token, id).await },
        )
        .await
    }
}
