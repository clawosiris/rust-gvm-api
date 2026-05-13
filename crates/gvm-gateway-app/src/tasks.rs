// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Greenbone AG

//! Task use cases.

use gvm_gateway_domain::{
    CreateTaskInput, GatewayError, ModifyTaskInput, Task, TaskAction, TaskPage, TaskQuery,
};

use crate::GatewayService;

impl GatewayService {
    /// Lists tasks for an authenticated session.
    pub async fn list_tasks(
        &self,
        session_token: &str,
        query: TaskQuery,
    ) -> Result<TaskPage, GatewayError> {
        self.execute_with_resource(
            "tasks.list",
            session_token,
            "list",
            "task",
            None,
            |session| async move { self.tasks.list_tasks(&session.token, &query).await },
        )
        .await
    }

    /// Creates a new task for an authenticated session.
    pub async fn create_task(
        &self,
        session_token: &str,
        input: CreateTaskInput,
    ) -> Result<String, GatewayError> {
        self.execute_with_resource(
            "tasks.create",
            session_token,
            "create",
            "task",
            None,
            |session| async move { self.tasks.create_task(&session.token, input).await },
        )
        .await
    }

    /// Fetches a task for an authenticated session.
    pub async fn get_task(&self, session_token: &str, id: &str) -> Result<Task, GatewayError> {
        self.execute_with_resource(
            "tasks.get",
            session_token,
            "read",
            "task",
            Some(id),
            |session| async move { self.tasks.get_task(&session.token, id).await },
        )
        .await
    }

    /// Modifies a task for an authenticated session.
    pub async fn modify_task(
        &self,
        session_token: &str,
        id: &str,
        input: ModifyTaskInput,
    ) -> Result<Task, GatewayError> {
        self.execute_with_resource(
            "tasks.modify",
            session_token,
            "modify",
            "task",
            Some(id),
            |session| async move { self.tasks.modify_task(&session.token, id, input).await },
        )
        .await
    }

    /// Deletes a task for an authenticated session.
    pub async fn delete_task(&self, session_token: &str, id: &str) -> Result<(), GatewayError> {
        self.execute_with_resource(
            "tasks.delete",
            session_token,
            "delete",
            "task",
            Some(id),
            |session| async move { self.tasks.delete_task(&session.token, id).await },
        )
        .await
    }

    /// Starts a task for an authenticated session.
    pub async fn start_task(
        &self,
        session_token: &str,
        id: &str,
    ) -> Result<TaskAction, GatewayError> {
        self.execute_with_resource(
            "tasks.start",
            session_token,
            "start",
            "task",
            Some(id),
            |session| async move { self.tasks.start_task(&session.token, id).await },
        )
        .await
    }

    /// Stops a running task for an authenticated session.
    pub async fn stop_task(&self, session_token: &str, id: &str) -> Result<(), GatewayError> {
        self.execute_with_resource(
            "tasks.stop",
            session_token,
            "stop",
            "task",
            Some(id),
            |session| async move { self.tasks.stop_task(&session.token, id).await },
        )
        .await
    }

    /// Resumes a stopped task for an authenticated session.
    pub async fn resume_task(
        &self,
        session_token: &str,
        id: &str,
    ) -> Result<TaskAction, GatewayError> {
        self.execute_with_resource(
            "tasks.resume",
            session_token,
            "resume",
            "task",
            Some(id),
            |session| async move { self.tasks.resume_task(&session.token, id).await },
        )
        .await
    }
}
