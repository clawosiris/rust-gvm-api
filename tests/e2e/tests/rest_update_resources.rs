// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Greenbone AG

use anyhow::{Context, Result};
use gvm_gateway_e2e::harness::{E2eHarness, PortList, SessionResponse, Timezone};

const SCHEDULE_ICALENDAR: &str = "BEGIN:VCALENDAR\n\
VERSION:2.0\n\
PRODID:-//Greenbone//rust-gvm-api e2e//EN\n\
BEGIN:VEVENT\n\
DTSTART:20300101T000000Z\n\
DURATION:PT1H\n\
RRULE:FREQ=DAILY;COUNT=1\n\
END:VEVENT\n\
END:VCALENDAR";

// Covers representative PUT contracts against a live backend so mutable REST
// resources prove id-stable updates instead of only create/read/delete flows.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires a compose-backed gvmd environment"]
async fn rest_update_resource_lifecycles_preserve_ids_and_changed_fields() -> Result<()> {
    let (harness, session) = ready_session().await?;
    let mut target_id = None;
    let mut port_list_id = None;
    let mut schedule_id = None;

    let run = async {
        let existing_port_list = select_port_list(&harness, &session.token).await?;
        let target_name = harness.unique_name("nightly-update-target");
        let target = harness
            .create_target(&session.token, &target_name, &existing_port_list.id)
            .await?;
        target_id = Some(target.id.clone());

        let updated_target_name = harness.unique_name("nightly-updated-target");
        let updated_target = harness
            .update_target_name(&session.token, &target.id, &updated_target_name)
            .await?;
        assert_eq!(
            updated_target.id, target.id,
            "target id changed after update"
        );
        assert_eq!(
            updated_target.name, updated_target_name,
            "target update response did not expose changed name"
        );
        let fetched_target = harness.get_target(&session.token, &target.id).await?;
        assert_eq!(
            fetched_target.name, updated_target_name,
            "target read after update did not preserve changed name"
        );

        let port_list_name = harness.unique_name("nightly-update-port-list");
        let created_port_list = harness
            .create_port_list(&session.token, &port_list_name, "T:2")
            .await?;
        port_list_id = Some(created_port_list.id.clone());
        let updated_port_list_comment = "updated by compose-backed E2E PUT coverage";
        let updated_port_list = harness
            .update_port_list_comment(
                &session.token,
                &created_port_list.id,
                updated_port_list_comment,
            )
            .await?;
        assert_eq!(
            updated_port_list.id, created_port_list.id,
            "port-list id changed after update"
        );
        assert_eq!(
            updated_port_list.comment.as_deref(),
            Some(updated_port_list_comment),
            "port-list update response did not expose changed comment"
        );
        let fetched_port_list = harness
            .get_port_list(&session.token, &created_port_list.id)
            .await?;
        assert_eq!(
            fetched_port_list.comment.as_deref(),
            Some(updated_port_list_comment),
            "port-list read after update did not preserve changed comment"
        );

        let timezones = harness.list_timezones(&session.token).await?;
        let timezone = select_schedule_timezone(&timezones)?;
        let schedule_name = harness.unique_name("nightly-update-schedule");
        let created_schedule = harness
            .create_schedule(
                &session.token,
                &schedule_name,
                SCHEDULE_ICALENDAR,
                &timezone.name,
            )
            .await?;
        schedule_id = Some(created_schedule.id.clone());
        let updated_schedule_name = harness.unique_name("nightly-updated-schedule");
        let updated_schedule_comment = "updated by compose-backed E2E PUT coverage";
        let updated_schedule = harness
            .update_schedule(
                &session.token,
                &created_schedule.id,
                &updated_schedule_name,
                updated_schedule_comment,
                SCHEDULE_ICALENDAR,
                &timezone.name,
            )
            .await?;
        assert_eq!(
            updated_schedule.id, created_schedule.id,
            "schedule id changed after update"
        );
        assert_eq!(
            updated_schedule.name, updated_schedule_name,
            "schedule update response did not expose changed name"
        );
        assert_eq!(
            updated_schedule.comment.as_deref(),
            Some(updated_schedule_comment),
            "schedule update response did not expose changed comment"
        );
        let fetched_schedule = harness
            .get_schedule(&session.token, &created_schedule.id)
            .await?;
        assert_eq!(
            fetched_schedule.name, updated_schedule_name,
            "schedule read after update did not preserve changed name"
        );

        harness
            .delete_schedule(&session.token, &created_schedule.id)
            .await?;
        schedule_id = None;
        harness
            .delete_port_list(&session.token, &created_port_list.id)
            .await?;
        port_list_id = None;
        harness.delete_target(&session.token, &target.id).await?;
        target_id = None;

        Ok(())
    }
    .await;

    if run.is_err() {
        best_effort_cleanup(
            &harness,
            &session.token,
            schedule_id.as_deref(),
            port_list_id.as_deref(),
            target_id.as_deref(),
        )
        .await;
    }
    finish_session(&harness, &session, run).await
}

async fn ready_session() -> Result<(E2eHarness, SessionResponse)> {
    let harness = E2eHarness::from_env()?;
    harness.wait_until_ready().await?;
    let session = harness.create_session().await?;
    Ok((harness, session))
}

async fn finish_session(
    harness: &E2eHarness,
    session: &SessionResponse,
    run: Result<()>,
) -> Result<()> {
    if let Err(error) = harness.delete_session(&session.token).await {
        eprintln!("best-effort session cleanup failed: {error:#}");
    }
    run
}

async fn select_port_list(harness: &E2eHarness, token: &str) -> Result<PortList> {
    let port_lists = harness.list_port_lists(token).await?;
    Ok(harness.select_port_list(&port_lists)?.clone())
}

fn select_schedule_timezone(timezones: &[Timezone]) -> Result<&Timezone> {
    timezones
        .iter()
        .find(|timezone| timezone.name == "Europe/Berlin")
        .or_else(|| {
            timezones
                .iter()
                .find(|timezone| !timezone.name.trim().is_empty())
        })
        .with_context(|| "timezone catalog did not return a usable timezone".to_string())
}

async fn best_effort_cleanup(
    harness: &E2eHarness,
    token: &str,
    schedule_id: Option<&str>,
    port_list_id: Option<&str>,
    target_id: Option<&str>,
) {
    if let Some(schedule_id) = schedule_id {
        if let Err(error) = harness.delete_schedule(token, schedule_id).await {
            eprintln!("best-effort schedule cleanup failed for {schedule_id}: {error:#}");
        }
    }
    if let Some(port_list_id) = port_list_id {
        if let Err(error) = harness.delete_port_list(token, port_list_id).await {
            eprintln!("best-effort port-list cleanup failed for {port_list_id}: {error:#}");
        }
    }
    if let Some(target_id) = target_id {
        if let Err(error) = harness.delete_target(token, target_id).await {
            eprintln!("best-effort target cleanup failed for {target_id}: {error:#}");
        }
    }
}
