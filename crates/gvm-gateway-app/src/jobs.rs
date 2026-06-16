// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Greenbone AG

//! Asynchronous job use cases.

use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use gvm_gateway_domain::{
    CreateReportExportRequest, GatewayError, GetReportOpts, JobArtifact, JobCancelOutcome,
    JobProblem, JobProgress, JobResult, JobStatus, ReportExportFormat, ReportExportJob,
    ReportExportRequest, ReportJsonExport, ResourceRef, ResultQuery, Session, SessionHold,
    SessionTokenDigest,
};
use tokio::task::{AbortHandle, JoinHandle};
use uuid::Uuid;

use crate::GatewayService;

const JOB_KIND_REPORT_EXPORT: &str = "report_export";
const JSON_EXPORT_PAGE_SIZE: u32 = 1000;
const DEFAULT_MAX_JOBS_TOTAL: usize = 1000;
const DEFAULT_TERMINAL_JOB_RETENTION_SECS: u64 = 15 * 60;
const DEFAULT_JOB_REAPER_INTERVAL_SECS: u64 = 60;

pub(crate) struct JobRegistry {
    state: Mutex<JobRegistryState>,
}

struct JobRegistryState {
    jobs: HashMap<String, JobRecord>,
    policy: JobPolicy,
}

#[derive(Clone, Copy)]
struct JobPolicy {
    max_jobs_total: usize,
    terminal_retention_secs: u64,
}

#[derive(Clone)]
struct JobRecord {
    owner_user: String,
    session_token_digest: SessionTokenDigest,
    job: ReportExportJob,
    artifact: Option<JobArtifact>,
    abort_handle: Option<AbortHandle>,
    purge_after_epoch_secs: Option<u64>,
}

impl Default for JobRegistry {
    fn default() -> Self {
        Self {
            state: Mutex::new(JobRegistryState {
                jobs: HashMap::new(),
                policy: JobPolicy::default(),
            }),
        }
    }
}

impl Default for JobPolicy {
    fn default() -> Self {
        Self {
            max_jobs_total: DEFAULT_MAX_JOBS_TOTAL,
            terminal_retention_secs: DEFAULT_TERMINAL_JOB_RETENTION_SECS,
        }
    }
}

impl GatewayService {
    /// Creates a background reaper for expired asynchronous jobs.
    pub fn job_reaper(&self) -> JobReaper {
        JobReaper::new(Arc::clone(&self.jobs))
    }

    /// Starts an asynchronous report export job.
    pub async fn create_report_export_job(
        &self,
        session_token: &str,
        report_id: &str,
        request: CreateReportExportRequest,
    ) -> Result<ReportExportJob, GatewayError> {
        let report_id = report_id.to_string();
        let audit_report_id = report_id.clone();
        let service = self.clone();
        self.execute_with_resource(
            "reports.exports.create",
            session_token,
            "create",
            "report_export",
            Some(&audit_report_id),
            move |session| async move {
                service
                    .enqueue_report_export_job(session, report_id, request)
                    .await
            },
        )
        .await
    }

    /// Gets the status of an asynchronous job.
    pub async fn get_job(
        &self,
        session_token: &str,
        job_id: &str,
    ) -> Result<ReportExportJob, GatewayError> {
        let job_id = job_id.to_string();
        let audit_job_id = job_id.clone();
        let service = self.clone();
        self.execute_with_resource(
            "jobs.get",
            session_token,
            "read",
            "job",
            Some(&audit_job_id),
            move |session| async move { service.job_snapshot(&session.user, &job_id) },
        )
        .await
    }

    /// Requests cancellation of an asynchronous job.
    pub async fn cancel_job(
        &self,
        session_token: &str,
        job_id: &str,
    ) -> Result<JobCancelOutcome, GatewayError> {
        let job_id = job_id.to_string();
        let audit_job_id = job_id.clone();
        let service = self.clone();
        self.execute_with_resource(
            "jobs.cancel",
            session_token,
            "cancel",
            "job",
            Some(&audit_job_id),
            move |session| async move { service.cancel_job_record(&session.user, &job_id) },
        )
        .await
    }

    /// Downloads a completed asynchronous job result.
    pub async fn download_job_result(
        &self,
        session_token: &str,
        job_id: &str,
    ) -> Result<JobArtifact, GatewayError> {
        let job_id = job_id.to_string();
        let audit_job_id = job_id.clone();
        let service = self.clone();
        self.execute_with_resource(
            "jobs.result.download",
            session_token,
            "read",
            "job_result",
            Some(&audit_job_id),
            move |session| async move { service.job_artifact(&session.user, &job_id) },
        )
        .await
    }

    async fn enqueue_report_export_job(
        &self,
        session: Session,
        report_id: String,
        request: CreateReportExportRequest,
    ) -> Result<ReportExportJob, GatewayError> {
        self.reports
            .get_report(
                &session.token,
                &report_id,
                &GetReportOpts {
                    page: 1,
                    per_page: 1,
                },
            )
            .await?;

        let job_id = Uuid::new_v4().to_string();
        let job = report_export_job(&job_id, &report_id, &request);
        let session_hold = self.sessions.hold(&session.token)?;
        let session_token_digest = SessionTokenDigest::from_token(&session.token);
        self.insert_job(session.user, session_token_digest, job.clone())?;

        let worker = self.clone();
        let worker_job_id = job_id.clone();
        let worker_report_id = report_id.clone();
        let worker_request = request.clone();
        let session_token = session.token;
        let handle = tokio::spawn(async move {
            worker
                .run_report_export_job(
                    worker_job_id,
                    session_token,
                    session_hold,
                    worker_report_id,
                    worker_request,
                )
                .await;
        });
        self.set_job_abort_handle(&job_id, handle.abort_handle())?;

        Ok(job)
    }

    async fn run_report_export_job(
        &self,
        job_id: String,
        session_token: String,
        _session_hold: SessionHold,
        report_id: String,
        request: CreateReportExportRequest,
    ) {
        if self.mark_job_running(&job_id).is_err() {
            return;
        }

        let result = match request {
            CreateReportExportRequest::GvmdReportFormat(request) => {
                let request = ReportExportRequest {
                    report_format_id: request.report_format_id,
                    report_config_id: request.report_config_id,
                    filter: request.filter,
                    filter_id: request.filter_id,
                };
                self.reports
                    .export_report(&session_token, &report_id, &request)
                    .await
                    .map(|export| {
                        let extension = export.extension.unwrap_or_else(|| "bin".to_string());
                        JobArtifact {
                            bytes: export.bytes,
                            content_type: export
                                .content_type
                                .unwrap_or_else(|| "application/octet-stream".to_string()),
                            filename: format!("report-{report_id}.{extension}"),
                        }
                    })
            }
            CreateReportExportRequest::Json(request) => {
                self.export_report_json(
                    &session_token,
                    &report_id,
                    request.filter,
                    request.filter_id,
                )
                .await
            }
        };

        match result {
            Ok(artifact) => {
                let _ = self.mark_job_succeeded(&job_id, artifact);
            }
            Err(error) => {
                let _ = self.mark_job_failed(&job_id, error);
            }
        }
    }

    async fn export_report_json(
        &self,
        session_token: &str,
        report_id: &str,
        filter_string: Option<String>,
        filter_id: Option<String>,
    ) -> Result<JobArtifact, GatewayError> {
        let mut report = self
            .reports
            .get_report(
                session_token,
                report_id,
                &GetReportOpts {
                    page: 1,
                    per_page: 1,
                },
            )
            .await?;
        report.results.clear();

        let mut page = 1;
        let mut results = Vec::new();
        loop {
            let result_page = self
                .reports
                .get_report_results(
                    session_token,
                    report_id,
                    &ResultQuery {
                        filter_string: filter_string.clone(),
                        filter_id: filter_id.clone(),
                        page,
                        per_page: JSON_EXPORT_PAGE_SIZE,
                    },
                )
                .await?;

            let total_pages = result_page.pagination.total_pages;
            let item_count = result_page.data.len();
            results.extend(result_page.data);

            if item_count == 0 || page >= total_pages {
                break;
            }
            page += 1;
        }

        let export = ReportJsonExport {
            report,
            results,
            generated_at: Some(now_rfc3339()),
        };
        let bytes = serde_json::to_vec(&export).map_err(|err| {
            GatewayError::Internal(format!("failed to serialize JSON report export: {err}"))
        })?;

        Ok(JobArtifact {
            bytes,
            content_type: "application/json".to_string(),
            filename: format!("report-{report_id}.json"),
        })
    }

    fn insert_job(
        &self,
        owner_user: String,
        session_token_digest: SessionTokenDigest,
        job: ReportExportJob,
    ) -> Result<(), GatewayError> {
        let mut state = self
            .jobs
            .state
            .lock()
            .map_err(|_| GatewayError::Internal("job registry lock poisoned".to_string()))?;
        let now = now_epoch_secs();
        purge_expired_jobs(&mut state, now);
        if state.jobs.len() >= state.policy.max_jobs_total {
            return Err(GatewayError::TooManyRequests(format!(
                "job capacity exceeded; at most {} jobs are retained",
                state.policy.max_jobs_total
            )));
        }
        state.jobs.insert(
            job.id.clone(),
            JobRecord {
                owner_user,
                session_token_digest,
                job,
                artifact: None,
                abort_handle: None,
                purge_after_epoch_secs: None,
            },
        );
        Ok(())
    }

    fn set_job_abort_handle(
        &self,
        job_id: &str,
        abort_handle: AbortHandle,
    ) -> Result<(), GatewayError> {
        let mut state = self
            .jobs
            .state
            .lock()
            .map_err(|_| GatewayError::Internal("job registry lock poisoned".to_string()))?;
        let record = state
            .jobs
            .get_mut(job_id)
            .ok_or_else(|| GatewayError::NotFound(format!("job {job_id} not found")))?;
        if record.job.status.is_terminal() {
            abort_handle.abort();
            return Ok(());
        }
        record.abort_handle = Some(abort_handle);
        Ok(())
    }

    fn mark_job_running(&self, job_id: &str) -> Result<(), GatewayError> {
        let mut state = self
            .jobs
            .state
            .lock()
            .map_err(|_| GatewayError::Internal("job registry lock poisoned".to_string()))?;
        let record = state
            .jobs
            .get_mut(job_id)
            .ok_or_else(|| GatewayError::NotFound(format!("job {job_id} not found")))?;
        if record.job.status == JobStatus::Cancelled {
            return Err(GatewayError::Conflict(format!(
                "job {job_id} was cancelled"
            )));
        }
        record.job.status = JobStatus::Running;
        record.job.started_at = Some(now_rfc3339());
        record.job.progress = Some(JobProgress {
            percent: Some(0),
            message: Some("running".to_string()),
        });
        Ok(())
    }

    fn mark_job_succeeded(&self, job_id: &str, artifact: JobArtifact) -> Result<(), GatewayError> {
        let mut state = self
            .jobs
            .state
            .lock()
            .map_err(|_| GatewayError::Internal("job registry lock poisoned".to_string()))?;
        let now = now_epoch_secs();
        let retention_secs = state.policy.terminal_retention_secs;
        let record = state
            .jobs
            .get_mut(job_id)
            .ok_or_else(|| GatewayError::NotFound(format!("job {job_id} not found")))?;
        if record.job.status == JobStatus::Cancelled {
            return Ok(());
        }
        let result_location = format!("/api/v1/jobs/{job_id}/result");
        record.job.status = JobStatus::Succeeded;
        record.job.completed_at = Some(format_epoch_secs(now));
        record.job.expires_at = Some(format_epoch_secs(now + retention_secs));
        record.job.result_location = Some(result_location.clone());
        record.job.progress = Some(JobProgress {
            percent: Some(100),
            message: Some("succeeded".to_string()),
        });
        record.job.result = Some(JobResult {
            content_type: Some(artifact.content_type.clone()),
            filename: Some(artifact.filename.clone()),
            size: Some(artifact.bytes.len() as u64),
            location: Some(result_location),
        });
        record.artifact = Some(artifact);
        record.abort_handle = None;
        record.purge_after_epoch_secs = Some(now + retention_secs);
        Ok(())
    }

    fn mark_job_failed(&self, job_id: &str, error: GatewayError) -> Result<(), GatewayError> {
        let mut state = self
            .jobs
            .state
            .lock()
            .map_err(|_| GatewayError::Internal("job registry lock poisoned".to_string()))?;
        let now = now_epoch_secs();
        let retention_secs = state.policy.terminal_retention_secs;
        let record = state
            .jobs
            .get_mut(job_id)
            .ok_or_else(|| GatewayError::NotFound(format!("job {job_id} not found")))?;
        if record.job.status == JobStatus::Cancelled {
            return Ok(());
        }
        record.job.status = JobStatus::Failed;
        record.job.completed_at = Some(format_epoch_secs(now));
        record.job.expires_at = Some(format_epoch_secs(now + retention_secs));
        record.job.progress = Some(JobProgress {
            percent: Some(100),
            message: Some("failed".to_string()),
        });
        record.job.error = Some(JobProblem::from_gateway_error(&error));
        record.abort_handle = None;
        record.purge_after_epoch_secs = Some(now + retention_secs);
        Ok(())
    }

    fn job_snapshot(
        &self,
        owner_user: &str,
        job_id: &str,
    ) -> Result<ReportExportJob, GatewayError> {
        let mut state = self
            .jobs
            .state
            .lock()
            .map_err(|_| GatewayError::Internal("job registry lock poisoned".to_string()))?;
        purge_expired_jobs(&mut state, now_epoch_secs());
        let record = state
            .jobs
            .get(job_id)
            .ok_or_else(|| GatewayError::NotFound(format!("job {job_id} not found")))?;
        ensure_job_owner(record, owner_user, job_id)?;
        Ok(record.job.clone())
    }

    fn cancel_job_record(
        &self,
        owner_user: &str,
        job_id: &str,
    ) -> Result<JobCancelOutcome, GatewayError> {
        let mut state = self
            .jobs
            .state
            .lock()
            .map_err(|_| GatewayError::Internal("job registry lock poisoned".to_string()))?;
        purge_expired_jobs(&mut state, now_epoch_secs());
        let now = now_epoch_secs();
        let retention_secs = state.policy.terminal_retention_secs;
        let record = state
            .jobs
            .get_mut(job_id)
            .ok_or_else(|| GatewayError::NotFound(format!("job {job_id} not found")))?;
        ensure_job_owner(record, owner_user, job_id)?;

        if record.job.status.is_terminal() {
            return Ok(JobCancelOutcome::AlreadyTerminal);
        }

        record.job.status = JobStatus::Cancelled;
        record.job.completed_at = Some(format_epoch_secs(now));
        record.job.expires_at = Some(format_epoch_secs(now + retention_secs));
        record.job.progress = Some(JobProgress {
            percent: Some(100),
            message: Some("cancelled".to_string()),
        });
        if let Some(handle) = record.abort_handle.take() {
            handle.abort();
        }
        record.purge_after_epoch_secs = Some(now + retention_secs);

        Ok(JobCancelOutcome::CancellationRequested)
    }

    pub(crate) fn cancel_jobs_for_session(
        &self,
        session_token_digest: &SessionTokenDigest,
    ) -> Result<usize, GatewayError> {
        let mut state = self
            .jobs
            .state
            .lock()
            .map_err(|_| GatewayError::Internal("job registry lock poisoned".to_string()))?;
        purge_expired_jobs(&mut state, now_epoch_secs());
        let now = now_epoch_secs();
        let retention_secs = state.policy.terminal_retention_secs;
        let mut abort_handles = Vec::new();
        let mut cancelled = 0;

        for record in state.jobs.values_mut() {
            if record.session_token_digest != *session_token_digest
                || record.job.status.is_terminal()
            {
                continue;
            }
            if let Some(handle) = cancel_job_record_in_place(record, now, retention_secs) {
                abort_handles.push(handle);
            }
            cancelled += 1;
        }

        drop(state);
        for handle in abort_handles {
            handle.abort();
        }

        Ok(cancelled)
    }

    fn job_artifact(&self, owner_user: &str, job_id: &str) -> Result<JobArtifact, GatewayError> {
        let mut state = self
            .jobs
            .state
            .lock()
            .map_err(|_| GatewayError::Internal("job registry lock poisoned".to_string()))?;
        purge_expired_jobs(&mut state, now_epoch_secs());
        let record = state
            .jobs
            .get(job_id)
            .ok_or_else(|| GatewayError::NotFound(format!("job {job_id} not found")))?;
        ensure_job_owner(record, owner_user, job_id)?;

        if record.job.status != JobStatus::Succeeded {
            return Err(GatewayError::Conflict(format!(
                "job {job_id} has not produced a downloadable result"
            )));
        }

        record
            .artifact
            .clone()
            .ok_or_else(|| GatewayError::Internal(format!("job {job_id} artifact is missing")))
    }

    #[cfg(test)]
    pub(crate) fn set_job_policy_for_tests(
        &self,
        max_jobs_total: usize,
        terminal_retention_secs: u64,
    ) {
        let mut state = self.jobs.state.lock().unwrap();
        state.policy = JobPolicy {
            max_jobs_total,
            terminal_retention_secs,
        };
    }

    #[cfg(test)]
    pub(crate) fn retained_job_count_for_tests(&self) -> usize {
        self.jobs.state.lock().unwrap().jobs.len()
    }

    #[cfg(test)]
    pub(crate) fn attach_abort_handle_for_tests(
        &self,
        job_id: &str,
        abort_handle: AbortHandle,
    ) -> Result<(), GatewayError> {
        self.set_job_abort_handle(job_id, abort_handle)
    }

    #[cfg(test)]
    pub(crate) fn job_has_abort_handle_for_tests(&self, job_id: &str) -> bool {
        self.jobs
            .state
            .lock()
            .unwrap()
            .jobs
            .get(job_id)
            .and_then(|record| record.abort_handle.as_ref())
            .is_some()
    }
}

fn cancel_job_record_in_place(
    record: &mut JobRecord,
    now: u64,
    retention_secs: u64,
) -> Option<AbortHandle> {
    record.job.status = JobStatus::Cancelled;
    record.job.completed_at = Some(format_epoch_secs(now));
    record.job.expires_at = Some(format_epoch_secs(now + retention_secs));
    record.job.progress = Some(JobProgress {
        percent: Some(100),
        message: Some("cancelled".to_string()),
    });
    record.artifact = None;
    record.purge_after_epoch_secs = Some(now + retention_secs);
    record.abort_handle.take()
}

/// Background task that periodically removes expired asynchronous jobs.
pub struct JobReaper {
    jobs: Arc<JobRegistry>,
}

impl JobReaper {
    /// Creates a new job reaper for the given registry.
    pub(crate) fn new(jobs: Arc<JobRegistry>) -> Self {
        Self { jobs }
    }

    /// Spawns the reaper with the default sweep interval.
    pub fn spawn(&self) -> JoinHandle<()> {
        self.spawn_with_interval(Duration::from_secs(DEFAULT_JOB_REAPER_INTERVAL_SECS))
    }

    /// Spawns the reaper with an explicit sweep interval.
    pub fn spawn_with_interval(&self, interval: Duration) -> JoinHandle<()> {
        let jobs = Arc::clone(&self.jobs);
        tokio::spawn(Self::run(jobs, interval))
    }

    async fn run(jobs: Arc<JobRegistry>, interval: Duration) {
        let mut tick = tokio::time::interval(interval);
        loop {
            tick.tick().await;
            Self::sweep_once(Arc::clone(&jobs));
        }
    }

    fn sweep_once(jobs: Arc<JobRegistry>) {
        match jobs.sweep_expired_jobs() {
            Ok(0) => {}
            Ok(count) => {
                tracing::info!(count, "job reaper: removed expired jobs");
            }
            Err(err) => {
                tracing::warn!(?err, "job reaper: sweep failed");
            }
        }
    }

    #[cfg(test)]
    pub(crate) async fn sweep_once_for_test(&self) {
        Self::sweep_once(Arc::clone(&self.jobs));
    }
}

impl JobRegistry {
    fn sweep_expired_jobs(&self) -> Result<usize, GatewayError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| GatewayError::Internal("job registry lock poisoned".to_string()))?;
        Ok(purge_expired_jobs(&mut state, now_epoch_secs()))
    }
}

fn report_export_job(
    job_id: &str,
    report_id: &str,
    request: &CreateReportExportRequest,
) -> ReportExportJob {
    let (format, report_format_id) = match request {
        CreateReportExportRequest::GvmdReportFormat(request) => (
            ReportExportFormat::GvmdReportFormat,
            Some(request.report_format_id.clone()),
        ),
        CreateReportExportRequest::Json(_) => (ReportExportFormat::Json, None),
    };

    ReportExportJob {
        id: job_id.to_string(),
        kind: JOB_KIND_REPORT_EXPORT.to_string(),
        status: JobStatus::Queued,
        progress: Some(JobProgress {
            percent: Some(0),
            message: Some("queued".to_string()),
        }),
        created_at: now_rfc3339(),
        started_at: None,
        completed_at: None,
        expires_at: None,
        result_location: None,
        error: None,
        report: ResourceRef {
            id: report_id.to_string(),
            name: None,
        },
        format,
        report_format_id,
        result: None,
    }
}

fn now_rfc3339() -> String {
    format_epoch_secs(now_epoch_secs())
}

fn now_epoch_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn format_epoch_secs(epoch_secs: u64) -> String {
    gvm_gateway_domain::format_rfc3339(epoch_secs)
}

fn purge_expired_jobs(state: &mut JobRegistryState, now_epoch_secs: u64) -> usize {
    let before = state.jobs.len();
    state
        .jobs
        .retain(|_, record| match record.purge_after_epoch_secs {
            Some(purge_after) => purge_after > now_epoch_secs,
            None => true,
        });
    before - state.jobs.len()
}

fn ensure_job_owner(
    record: &JobRecord,
    owner_user: &str,
    job_id: &str,
) -> Result<(), GatewayError> {
    if record.owner_user == owner_user {
        Ok(())
    } else {
        Err(GatewayError::NotFound(format!("job {job_id} not found")))
    }
}

pub(crate) fn new_job_registry() -> Arc<JobRegistry> {
    Arc::new(JobRegistry::default())
}
