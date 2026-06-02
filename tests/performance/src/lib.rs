// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Greenbone AG

use std::{
    env, fs,
    future::Future,
    path::{Path, PathBuf},
    time::{Instant, SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result};
use serde::Serialize;

const DEFAULT_ITERATIONS: u32 = 5;
const DEFAULT_WARMUP_ITERATIONS: u32 = 1;
const DEFAULT_OUTPUT_DIR: &str = "dist/performance";

#[derive(Clone, Debug)]
pub struct PerformanceConfig {
    pub iterations: u32,
    pub warmup_iterations: u32,
    pub output_dir: PathBuf,
}

impl PerformanceConfig {
    pub fn from_env() -> Result<Self> {
        Ok(Self {
            iterations: env_u32_or_default("GVM_GATEWAY_PERF_ITERATIONS", DEFAULT_ITERATIONS)?,
            warmup_iterations: env_u32_or_default(
                "GVM_GATEWAY_PERF_WARMUP_ITERATIONS",
                DEFAULT_WARMUP_ITERATIONS,
            )?,
            output_dir: PathBuf::from(env_or_default(
                "GVM_GATEWAY_PERF_OUTPUT_DIR",
                DEFAULT_OUTPUT_DIR,
            )),
        })
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct ScenarioReport {
    pub scenario: String,
    pub category: String,
    pub measured_at_unix_secs: u64,
    pub iterations: u32,
    pub warmup_iterations: u32,
    pub unit: &'static str,
    pub samples_ms: Vec<f64>,
    pub min_ms: f64,
    pub max_ms: f64,
    pub average_ms: f64,
    pub median_ms: f64,
    pub p95_ms: f64,
    pub setup_notes: Vec<String>,
}

pub async fn measure_operation<F, Fut>(
    config: &PerformanceConfig,
    scenario: &str,
    category: &str,
    setup_notes: Vec<String>,
    mut operation: F,
) -> Result<ScenarioReport>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<()>>,
{
    for _ in 0..config.warmup_iterations {
        operation().await?;
    }

    let mut samples_ms = Vec::with_capacity(config.iterations as usize);
    for _ in 0..config.iterations {
        let started = Instant::now();
        operation().await?;
        samples_ms.push(started.elapsed().as_secs_f64() * 1_000.0);
    }

    let mut sorted_samples = samples_ms.clone();
    sorted_samples.sort_by(f64::total_cmp);

    let sum = sorted_samples.iter().sum::<f64>();
    let average_ms = sum / sorted_samples.len() as f64;
    let median_ms = percentile(&sorted_samples, 0.5);
    let p95_ms = percentile(&sorted_samples, 0.95);

    Ok(ScenarioReport {
        scenario: scenario.to_owned(),
        category: category.to_owned(),
        measured_at_unix_secs: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
        iterations: config.iterations,
        warmup_iterations: config.warmup_iterations,
        unit: "milliseconds",
        min_ms: *sorted_samples.first().unwrap_or(&0.0),
        max_ms: *sorted_samples.last().unwrap_or(&0.0),
        average_ms,
        median_ms,
        p95_ms,
        samples_ms,
        setup_notes,
    })
}

pub fn persist_report(config: &PerformanceConfig, report: &ScenarioReport) -> Result<PathBuf> {
    fs::create_dir_all(&config.output_dir).with_context(|| {
        format!(
            "create performance output directory {}",
            config.output_dir.display()
        )
    })?;

    let path = config.output_dir.join(format!("{}.json", report.scenario));
    let payload =
        serde_json::to_vec_pretty(report).context("serialize performance scenario report")?;
    fs::write(&path, payload)
        .with_context(|| format!("write performance report {}", path.display()))?;
    Ok(path)
}

pub fn log_report(report: &ScenarioReport, path: &Path) {
    eprintln!(
        "performance report {}: min={:.2}ms avg={:.2}ms median={:.2}ms p95={:.2}ms max={:.2}ms -> {}",
        report.scenario,
        report.min_ms,
        report.average_ms,
        report.median_ms,
        report.p95_ms,
        report.max_ms,
        path.display()
    );
}

fn percentile(sorted_samples: &[f64], percentile: f64) -> f64 {
    if sorted_samples.is_empty() {
        return 0.0;
    }

    let index = ((sorted_samples.len() - 1) as f64 * percentile).ceil() as usize;
    sorted_samples[index.min(sorted_samples.len() - 1)]
}

fn env_or_default(key: &str, default: &str) -> String {
    env::var(key)
        .ok()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| default.to_owned())
}

fn env_u32_or_default(key: &str, default: u32) -> Result<u32> {
    match env::var(key) {
        Ok(value) if !value.trim().is_empty() => value
            .parse::<u32>()
            .with_context(|| format!("{key} must be a positive integer")),
        _ => Ok(default),
    }
}
