// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Greenbone AG

use std::{
    fs,
    path::{Path, PathBuf},
};

#[derive(Debug, Eq, PartialEq)]
struct Finding {
    path: String,
    line: usize,
    marker: &'static str,
    text: String,
}

const FORBIDDEN_MARKERS: &[(&str, &str)] = &[
    (
        "quick_xml::",
        "raw GMP XML parsing belongs in clawosiris/rust-gvm",
    ),
    (
        "roxmltree::",
        "raw GMP XML parsing belongs in clawosiris/rust-gvm",
    ),
    (
        "xmltree::",
        "raw GMP XML parsing belongs in clawosiris/rust-gvm",
    ),
    (
        "serde_xml_rs::",
        "raw GMP XML parsing belongs in clawosiris/rust-gvm",
    ),
    (
        "Response::from(",
        "raw GMP XML response fixture parsing belongs in clawosiris/rust-gvm tests",
    ),
    (
        "XmlCommand",
        "local GMP XML command construction belongs in clawosiris/rust-gvm",
    ),
    (
        ".to_bytes()",
        "GMP command serialization assertions belong in clawosiris/rust-gvm",
    ),
    (
        "_gvmd_name",
        "GMP wire/display-name translation belongs in clawosiris/rust-gvm",
    ),
    (
        "normalize_alert_",
        "GMP response value normalization belongs in clawosiris/rust-gvm",
    ),
    (
        "same XML structure",
        "GMP response shape aliases belong in clawosiris/rust-gvm",
    ),
    (
        "Task run status changed",
        "gvmd alert display names belong in clawosiris/rust-gvm",
    ),
    (
        "Updated SecInfo arrived",
        "gvmd alert display names belong in clawosiris/rust-gvm",
    ),
    (
        "New SecInfo arrived",
        "gvmd alert display names belong in clawosiris/rust-gvm",
    ),
    (
        "SysLog",
        "gvmd alert display names belong in clawosiris/rust-gvm",
    ),
    (
        "Syslog",
        "gvmd alert display names belong in clawosiris/rust-gvm",
    ),
];

const FORBIDDEN_DIRECT_DEPS: &[(&str, &str)] = &[
    (
        "quick-xml",
        "direct XML parser dependencies belong in clawosiris/rust-gvm",
    ),
    (
        "roxmltree",
        "direct XML parser dependencies belong in clawosiris/rust-gvm",
    ),
    (
        "xmltree",
        "direct XML parser dependencies belong in clawosiris/rust-gvm",
    ),
    (
        "serde-xml-rs",
        "direct XML parser dependencies belong in clawosiris/rust-gvm",
    ),
];

#[test]
fn gmp_wire_handling_stays_in_rust_gvm() {
    // This is an architecture boundary test, not a style lint. The gateway may
    // orchestrate typed rust-gvm APIs, but GMP XML command construction and GMP
    // response parsing, protocol-shape aliases, and wire/display-name parsing
    // must be fixed upstream in clawosiris/rust-gvm. Unit-test sidecar fixtures
    // may still contain raw XML; this test intentionally scans production
    // source.
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let src_dir = manifest_dir.join("src");
    let mut findings = find_forbidden_gmp_wire_handling(&manifest_dir, &src_dir);
    findings.extend(find_forbidden_direct_dependencies(&manifest_dir));
    findings.extend(find_mismatched_response_parsers(
        &manifest_dir,
        &src_dir.join("gvmd_adapter"),
    ));

    assert!(
        findings.is_empty(),
        "GMP command/response wire handling must be implemented in \
         clawosiris/rust-gvm, not rust-gvm-api. Stop this change and report an \
         upstream issue using docs/rust-gvm-gmp-boundary-issue-template.md.\n\n{}",
        format_findings(&findings.iter().collect::<Vec<_>>())
    );
}

fn find_forbidden_gmp_wire_handling(manifest_dir: &Path, dir: &Path) -> Vec<Finding> {
    let mut findings = Vec::new();
    for file in rust_files(dir) {
        let relative = file
            .strip_prefix(manifest_dir)
            .expect("source file should be below manifest dir")
            .to_string_lossy()
            .replace('\\', "/");
        let contents = fs::read_to_string(&file).expect("read Rust source file");
        let mut cfg_test_pending = false;
        let mut test_module_depth: Option<isize> = None;

        for (line_index, line) in contents.lines().enumerate() {
            if let Some(depth) = test_module_depth.as_mut() {
                *depth += brace_delta(line);
                if *depth <= 0 {
                    test_module_depth = None;
                }
                continue;
            }

            if line.trim() == "#[cfg(test)]" {
                cfg_test_pending = true;
                continue;
            }

            if cfg_test_pending && line.contains("mod tests") {
                test_module_depth = Some(brace_delta(line));
                cfg_test_pending = false;
                continue;
            }
            cfg_test_pending = false;

            for (needle, marker) in FORBIDDEN_MARKERS {
                if line.contains(needle) {
                    findings.push(Finding {
                        path: relative.clone(),
                        line: line_index + 1,
                        marker,
                        text: line.trim().to_string(),
                    });
                }
            }
        }
    }
    findings
}

fn brace_delta(line: &str) -> isize {
    line.chars().filter(|character| *character == '{').count() as isize
        - line.chars().filter(|character| *character == '}').count() as isize
}

fn find_forbidden_direct_dependencies(manifest_dir: &Path) -> Vec<Finding> {
    let cargo_toml = manifest_dir.join("Cargo.toml");
    let contents = fs::read_to_string(&cargo_toml).expect("read Cargo.toml");
    let mut findings = Vec::new();

    for (line_index, line) in contents.lines().enumerate() {
        let trimmed = line.trim_start();
        for (dependency, marker) in FORBIDDEN_DIRECT_DEPS {
            if trimmed.starts_with(&format!("{dependency} "))
                || trimmed.starts_with(&format!("{dependency}="))
                || trimmed.starts_with(&format!("{dependency}."))
            {
                findings.push(Finding {
                    path: "Cargo.toml".to_string(),
                    line: line_index + 1,
                    marker,
                    text: line.trim().to_string(),
                });
            }
        }
    }

    findings
}

fn find_mismatched_response_parsers(manifest_dir: &Path, dir: &Path) -> Vec<Finding> {
    let mut findings = Vec::new();

    for file in rust_files(dir) {
        let relative = file
            .strip_prefix(manifest_dir)
            .expect("source file should be below manifest dir")
            .to_string_lossy()
            .replace('\\', "/");
        let contents = fs::read_to_string(file).expect("read gvmd adapter source file");
        let mut last_operation: Option<(&'static str, usize)> = None;

        for (line_index, line) in contents.lines().enumerate() {
            if line.contains("\"tasks.start\"") {
                last_operation = Some(("tasks.start", line_index + 1));
            } else if line.contains("\"tasks.resume\"") {
                last_operation = Some(("tasks.resume", line_index + 1));
            } else if line.contains("StartTaskResponse::from_response(&response)") {
                if let Some(("tasks.resume", operation_line)) = last_operation {
                    findings.push(Finding {
                        path: relative.clone(),
                        line: line_index + 1,
                        marker: "resume_task must use a typed rust-gvm resume response parser",
                        text: format!(
                            "operation declared at line {operation_line}; parser: {}",
                            line.trim()
                        ),
                    });
                }
                last_operation = None;
            } else if line.contains("ActionResponse::from_response(&response)")
                || line.contains("GetTasksResponse::from_response(&response)")
                || line.contains("CreateTaskResponse::from_response(&response)")
            {
                last_operation = None;
            }
        }
    }

    findings
}

fn rust_files(dir: &Path) -> Vec<PathBuf> {
    let mut files = Vec::new();
    for entry in fs::read_dir(dir).expect("read source directory") {
        let path = entry.expect("read directory entry").path();
        if path.is_dir() {
            files.extend(rust_files(&path));
        } else if path.extension().is_some_and(|extension| extension == "rs")
            && !path
                .file_name()
                .is_some_and(|name| name.to_string_lossy().ends_with("_test.rs"))
        {
            files.push(path);
        }
    }
    files.sort();
    files
}

fn format_findings(findings: &[&Finding]) -> String {
    if findings.is_empty() {
        return "no unexpected findings".to_string();
    }

    findings
        .iter()
        .map(|finding| {
            format!(
                "{}:{}: {}\n    {}\n    {}",
                finding.path, finding.line, finding.marker, finding.text, finding.marker
            )
        })
        .collect::<Vec<_>>()
        .join("\n")
}
