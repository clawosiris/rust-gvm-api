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

#[test]
fn gmp_wire_handling_stays_in_rust_gvm() {
    // This is an architecture boundary test, not a style lint. The gateway may
    // orchestrate typed rust-gvm APIs, but GMP XML command construction and GMP
    // wire/display-name parsing must be fixed upstream in clawosiris/rust-gvm.
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let src_dir = manifest_dir.join("src");
    let findings = find_forbidden_gmp_wire_handling(&manifest_dir, &src_dir);

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
        for (line_index, line) in contents.lines().enumerate() {
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

fn rust_files(dir: &Path) -> Vec<PathBuf> {
    let mut files = Vec::new();
    for entry in fs::read_dir(dir).expect("read source directory") {
        let path = entry.expect("read directory entry").path();
        if path.is_dir() {
            files.extend(rust_files(&path));
        } else if path.extension().is_some_and(|extension| extension == "rs") {
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
