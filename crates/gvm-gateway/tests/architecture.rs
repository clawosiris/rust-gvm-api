// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Greenbone AG

//! Architectural boundary tests.
//!
//! These tests enforce that the domain, application, and REST adapter crates
//! do **not** depend on GMP/GVMD protocol crates.  Only the outgoing gvmd
//! adapter (`gvm-gateway-gvmd`) and the composition-root binary
//! (`gvm-gateway`) are allowed to reference `gvm-gmp`, `gvm-client`, or
//! `gvm-connection`.

/// GMP/GVMD protocol crates that must NOT appear in inner-layer
/// `[dependencies]` sections.
const BANNED_DEPS: &[&str] = &["gvm-gmp", "gvm-client", "gvm-connection"];

/// Crates that form the inner layers of the hexagonal architecture.
const INNER_CRATES: &[(&str, &str)] = &[
    (
        "gvm-gateway-domain",
        "crates/gvm-gateway-domain/Cargo.toml",
    ),
    ("gvm-gateway-app", "crates/gvm-gateway-app/Cargo.toml"),
    ("gvm-gateway-rest", "crates/gvm-gateway-rest/Cargo.toml"),
];

/// Asserts that inner-layer crates do not list any GMP protocol crate as a
/// runtime dependency.  Dev-dependencies are allowed (e.g. for integration
/// tests that spin up a mock server).
#[test]
fn inner_crates_must_not_depend_on_gmp_protocol_crates() {
    let workspace_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap();

    let mut violations = Vec::new();

    for &(crate_name, cargo_toml_path) in INNER_CRATES {
        let full_path = workspace_root.join(cargo_toml_path);
        let content = std::fs::read_to_string(&full_path).unwrap_or_else(|err| {
            panic!("failed to read {}: {err}", full_path.display());
        });

        // Extract only the [dependencies] section (not [dev-dependencies] or
        // [build-dependencies]).  We look for lines between `[dependencies]`
        // and the next `[` header.
        let deps_section = extract_dependencies_section(&content);

        for banned in BANNED_DEPS {
            // Check for the dependency as a TOML key (at the start of a line
            // or as a dotted key like `gvm-gmp.workspace`).
            let patterns = [
                format!("\n{banned}"),
                format!("{banned}."),
                format!("{banned} "),
                format!("{banned}="),
            ];
            let found = deps_section
                .as_ref()
                .map(|section| patterns.iter().any(|p| section.contains(p.as_str())))
                .unwrap_or(false);

            if found {
                violations.push(format!(
                    "{crate_name} depends on `{banned}` (in {cargo_toml_path})"
                ));
            }
        }
    }

    assert!(
        violations.is_empty(),
        "Architectural boundary violations detected:\n  - {}",
        violations.join("\n  - ")
    );
}

/// Extracts the `[dependencies]` section from a Cargo.toml string.
/// Returns the text between `[dependencies]` and the next section header.
fn extract_dependencies_section(content: &str) -> Option<String> {
    let mut in_deps = false;
    let mut section = String::new();

    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed == "[dependencies]" {
            in_deps = true;
            continue;
        }
        if in_deps {
            if trimmed.starts_with('[') {
                break;
            }
            section.push('\n');
            section.push_str(line);
        }
    }

    if section.is_empty() {
        None
    } else {
        Some(section)
    }
}
