// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Greenbone AG

//! Feed domain types.

use serde::{Deserialize, Serialize};

/// Domain feed status representation.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Feed {
    /// Feed type.
    #[serde(rename = "type")]
    pub feed_type: String,
    /// Feed display name.
    pub name: String,
    /// Optional version string.
    pub version: Option<String>,
    /// Optional description.
    pub description: Option<String>,
    /// Whether a sync is currently running.
    #[serde(rename = "currentlySyncing")]
    pub currently_syncing: bool,
}
