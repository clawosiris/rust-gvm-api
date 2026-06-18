// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Greenbone AG

use gvm_gateway_domain::{
    CreateNoteInput, CreateOverrideInput, GatewayError, ModifyNoteInput, ModifyOverrideInput,
};
use gvm_gmp::commands::{notes::NoteOpts, overrides::OverrideOpts};

use crate::conversions::parse_entity_id;

pub(super) fn note_opts_from_create_input(
    input: CreateNoteInput,
) -> Result<NoteOpts, GatewayError> {
    Ok(NoteOpts {
        text: input.text,
        hosts: input.hosts,
        port: input.port,
        severity: input.severity,
        task_id: input.task_id.as_deref().map(parse_entity_id).transpose()?,
        result_id: input
            .result_id
            .as_deref()
            .map(parse_entity_id)
            .transpose()?,
        active: input.active,
        orphan: input.orphan,
    })
}

pub(super) fn note_opts_from_modify_input(
    input: ModifyNoteInput,
) -> Result<NoteOpts, GatewayError> {
    Ok(NoteOpts {
        text: input.text,
        hosts: input.hosts.unwrap_or_default(),
        port: input.port,
        severity: input.severity,
        task_id: input.task_id.as_deref().map(parse_entity_id).transpose()?,
        result_id: input
            .result_id
            .as_deref()
            .map(parse_entity_id)
            .transpose()?,
        active: input.active,
        orphan: input.orphan,
    })
}

pub(super) fn override_opts_from_create_input(
    input: CreateOverrideInput,
) -> Result<OverrideOpts, GatewayError> {
    Ok(OverrideOpts {
        text: input.text,
        hosts: input.hosts,
        port: input.port,
        severity: input.severity,
        new_severity: input.new_severity,
        task_id: input.task_id.as_deref().map(parse_entity_id).transpose()?,
        result_id: input
            .result_id
            .as_deref()
            .map(parse_entity_id)
            .transpose()?,
        active: input.active,
    })
}

pub(super) fn override_opts_from_modify_input(
    input: ModifyOverrideInput,
) -> Result<OverrideOpts, GatewayError> {
    Ok(OverrideOpts {
        text: input.text,
        hosts: input.hosts.unwrap_or_default(),
        port: input.port,
        severity: input.severity,
        new_severity: input.new_severity,
        task_id: input.task_id.as_deref().map(parse_entity_id).transpose()?,
        result_id: input
            .result_id
            .as_deref()
            .map(parse_entity_id)
            .transpose()?,
        active: input.active,
    })
}
