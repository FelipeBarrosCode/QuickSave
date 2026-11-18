// SPDX-License-Identifier: GPL-3.0-only
//! Unsigned Unix tombstone/path grants are not Windows mutation authority.
//! Windows native tombstones use the shared authenticated NativeTransaction.
use crate::{identity::VerifiedIdentity, NativeObjectId, PlannedTombstone};
use noland_state_core::{Result, StateError};
use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub(super) struct Observation {
    parent: Option<NativeObjectId>,
    pub identity: Option<VerifiedIdentity>,
}

impl Observation {
    pub fn same_parent(self, current: Self) -> bool {
        self.parent == current.parent
    }
}

pub(super) fn observe(_: &Path) -> Result<Observation> {
    Err(StateError::Conflict(
        "legacy leaf observations cannot authorize Windows tombstones".into(),
    ))
}

pub(super) fn publish_new(
    _: &Path,
    _: &Path,
    _: Option<&(std::path::PathBuf, (u64, u64))>,
) -> Result<()> {
    Err(StateError::Conflict(
        "Windows publication requires typed native ownership with full file IDs".into(),
    ))
}

impl PlannedTombstone {
    pub(super) fn validate(&self) -> Result<()> {
        Err(StateError::Conflict(
            "Windows legacy tombstone validation is unsupported; use typed native recovery".into(),
        ))
    }
    pub(super) fn apply(&self) -> Result<()> {
        Err(StateError::Conflict(
            "Windows legacy tombstone mutation is unsupported; use typed native recovery".into(),
        ))
    }
}
