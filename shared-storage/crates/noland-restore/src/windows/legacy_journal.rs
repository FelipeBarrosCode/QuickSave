// SPDX-License-Identifier: GPL-3.0-only
//! Explicit rejection surface for the Unix-only unsigned transaction format.
use crate::RestoreTransactionJournal;
use noland_state_core::{Result, StateError};
use std::path::{Path, PathBuf};

pub(super) enum Intent {
    Directory(PathBuf),
    Created(PathBuf),
    Partial(PathBuf),
}
pub(super) fn append(_: &Path, _: &[Intent]) -> Result<()> {
    Err(StateError::Conflict(
        "Windows cannot append unsigned restore mutation intents".into(),
    ))
}
pub(super) fn checkpoint(_: &Path) -> Result<()> {
    Err(StateError::Conflict(
        "Windows cannot checkpoint unsigned restore cleanup authority".into(),
    ))
}
pub(super) fn read(_: &Path) -> Result<RestoreTransactionJournal> {
    Err(StateError::Conflict(
        "Windows will not replay unsigned legacy restore journals".into(),
    ))
}
