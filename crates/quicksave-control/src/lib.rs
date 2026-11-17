// SPDX-License-Identifier: GPL-3.0-only
//! Shared native authorization and bounded worker admission.
//!
//! The desktop supplies the actual native confirmation dialog. This crate owns
//! exact scopes, pinned proofs, expiring one-use tokens, and shutdown admission.
//! These tests exercise the real production policy without a GUI/WebKit linker.
#![forbid(unsafe_code)]

pub mod approval;
pub mod runtime;

fn message(error: anyhow::Error) -> String {
    format!("{error:#}")
}
