// SPDX-License-Identifier: GPL-3.0-only
use anyhow::{bail, Result};
use quicksave_state::ProviderAccess;
use serde_json::Value;
use std::path::Path;
use std::sync::Arc;

pub struct NativeEngine;

fn unsupported<T>() -> Result<T> {
    bail!("native No Land shared storage is unsupported on this platform: the Unix restore engine has not been ported; remote Linux execution is not used")
}

impl NativeEngine {
    pub fn open(_: &Path, _: &Path) -> Result<Self> {
        unsupported()
    }
    pub fn with_workspace(self, _: quicksave_state::WorkspaceStore) -> Result<Self> {
        unsupported()
    }
    pub async fn shutdown(&self) -> Result<()> {
        unsupported()
    }
    pub async fn preflight(&self) -> Result<Value> {
        unsupported()
    }
    pub async fn probe(&self, _: &ProviderAccess) -> Result<Value> {
        unsupported()
    }
    pub async fn health(&self, _: &ProviderAccess) -> Result<Value> {
        unsupported()
    }
    pub async fn register(&self, _: &Value) -> Result<()> {
        unsupported()
    }
    pub async fn catalog(&self, _: &ProviderAccess) -> Result<Value> {
        unsupported()
    }
    pub async fn files(&self, _: &ProviderAccess, _: &Value) -> Result<Value> {
        unsupported()
    }
    pub async fn software_files(&self, _: &Value) -> Result<Value> {
        unsupported()
    }
    pub async fn upload(&self, _: ProviderAccess, _: Value) -> Result<Value> {
        unsupported()
    }
    pub async fn upload_guarded(
        &self,
        _: ProviderAccess,
        _: Value,
        _: Arc<dyn Fn() -> Result<()> + Send + Sync>,
    ) -> Result<Value> {
        unsupported()
    }
    pub async fn retry_guarded(
        &self,
        _: &str,
        _: Arc<dyn Fn() -> Result<()> + Send + Sync>,
    ) -> Result<Value> {
        unsupported()
    }
    pub async fn download(&self, _: ProviderAccess, _: Value) -> Result<Value> {
        unsupported()
    }
    pub async fn preview_delete(&self, _: &ProviderAccess, _: Value) -> Result<Value> {
        unsupported()
    }
    pub async fn delete(&self, _: ProviderAccess, _: Value) -> Result<Value> {
        unsupported()
    }
    pub async fn status(&self, _: &str) -> Result<Value> {
        unsupported()
    }
    pub async fn recent(&self) -> Result<Vec<Value>> {
        unsupported()
    }
    pub async fn cancel(&self, _: &str) -> Result<Value> {
        unsupported()
    }
    pub async fn retry(&self, _: &str) -> Result<Value> {
        unsupported()
    }
    pub async fn reattach(&self, _: ProviderAccess, _: &str) -> Result<()> {
        unsupported()
    }
}
