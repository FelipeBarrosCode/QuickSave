// SPDX-License-Identifier: GPL-3.0-only
//! Explicit provider lifecycle operations; credentials never enter history DTOs.

use crate::{boundary as dto, OperationGuard, RetryPlan, WorkspaceService};
use anyhow::{anyhow, ensure};
use serde_json::{json, Value};
use std::{
    ops::Deref,
    sync::{atomic::Ordering, Arc},
};
use zeroize::Zeroize;

struct PrivateInput(Value);
impl Deref for PrivateInput {
    type Target = Value;
    fn deref(&self) -> &Value {
        &self.0
    }
}
impl Drop for PrivateInput {
    fn drop(&mut self) {
        fn scrub(value: &mut Value) {
            match value {
                Value::String(text) => text.zeroize(),
                Value::Array(values) => values.iter_mut().for_each(scrub),
                Value::Object(values) => values.values_mut().for_each(scrub),
                _ => {}
            }
        }
        scrub(&mut self.0);
    }
}

impl WorkspaceService {
    pub(super) async fn run_reauthorization(
        self: Arc<Self>,
        id: &str,
        plan: RetryPlan,
        mut guard: OperationGuard,
    ) {
        let input = PrivateInput(plan.params);
        let result = async {
            ensure!(!self.cancelled(id),"Provider reauthorization was cancelled");
            ensure!(plan.scope == self.source_scope(&input)?,
                "The approved provider configuration changed");
            let provider_id = dto::id(&input,"providerId")?.to_owned();
            let snapshot = self.snapshot()?;
            let provider = dto::provider_record(&snapshot,&provider_id)?;
            ensure!(provider["status"] != "disconnected",
                "Disconnected providers need an explicitly new connection");
            let kind = dto::id(provider,"kind")?.to_owned();
            let oauth = matches!(kind.as_str(),
                "google_drive" | "microsoft_onedrive" | "microsoft_one_drive" | "dropbox" | "box");
            self.patch_operation(id,json!({"state":"running","phase":"storing_native_credentials","canCancel":false}));
            let (expected,credentials) = if oauth {
                ensure!(input.get("credentials").is_none(),
                    "OAuth reauthorization uses the original registered client, not caller-supplied tokens");
                ensure!(self.oauth.supports(&kind),"Native OAuth reauthorization is unavailable");
                let report = self.engine_call("preflight",None,json!({})).await?;
                ensure!(report["available"] == true && report["oauthRefreshPersistence"] == true,
                    dto::OAUTH_STORAGE_UNAVAILABLE);
                let store = self.store.clone();
                let provider_id = provider_id.clone();
                let mut profile = tokio::task::spawn_blocking(move ||
                    store.oauth_reauthorization_profile(&provider_id)).await
                    .map_err(|_| anyhow!("Native OAuth profile worker failed"))??;
                ensure!(profile.provider_id == input["providerId"] && profile.kind == kind,
                    "Native OAuth profile no longer matches this provider");
                self.patch_operation(id,json!({"phase":"authorizing_oauth"}));
                let private = json!({"kind":kind,"name":provider["name"],
                    "clientId":std::mem::take(&mut profile.client_id),
                    "clientSecret":profile.client_secret.take()});
                let result = PrivateInput(self.oauth.authorize(private).await?);
                (profile.credential_generation,PrivateInput(result["credentials"].clone()))
            } else {
                let store = self.store.clone();
                let provider_id = provider_id.clone();
                let generation = tokio::task::spawn_blocking(move ||
                    store.provider_credential_generation(&provider_id)).await
                    .map_err(|_| anyhow!("Native credential revision worker failed"))??;
                (generation,PrivateInput(input.get("credentials")
                    .ok_or_else(|| anyhow!("Static provider reauthorization requires credentials"))?.clone()))
            };
            ensure!(plan.scope == self.source_scope(&input)?,
                "The provider changed during native reauthorization");
            let store = self.store.clone();
            let selected = provider_id.clone();
            tokio::task::spawn_blocking(move ||
                store.complete_provider_reauthorization(&selected,expected,&credentials)).await
                .map_err(|_| anyhow!("Native credential persistence worker failed"))??;
            // Explicit sign-in changes authority and revokes old autosave grants.
            // A token alone is not proof of the original provider account.
            self.healthy.lock().map_err(|_| anyhow!("Provider health lock failed"))?.remove(&provider_id);
            self.patch_operation(id,json!({"phase":"verifying_provider_access"}));
            self.ensure_provider_health(&provider_id).await?;
            Ok::<(),anyhow::Error>(())
        }.await;
        self.finish(
            id,
            if result.is_ok() {
                "completed"
            } else {
                "failed"
            },
            result.is_err(),
        );
        if let Err(error) = result {
            self.patch_operation(id, json!({"error":dto::engine_error(&error)}));
        }
        guard.finalized = !self.lifetime.finalization_blocked.load(Ordering::Acquire);
    }
}
