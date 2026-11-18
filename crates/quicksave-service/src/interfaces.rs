// SPDX-License-Identifier: GPL-3.0-only
//! Injectable native-only boundaries. No default implementation is a fake.

use anyhow::Result;
use quicksave_state::ProviderAccess;
use serde_json::Value;
use std::{future::Future, pin::Pin, sync::Arc};

pub type NativeFuture<'a, T> = Pin<Box<dyn Future<Output = Result<T>> + Send + 'a>>;
pub type Enqueue = Arc<dyn Fn(Value) -> Result<()> + Send + Sync>;
pub type PublishGuard = Arc<dyn Fn() -> Result<()> + Send + Sync>;

/// `snapshot` reads only non-secret QuickSave state, never a credential vault.
/// Provider references and tracking records are private to the service.
pub trait ServiceStore: Send + Sync + 'static {
    fn snapshot(&self) -> Result<Value>;
    fn provider_types(&self) -> Value;
    fn connect_provider(&self, input: &Value) -> Result<Value>;
    fn disconnect_provider(&self, id: &str) -> Result<()>;
    fn import_noland(&self, input: &Value) -> Result<Value>;
    /// Explicit consent precedes discovery. This must not parse source contents
    /// or access any source/native credential vault.
    fn discover_noland_sources(&self) -> Result<Value> {
        anyhow::bail!("Native No Land source discovery is unavailable")
    }
    /// Native-only selected-source scope. Includes its pinned path and stamp,
    /// never credentials and never a webview-provided path substitution.
    fn noland_source_scope(&self, _source_id: &str) -> Result<Value> {
        anyhow::bail!("Native No Land source proof is unavailable")
    }
    fn provider_access(&self, id: &str, operation_id: &str) -> Result<ProviderAccess>;
    fn record_provider_health(&self, id: &str, report: &Value) -> Result<()>;
    fn grant_provider_write(&self, id: &str) -> Result<()>;
    fn provider_writable(&self, id: &str) -> Result<bool>;
    fn oauth_reauthorization_profile(
        &self,
        _id: &str,
    ) -> Result<quicksave_state::NativeOAuthProfile> {
        anyhow::bail!("Native OAuth reauthorization is unavailable")
    }
    fn provider_credential_generation(&self, _id: &str) -> Result<u64> {
        anyhow::bail!("Native provider reauthorization is unavailable")
    }
    fn complete_provider_reauthorization(
        &self,
        _id: &str,
        _expected: u64,
        _credentials: &Value,
    ) -> Result<()> {
        anyhow::bail!("Native provider reauthorization is unavailable")
    }
    fn export_recovery_key(&self, _input: &Value) -> Result<Value> {
        anyhow::bail!("Native external recovery-key export is unavailable")
    }
}

/// Access credentials are moved directly into a private native operation. The
/// interface never serializes them, returns them to JS, or stores them in plans.
/// A submission error must mean definitive admission failure. Ambiguous
/// acceptance must return an operation ID with a retained native journal.
pub trait ServiceEngine: Send + Sync + 'static {
    fn shutdown<'a>(&'a self) -> NativeFuture<'a, ()>;
    /// Once at successful native upload finalization, never on status polling.
    /// Prepared bytes alone do not prove that COMMITTED was durably published.
    fn verify_capture_completion<'a>(
        &'a self,
        _operation_id: &'a str,
        _binding: Value,
    ) -> NativeFuture<'a, Value> {
        Box::pin(async {
            anyhow::bail!("Authenticated native committed-capture verification is unavailable")
        })
    }
    fn rich_catalog_supported(&self) -> bool {
        false
    }
    fn native_capture_supported(&self) -> bool {
        false
    }
    #[cfg(any(unix, windows))]
    fn upload_captured_guarded<'a>(
        &'a self,
        _access: ProviderAccess,
        _selection: Value,
        _guard: PublishGuard,
        _capture: Arc<dyn quicksave_noland::capture_control::NativeCaptureController>,
    ) -> NativeFuture<'a, Value> {
        Box::pin(async { anyhow::bail!("Actual native source capture receipts are unavailable") })
    }
    fn call<'a>(
        &'a self,
        method: &'a str,
        access: Option<ProviderAccess>,
        input: Value,
    ) -> NativeFuture<'a, Value>;
    fn upload_guarded<'a>(
        &'a self,
        access: ProviderAccess,
        selection: Value,
        guard: PublishGuard,
    ) -> NativeFuture<'a, Value>;
    /// Replace the trusted callback before an exact native retry. An old
    /// cancelled operation's callback must not authorize a new attempt.
    fn retry_guarded<'a>(
        &'a self,
        operation_id: &'a str,
        guard: PublishGuard,
    ) -> NativeFuture<'a, Value>;
    fn download_guarded<'a>(
        &'a self,
        _access: ProviderAccess,
        _selection: Value,
        _guard: PublishGuard,
    ) -> NativeFuture<'a, Value> {
        Box::pin(async { anyhow::bail!("Authenticated frozen native restore is unavailable") })
    }
    /// Recover retained local outputs/journals only. This does not reconnect a
    /// provider, retry a download, or require cloud credentials.
    fn recover_restore_local<'a>(
        &'a self,
        _selection: Value,
        _guard: PublishGuard,
    ) -> NativeFuture<'a, Value> {
        Box::pin(async { anyhow::bail!("Authenticated local restore recovery is unavailable") })
    }
    fn delete_guarded<'a>(
        &'a self,
        _access: ProviderAccess,
        _selection: Value,
        _guard: PublishGuard,
    ) -> NativeFuture<'a, Value> {
        Box::pin(async { anyhow::bail!("Exact guarded native cloud deletion is unavailable") })
    }
}

/// Implementations verify authenticated tracking grants even for manual reads,
/// revalidate native identities, and finalize exact captured generations.
pub trait ServiceTracking: Send + Sync + 'static {
    fn call(&self, method: &str, input: &Value) -> Result<Value>;
    fn pin_scope(&self, record: &Value) -> Result<Arc<dyn SourceGuard>>;
    fn shutdown(&self) -> Result<()>;
    fn accept_capture_receipt(
        &self,
        _work_id: &str,
        _receipt: Arc<dyn quicksave_tracking::NativeCaptureReceipt>,
    ) -> Result<Value> {
        anyhow::bail!("Native source capture receipt admission is unavailable")
    }
    fn original_work(
        &self,
        _record: &Value,
        _work_id: &str,
        _generation: u64,
    ) -> Result<Arc<quicksave_tracking::NativeFrozenWork>> {
        anyhow::bail!("Original authenticated native frozen work is unavailable")
    }
    fn resume_pending(
        &self,
        _original: Arc<quicksave_tracking::NativeFrozenWork>,
        _receipt: Arc<dyn quicksave_tracking::NativeCaptureReceipt>,
    ) -> Result<Value> {
        anyhow::bail!("Original authenticated native capture reattachment is unavailable")
    }
    fn verify_upload_authority(
        &self,
        software: &str,
        provider: &str,
        automatic: bool,
        work: &Value,
    ) -> Result<()> {
        // Native revocation check, not inventory/capture verification. The real
        // source callback separately verifies its immutable prepared receipt at
        // publication. `work` may contain only frozen small grant envelopes.
        self.call(
            "verify_upload_authority",
            &serde_json::json!({
                "softwareId":software,"providerId":provider,"automatic":automatic,"work":work,
            }),
        )?;
        Ok(())
    }
}

/// Owned native handles live until the real async operation is terminal and its
/// baseline has been durably finalized, not merely until submission returns.
pub trait SourceGuard: Send + Sync + 'static {
    fn verify(&self) -> Result<()>;
}

pub trait ServiceDiscovery: Send + Sync + 'static {
    fn applications(&self) -> Result<Value>;
    fn software_bundles(&self) -> Result<Value> {
        anyhow::bail!("Verified native software bundle planning is unavailable")
    }
    /// Native-only, verified policy handoff. Never supplied by a webview.
    fn software_bundles_approved(&self, _authority: &Value) -> Result<Value> {
        anyhow::bail!("Pinned native discovery policy is unavailable")
    }
    /// Pure native path/rule description for consent, not a content grant.
    fn tracking_scope(&self) -> Result<Value> {
        anyhow::bail!("Native application enrollment scope is unavailable")
    }
}

/// Returns a private native provider-input document containing OAuth credentials.
/// Never pass this result to a webview, log, or generic operation history.
pub trait ServiceOAuth: Send + Sync + 'static {
    fn supports(&self, kind: &str) -> bool;
    fn authorize<'a>(&'a self, input: Value) -> NativeFuture<'a, Value>;
}

pub struct UnavailableOAuth;
impl ServiceOAuth for UnavailableOAuth {
    fn supports(&self, _kind: &str) -> bool {
        false
    }
    fn authorize<'a>(&'a self, _input: Value) -> NativeFuture<'a, Value> {
        Box::pin(async {
            anyhow::bail!("Native OAuth PKCE is not available in this injected environment")
        })
    }
}

pub struct NativeDiscovery {
    scope: quicksave_integrations::bundles::BundleInventoryScope,
    bases: Vec<std::path::PathBuf>,
}
impl NativeDiscovery {
    pub fn new(home: &std::path::Path, data: &std::path::Path, isolated: bool) -> Result<Self> {
        use std::path::{Path, PathBuf};
        let mut scope = quicksave_integrations::bundles::BundleInventoryScope {
            home: Some(home.to_path_buf()),
            protected_roots: vec![
                data.to_path_buf(),
                Path::new(env!("CARGO_MANIFEST_DIR"))
                    .parent()
                    .and_then(Path::parent)
                    .ok_or_else(|| anyhow::anyhow!("Native repository exclusion is unavailable"))?
                    .to_path_buf(),
            ],
            ..Default::default()
        };
        let mut bases = Vec::new();
        if cfg!(target_os = "macos") {
            scope
                .application_directories
                .push(home.join("Applications"));
            if !isolated {
                scope
                    .application_directories
                    .insert(0, PathBuf::from("/Applications"));
            }
            bases.extend(scope.application_directories.iter().cloned());
            for relative in [
                "Library/Application Support",
                "Library/Preferences",
                "Library/Containers",
                "Library/Group Containers",
            ] {
                bases.push(home.join(relative));
            }
            scope
                .steam_roots
                .push(home.join("Library/Application Support/Steam"));
        } else if cfg!(target_os = "linux") {
            let data_home = if isolated {
                home.join(".local/share")
            } else {
                let dirs = quicksave_platform::app_directories()?;
                PathBuf::from(
                    dirs["data"]
                        .as_str()
                        .ok_or_else(|| anyhow::anyhow!("Native data base is unavailable"))?,
                )
                .parent()
                .ok_or_else(|| anyhow::anyhow!("Native data base has no parent"))?
                .to_path_buf()
            };
            let config_home = if isolated {
                home.join(".config")
            } else {
                let dirs = quicksave_platform::app_directories()?;
                PathBuf::from(
                    dirs["config"]
                        .as_str()
                        .ok_or_else(|| anyhow::anyhow!("Native config base is unavailable"))?,
                )
                .parent()
                .ok_or_else(|| anyhow::anyhow!("Native config base has no parent"))?
                .to_path_buf()
            };
            scope
                .desktop_directories
                .push(data_home.join("applications"));
            if !isolated {
                scope.desktop_directories.extend([
                    PathBuf::from("/usr/local/share/applications"),
                    PathBuf::from("/usr/share/applications"),
                ]);
                bases.extend(scope.desktop_directories.iter().cloned());
                bases.extend([
                    PathBuf::from("/usr/bin"),
                    PathBuf::from("/usr/local/bin"),
                    PathBuf::from("/usr/lib"),
                    PathBuf::from("/usr/local/lib"),
                    PathBuf::from("/opt"),
                ]);
            }
            bases.extend([
                data_home.clone(),
                config_home.clone(),
                home.join(".var/app"),
                home.join("Applications"),
            ]);
            scope.xdg_data_home = Some(data_home);
            scope.xdg_config_home = Some(config_home);
            scope
                .steam_roots
                .extend([home.join(".local/share/Steam"), home.join(".steam/steam")]);
        }
        // Source state is always excluded, even when absent. It is accessed only
        // by the independent read-only, consent-backed No Land import operation.
        scope.protected_roots.push(if cfg!(target_os = "macos") {
            home.join("Library/Application Support/com.noland.connect")
        } else if cfg!(windows) {
            home.join("AppData/Roaming/com.noland.connect")
        } else {
            scope
                .xdg_data_home
                .clone()
                .unwrap_or_else(|| home.join(".local/share"))
                .join("com.noland.connect")
        });
        bases.extend(scope.steam_roots.iter().cloned());
        Ok(Self { scope, bases })
    }
}
impl ServiceDiscovery for NativeDiscovery {
    fn applications(&self) -> Result<Value> {
        quicksave_integrations::discover_applications()
    }
    fn software_bundles(&self) -> Result<Value> {
        let report = quicksave_integrations::discover_software_bundles_in_scope(&self.scope)?;
        let mut scope = self.scope.clone();
        // This method runs only after native inventory consent, whose exact-ID
        // policy allows verified Steam apps, not title/path ownership guesses.
        // An initial metadata pass supplies numeric IDs for the explicit
        // inventory allowlist. Neither pass reads saved-file payloads.
        for app in report["bundlePlans"].as_array().into_iter().flatten() {
            if let Some(id) = app
                .pointer("/sourceIdentity/steam_app_id")
                .and_then(Value::as_u64)
            {
                if let Ok(id) = u32::try_from(id) {
                    scope.inventory_approved_steam_app_ids.insert(id);
                }
            }
        }
        if scope.inventory_approved_steam_app_ids.is_empty() {
            return Ok(report);
        }
        quicksave_integrations::discover_software_bundles_in_scope(&scope)
    }
    fn software_bundles_approved(&self, authority: &Value) -> Result<Value> {
        use quicksave_integrations::bundles::ApprovedDiscoveryBase;
        let proofs = authority["baseDirectories"]
            .as_array()
            .ok_or_else(|| anyhow::anyhow!("Native discovery base capabilities are missing"))?;
        anyhow::ensure!(
            !proofs.is_empty() && proofs.len() <= 32,
            "Native discovery base capability count is invalid"
        );
        let mut caps = Vec::new();
        for proof in proofs {
            let path = std::path::PathBuf::from(
                proof["path"]
                    .as_str()
                    .ok_or_else(|| anyhow::anyhow!("Native discovery base path is missing"))?,
            );
            anyhow::ensure!(
                proof["kind"] == "directory",
                "Native discovery needs pinned directory capabilities"
            );
            let identity: quicksave_platform::RootIdentity =
                serde_json::from_value(proof["identity"].clone())?;
            let root = Arc::new(quicksave_platform::SafeRoot::open(&path)?);
            caps.push(ApprovedDiscoveryBase::from_pinned(path, root, identity)?);
        }
        let mut scope = self.scope.clone();
        let exclusions = authority["excludedPaths"]
            .as_array()
            .ok_or_else(|| anyhow::anyhow!("Native discovery exclusions are missing"))?;
        anyhow::ensure!(
            exclusions.len() <= 128,
            "Native discovery exclusions exceeded their bound"
        );
        for excluded in exclusions {
            let path =
                std::path::PathBuf::from(excluded.as_str().ok_or_else(|| {
                    anyhow::anyhow!("Native discovery exclusion path is missing")
                })?);
            anyhow::ensure!(path.is_absolute(), "Native exclusions must be absolute");
            if !scope.protected_roots.contains(&path) {
                scope.protected_roots.push(path);
            }
        }
        let report =
            quicksave_integrations::bundles::discover_software_bundles_with_approved_bases(
                &scope, &caps,
            )?;
        for app in report["bundlePlans"].as_array().into_iter().flatten() {
            if let Some(id) = app
                .pointer("/sourceIdentity/steam_app_id")
                .and_then(Value::as_u64)
            {
                if let Ok(id) = u32::try_from(id) {
                    scope.inventory_approved_steam_app_ids.insert(id);
                }
            }
        }
        if scope.inventory_approved_steam_app_ids.is_empty() {
            return Ok(report);
        }
        quicksave_integrations::bundles::discover_software_bundles_with_approved_bases(
            &scope, &caps,
        )
    }
    fn tracking_scope(&self) -> Result<Value> {
        Ok(serde_json::json!({
            "baseDirectories":self.bases, "excludedPaths":self.scope.protected_roots,
            "summary":"Allow future verified applications only inside these pinned native bases and exact product/container/Steam ownership rules. Installation, save, configuration and runtime roots are indexed without following links. Unknown app names never authorize data roots. This does not enable uploads or autosave.",
        }))
    }
}
