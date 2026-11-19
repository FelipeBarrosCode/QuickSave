// SPDX-License-Identifier: GPL-3.0-only
//! Bounded native root/operation context; no payload bytes, keys or grants.
use crate::{
    model::{ApprovedRoot, TrackingPolicy},
    scan::AuthorityChanged,
};
use anyhow::Result;
use quicksave_platform::{
    DirectoryIdentityInspectionFailure, DirectoryIdentityInspectionSide,
    DirectoryIdentityInspectionStage,
};
use serde_json::{json, Value};
#[cfg(test)]
use std::path::Path;
use std::{
    fmt::{self, Write},
    path::PathBuf,
};

const MAX_MESSAGE_BYTES: usize = 1024;

#[derive(Clone, Debug)]
pub(crate) struct RootContext {
    root_id: String,
    path: Option<PathBuf>,
    role: String,
    relative: Option<String>,
    stage: &'static str,
}

/// Native policy proof is separate from app capture. An unavailable protected
/// root (or an unattributed pair inspection) cannot authorize omission of an
/// application root, even when its underlying error happens to be EACCES.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum InspectionSide {
    Selected,
    Protected,
    Both,
}

impl InspectionSide {
    fn name(self) -> &'static str {
        match self {
            Self::Selected => "selected",
            Self::Protected => "protected",
            Self::Both => "undetermined",
        }
    }
}

#[derive(Clone, Debug)]
pub(crate) struct PolicyRootFailure {
    selected: PathBuf,
    protected: Option<PathBuf>,
    side: InspectionSide,
    stage: &'static str,
    native_stage: Option<DirectoryIdentityInspectionStage>,
    relative: Option<String>,
    relative_unavailable: Option<&'static str>,
}

impl PolicyRootFailure {
    pub(crate) fn new(
        selected: &std::path::Path,
        protected: Option<&std::path::Path>,
        side: InspectionSide,
        stage: &'static str,
    ) -> Self {
        Self {
            selected: selected.to_owned(),
            protected: protected.map(std::path::Path::to_owned),
            side,
            stage,
            native_stage: None,
            relative: None,
            relative_unavailable: None,
        }
    }

    fn with_native_failure(mut self, error: &anyhow::Error) -> Self {
        // Only the pair inspection needs refinement. An explicitly protected
        // caller boundary must never be downgraded by an inner selected marker.
        if self.side == InspectionSide::Both {
            if let Some(native) = error.downcast_ref::<DirectoryIdentityInspectionFailure>() {
                self.side = match native.side {
                    DirectoryIdentityInspectionSide::Selected => InspectionSide::Selected,
                    DirectoryIdentityInspectionSide::Protected => InspectionSide::Protected,
                };
                self.native_stage = Some(native.stage);
                (self.relative, self.relative_unavailable) =
                    bounded_inspection_relative_path(native.relative_path.as_deref());
            }
        }
        self
    }

    pub(crate) fn run<T>(
        self,
        policy: &TrackingPolicy,
        operation: impl FnOnce() -> Result<T>,
    ) -> Result<T> {
        (|| {
            #[cfg(test)]
            policy.faults.check(
                match self.side {
                    InspectionSide::Selected => Some(self.selected.as_path()),
                    InspectionSide::Protected => self.protected.as_deref(),
                    InspectionSide::Both => None,
                },
                None,
                self.stage,
            )?;
            let _ = policy;
            operation()
        })()
        .map_err(|error| {
            let context = self.with_native_failure(&error);
            error.context(context)
        })
    }
}

impl fmt::Display for PolicyRootFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "native {} policy-root inspection stage {}",
            self.side.name(),
            self.stage
        )?;
        if let Some(stage) = self.native_stage {
            write!(f, " (native phase {})", native_stage_name(stage))?;
        }
        match self.side {
            InspectionSide::Selected => write!(f, " at {}", self.selected.display())?,
            InspectionSide::Protected => {
                if let Some(path) = &self.protected {
                    write!(f, " at {}", path.display())?;
                }
            }
            InspectionSide::Both => write!(f, " for selected {}", self.selected.display())?,
        }
        if let Some(relative) = &self.relative {
            write!(f, " / {relative}")?;
        }
        Ok(())
    }
}
impl std::error::Error for PolicyRootFailure {}

fn native_stage_name(stage: DirectoryIdentityInspectionStage) -> &'static str {
    match stage {
        DirectoryIdentityInspectionStage::ValidatePinnedRoot => "validate_pinned_root",
        DirectoryIdentityInspectionStage::RecordDirectories => "record_directories",
        DirectoryIdentityInspectionStage::VerifyDirectories => "verify_directories",
        DirectoryIdentityInspectionStage::RevalidateRootIdentity => "revalidate_root_identity",
        DirectoryIdentityInspectionStage::RevalidatePinnedRoot => "revalidate_pinned_root",
        DirectoryIdentityInspectionStage::UnsupportedPlatform => "unsupported_platform",
        DirectoryIdentityInspectionStage::NativeNamespaceProof => "native_namespace_proof",
        _ => "unknown",
    }
}

fn bounded_inspection_relative_path(
    path: Option<&std::path::Path>,
) -> (Option<String>, Option<&'static str>) {
    let Some(path) = path else {
        return (None, None);
    };
    if path.as_os_str().len() > quicksave_platform::MAX_PATH_BYTES {
        return (None, Some("exceeds_byte_bound"));
    }
    match path.to_str() {
        Some(path) => (Some(path.to_owned()), None),
        None => (None, Some("non_utf8_native_path")),
    }
}

#[derive(Debug)]
pub(crate) struct ScopeGrantViolation(pub &'static str);
impl fmt::Display for ScopeGrantViolation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.0)
    }
}
impl std::error::Error for ScopeGrantViolation {}

impl RootContext {
    pub(crate) fn approved(
        root: &ApprovedRoot,
        relative: Option<&str>,
        stage: &'static str,
    ) -> Self {
        Self {
            root_id: root.id.clone(),
            path: Some(root.path.clone()),
            role: root.role.clone(),
            relative: relative.map(str::to_owned),
            stage,
        }
    }
    pub(crate) fn candidate(root: &Value, stage: &'static str) -> Self {
        Self {
            root_id: root["rootId"]
                .as_str()
                .filter(|id| id.len() <= 512)
                .unwrap_or("")
                .to_owned(),
            path: root["path"]
                .as_str()
                .filter(|path| path.len() <= 32_768)
                .map(PathBuf::from),
            role: root["classification"]
                .as_str()
                .filter(|role| role.len() <= 64)
                .unwrap_or("")
                .to_owned(),
            relative: None,
            stage,
        }
    }
    pub(crate) fn run<T>(
        self,
        policy: &TrackingPolicy,
        operation: impl FnOnce() -> Result<T>,
    ) -> Result<T> {
        (|| {
            #[cfg(test)]
            policy
                .faults
                .check(self.path.as_deref(), self.relative.as_deref(), self.stage)?;
            let _ = policy;
            operation()
        })()
        .map_err(|error| self.attach(error))
    }
    pub(crate) fn attach(self, error: anyhow::Error) -> anyhow::Error {
        // Keep the innermost native operation, not a generic enclosing
        // "prepare/index root" context that would hide the useful stage/path.
        if error.downcast_ref::<Self>().is_some() {
            error
        } else {
            error.context(self)
        }
    }
}

impl fmt::Display for RootContext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "native root {} ({}) stage {}",
            self.root_id, self.role, self.stage
        )?;
        if let Some(path) = &self.path {
            write!(f, " at {}", path.display())?;
        }
        if let Some(path) = &self.relative {
            write!(f, " / {path}")?;
        }
        Ok(())
    }
}
impl std::error::Error for RootContext {}

pub(crate) fn message(error: &anyhow::Error) -> String {
    // Keep the actual failure even if a native path consumes the display
    // budget. Exact root/path/stage are separate bounded diagnostic fields.
    if error.chain().nth(1).is_none() {
        bounded_message(format_args!("{error}"))
    } else {
        bounded_message(format_args!("{}; {error:#}", error.root_cause()))
    }
}

pub(crate) fn bounded_message(args: fmt::Arguments<'_>) -> String {
    struct Limited(String);
    impl Write for Limited {
        fn write_str(&mut self, text: &str) -> fmt::Result {
            let mut count = text
                .len()
                .min(MAX_MESSAGE_BYTES.saturating_sub(self.0.len()));
            while !text.is_char_boundary(count) {
                count -= 1;
            }
            self.0.push_str(&text[..count]);
            if count < text.len() {
                Err(fmt::Error)
            } else {
                Ok(())
            }
        }
    }
    let mut output = Limited(String::new());
    let _ = output.write_fmt(args);
    output.0
}

pub(crate) fn os_error(error: &anyhow::Error) -> Option<i32> {
    for cause in error.chain() {
        if let Some(error) = cause.downcast_ref::<std::io::Error>() {
            if let Some(code) = error.raw_os_error() {
                return Some(code);
            }
        }
        #[cfg(unix)]
        if let Some(error) = cause.downcast_ref::<rustix::io::Errno>() {
            return Some(error.raw_os_error());
        }
    }
    None
}

pub(crate) fn unavailable(error: &anyhow::Error) -> bool {
    if error.downcast_ref::<AuthorityChanged>().is_some()
        || error.downcast_ref::<ScopeGrantViolation>().is_some()
        || error
            .downcast_ref::<PolicyRootFailure>()
            .is_some_and(|failure| failure.side != InspectionSide::Selected)
    {
        return false;
    }
    #[cfg(unix)]
    let native = matches!(os_error(error), Some(1 | 2 | 5 | 6 | 13 | 19 | 70 | 116));
    #[cfg(windows)]
    let native = matches!(os_error(error), Some(2 | 3 | 5 | 21 | 53 | 64 | 67 | 121));
    #[cfg(not(any(unix, windows)))]
    let native = false;
    native
        || error
            .chain()
            .filter_map(|cause| cause.downcast_ref::<std::io::Error>())
            .any(|error| {
                matches!(
                    error.kind(),
                    std::io::ErrorKind::PermissionDenied
                        | std::io::ErrorKind::NotFound
                        | std::io::ErrorKind::NotConnected
                        | std::io::ErrorKind::TimedOut
                        | std::io::ErrorKind::Interrupted
                )
            })
}

pub(crate) fn root_failure(error: &anyhow::Error) -> Option<Value> {
    let context = error.downcast_ref::<RootContext>()?;
    let mut value = json!({
        "rootId":context.root_id,"path":context.path,"role":context.role,
        "stage":context.stage,"relativePath":context.relative,"osError":os_error(error),
        "reason":bounded_message(format_args!("{}",error.root_cause())),
        "code":"native_root_index_unavailable","message":message(error),
        "preventsFullScopeCapture":true,"complete":false,
        "payloadReadability":"not_established",
    });
    if error.downcast_ref::<ScopeGrantViolation>().is_some() {
        value["code"] = json!("native_scope_grant_violation");
    }
    if error.is::<quicksave_platform::LinkOutsideLogicalRoot>() {
        value["code"] = json!("native_root_link_layout_unsupported");
    }
    if let Some(failure) = error.downcast_ref::<PolicyRootFailure>() {
        value["selectedRootPath"] = json!(failure.selected);
        value["protectedRootPath"] = json!(failure.protected);
        value["inspectionSide"] = json!(failure.side.name());
        value["stage"] = json!(failure.stage);
        if let Some(stage) = failure.native_stage {
            value["nativeInspectionStage"] = json!(native_stage_name(stage));
            value["relativePath"] = json!(failure.relative);
            if let Some(reason) = failure.relative_unavailable {
                value["relativePathUnavailableReason"] = json!(reason);
            }
        }
        value["path"] = match failure.side {
            InspectionSide::Selected => json!(failure.selected),
            InspectionSide::Protected => json!(failure.protected),
            InspectionSide::Both => Value::Null,
        };
        value["code"] = json!(if error.downcast_ref::<ScopeGrantViolation>().is_some() {
            "native_scope_grant_violation"
        } else {
            "native_policy_root_inspection_failed"
        });
    }
    Some(value)
}

#[derive(Debug)]
pub(crate) struct RootFailures(pub Vec<Value>);
impl fmt::Display for RootFailures {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "no complete native application index: {} unavailable root(s)",
            self.0.len()
        )?;
        if let Some(first) = self.0.first().and_then(|value| value["message"].as_str()) {
            write!(f, ": {first}")?;
        }
        Ok(())
    }
}
impl std::error::Error for RootFailures {}

#[derive(Debug)]
pub(crate) struct NoSelectedRoots(pub Vec<Value>);
impl fmt::Display for NoSelectedRoots {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("No independently verified roots remain in the selected roles. Installation/runtime or whole-container scopes were intentionally omitted; no bundle was created.")
    }
}
impl std::error::Error for NoSelectedRoots {}

pub(crate) fn failures(error: &anyhow::Error) -> Vec<Value> {
    if let Some(omissions) = error.downcast_ref::<NoSelectedRoots>() {
        return omissions.0.clone();
    }
    error
        .downcast_ref::<RootFailures>()
        .map(|failures| failures.0.clone())
        .unwrap_or_else(|| root_failure(error).into_iter().collect())
}

#[cfg(test)]
#[derive(Clone, Debug, Default)]
pub(crate) struct Faults(
    std::sync::Arc<
        std::sync::Mutex<std::collections::BTreeMap<(PathBuf, String, Option<String>), i32>>,
    >,
);

#[cfg(test)]
impl Faults {
    pub(crate) fn deny(&self, root: &Path, stage: &str, relative: Option<&str>, code: i32) {
        self.0.lock().unwrap().insert(
            (
                root.to_owned(),
                stage.to_owned(),
                relative.map(str::to_owned),
            ),
            code,
        );
    }
    pub(crate) fn clear(&self) {
        self.0.lock().unwrap().clear();
    }
    fn check(&self, root: Option<&Path>, relative: Option<&str>, stage: &str) -> Result<()> {
        if let Some(root) = root {
            let faults = self.0.lock().unwrap();
            let key = (
                root.to_owned(),
                stage.to_owned(),
                relative.map(str::to_owned),
            );
            if let Some(code) = faults
                .get(&key)
                .or_else(|| faults.get(&(root.to_owned(), stage.to_owned(), None)))
            {
                return Err(std::io::Error::from_raw_os_error(*code).into());
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn root_diagnostic_bounds_text_without_losing_exact_root_or_native_reason() {
        let candidate = json!({"rootId":"native-root","classification":"install",
            "path":format!("/{}", "é".repeat(4096))});
        let error = RootContext::candidate(&candidate, "approve_directory_identity")
            .attach(std::io::Error::from_raw_os_error(13).into());
        let failure = root_failure(&error).unwrap();
        assert_eq!(failure["path"], candidate["path"]);
        assert_eq!(failure["rootId"], "native-root");
        assert_eq!(failure["stage"], "approve_directory_identity");
        assert_eq!(failure["osError"], 13);
        assert!(failure["message"].as_str().unwrap().len() <= MAX_MESSAGE_BYTES);
        assert!(failure["message"].as_str().unwrap().contains("13"));
        assert!(failure["reason"].as_str().unwrap().contains("13"));
    }

    #[test]
    fn authority_failure_is_not_downgraded_to_omittable_availability() {
        let error =
            anyhow::Error::new(std::io::Error::from_raw_os_error(13)).context(AuthorityChanged);
        assert_eq!(os_error(&error), Some(13));
        assert!(!unavailable(&error));
    }

    #[test]
    fn unattributed_overlap_error_never_guesses_the_app_was_unreadable() {
        let selected = std::path::Path::new("/synthetic/selected");
        let protected = std::path::Path::new("/synthetic/protected");
        let policy = TrackingPolicy::new("/synthetic/state");
        let cause = PolicyRootFailure::new(
            selected,
            Some(protected),
            InspectionSide::Both,
            "inspect_policy_overlap",
        )
        .run(&policy, || -> Result<()> {
            Err(anyhow::Error::new(std::io::Error::from_raw_os_error(13))
                .context("selected-root directory-identity approval: inspect directories"))
        })
        .unwrap_err();
        let error = RootContext::candidate(
            &json!({
                "rootId":"candidate","path":selected,"classification":"install",
            }),
            "approve_directory_identity",
        )
        .attach(cause);
        let failure = root_failure(&error).unwrap();
        assert_eq!(failure["path"], Value::Null);
        assert_eq!(failure["inspectionSide"], "undetermined");
        assert_eq!(failure["selectedRootPath"], json!(selected));
        assert_eq!(failure["protectedRootPath"], json!(protected));
        assert!(!unavailable(&error));
    }

    #[test]
    fn native_inspection_relative_path_is_exact_or_explicitly_unavailable_never_lossy() {
        let literal = std::path::Path::new("Data:literal/known\\directory");
        assert_eq!(
            bounded_inspection_relative_path(Some(literal)),
            (Some("Data:literal/known\\directory".to_owned()), None)
        );
        let limit = "é".repeat(quicksave_platform::MAX_PATH_BYTES / 2);
        assert_eq!(
            bounded_inspection_relative_path(Some(std::path::Path::new(&limit))),
            (Some(limit.clone()), None)
        );
        assert_eq!(
            bounded_inspection_relative_path(Some(std::path::Path::new(&format!("{limit}x")))),
            (None, Some("exceeds_byte_bound"))
        );
        #[cfg(unix)]
        {
            use std::os::unix::ffi::OsStringExt;
            let native = PathBuf::from(std::ffi::OsString::from_vec(vec![b'a', 0xff]));
            assert_eq!(
                bounded_inspection_relative_path(Some(&native)),
                (None, Some("non_utf8_native_path"))
            );
        }
    }
}
