// SPDX-License-Identifier: GPL-3.0-only
//! Windows tracking uses the audited fork's safe, handle-relative native
//! metadata API. No snapshot-copy/lifecycle/remote API is invoked here.

use super::{
    validate_absolute, validate_relative, AuthorityChanged, FileStamp, NativeMetadata, RootIdentity,
};
use crate::model::{WindowsMetadata, WindowsMetadataPlatform};
use anyhow::{ensure, Context, Result};
use noland_snapshot::{
    NativeEntryKind, NativeIdentity, SourcePath, WindowsMetadata as ObservedMetadata,
};
use std::{
    fs::File,
    path::{Path, PathBuf},
};

pub(super) struct Anchor {
    path: PathBuf,
    source: SourcePath,
    handle: File,
    identity: RootIdentity,
    ancestors: Vec<RootIdentity>,
}

fn root_identity(identity: NativeIdentity) -> RootIdentity {
    RootIdentity {
        device: identity.volume,
        file_id: identity.file_id,
    }
}

fn native_identity(identity: &RootIdentity) -> NativeIdentity {
    NativeIdentity {
        volume: identity.device,
        file_id: identity.file_id,
    }
}

fn stamp(metadata: &ObservedMetadata) -> Result<FileStamp> {
    let native_time = |ticks: i64| -> Result<(i64, u32)> {
        let seconds = ticks
            .div_euclid(10_000_000)
            .checked_sub(11_644_473_600)
            .context("Windows native timestamp exceeds representable range")?;
        Ok((seconds, ticks.rem_euclid(10_000_000) as u32 * 100))
    };
    let modified = native_time(metadata.last_write_time)?;
    let changed = native_time(metadata.change_time)?;
    Ok(FileStamp {
        device: metadata.identity.volume,
        file_id: metadata.identity.file_id,
        size: metadata.size,
        modified_seconds: modified.0,
        modified_nanoseconds: modified.1,
        changed_seconds: changed.0,
        changed_nanoseconds: changed.1,
    })
}

fn required_metadata(metadata: &ObservedMetadata) -> NativeMetadata {
    NativeMetadata::Windows(WindowsMetadata {
        platform: WindowsMetadataPlatform::Windows,
        identity: root_identity(metadata.identity),
        kind: match metadata.kind {
            NativeEntryKind::File => quicksave_platform::EntryKind::File,
            NativeEntryKind::Directory => quicksave_platform::EntryKind::Directory,
            NativeEntryKind::Symlink => quicksave_platform::EntryKind::Symlink,
        },
        size: metadata.size,
        creation_time: metadata.creation_time,
        last_access_time: metadata.last_access_time,
        last_write_time: metadata.last_write_time,
        change_time: metadata.change_time,
        attributes: metadata.attributes,
        link_count: metadata.number_of_links,
        reparse_tag: metadata.reparse_tag,
    })
}

impl Anchor {
    pub(super) fn open(path: &Path) -> Result<Self> {
        validate_absolute(path)?;
        let source = SourcePath::new(path)?;
        let handle = source.open_directory()?;
        let observed = ObservedMetadata::from_file(&handle)?;
        ensure!(
            observed.kind == NativeEntryKind::Directory,
            "native root is not a real directory"
        );
        let identity = root_identity(observed.identity);
        // SourcePath already retains/rechecks every ancestor without delete
        // sharing. Collect their *real* full IDs to prove direction/alias
        // containment, including case-equivalent or short-name spellings.
        let mut ancestors = Vec::new();
        for ancestor in path
            .ancestors()
            .filter(|ancestor| ancestor.parent().is_some())
        {
            ensure!(
                ancestors.len() < 128,
                "native root ancestor count exceeds bound"
            );
            let directory = SourcePath::new(ancestor)?.open_directory()?;
            let native = ObservedMetadata::from_file(&directory)?;
            ensure!(
                native.kind == NativeEntryKind::Directory,
                "native ancestor is not a directory"
            );
            ancestors.push(root_identity(native.identity));
        }
        let anchor = Self {
            path: path.to_owned(),
            source,
            handle,
            identity,
            ancestors,
        };
        anchor.check()?;
        Ok(anchor)
    }

    pub(super) fn identity(&self) -> RootIdentity {
        self.identity.clone()
    }

    pub(super) fn inside(&self, other: &Self) -> bool {
        self.ancestors
            .iter()
            .any(|identity| identity == &other.identity)
    }

    pub(super) fn check(&self) -> Result<()> {
        let held = ObservedMetadata::from_file(&self.handle)?;
        let named = self.source.native_metadata()?;
        ensure!(
            held.kind == NativeEntryKind::Directory
                && named.kind == NativeEntryKind::Directory
                && root_identity(held.identity) == self.identity
                && root_identity(named.identity) == self.identity,
            AuthorityChanged
        );
        Ok(())
    }

    pub(super) fn metadata(
        &self,
        relative: Option<&str>,
        expected: Option<&FileStamp>,
    ) -> Result<NativeMetadata> {
        self.check()?;
        let native = if let Some(relative) = relative {
            validate_relative(relative)?;
            SourcePath::new_beneath_native(
                &self.path.join(relative),
                &self.path,
                native_identity(&self.identity),
            )?
            .native_metadata()?
        } else {
            self.source.native_metadata()?
        };
        if let Some(expected) = expected {
            ensure!(
                &stamp(&native)? == expected,
                "Windows no-follow metadata stamp changed"
            );
        }
        let value = required_metadata(&native);
        value.validate(
            match native.kind {
                NativeEntryKind::File => "file",
                NativeEntryKind::Directory => "directory",
                NativeEntryKind::Symlink => "symlink",
            },
            Some(&stamp(&native)?),
        )?;
        self.check()?;
        Ok(value)
    }

    pub(super) fn root_stamp(&self) -> Result<FileStamp> {
        self.check()?;
        let native = self.source.native_metadata()?;
        ensure!(
            native.kind == NativeEntryKind::Directory
                && root_identity(native.identity) == self.identity,
            AuthorityChanged
        );
        let value = stamp(&native)?;
        self.check()?;
        Ok(value)
    }

    pub(super) fn trusted_change_stamps(&self) -> Result<bool> {
        self.check()?;
        // Native notify alone is not a USN/change-journal proof. Until that
        // receipt is integrated, Windows performs real source capture instead
        // of pretending unchanged bytes from matching times/event silence.
        Ok(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn real_windows_handles_agree_on_full_root_and_leaf_metadata() {
        let temporary = tempfile::tempdir().unwrap();
        // Canonicalize ONLY this isolated fixture, never a real user path.
        let sandbox = std::fs::canonicalize(temporary.path()).unwrap();
        let path = sandbox.join("approved");
        std::fs::create_dir(&path).unwrap();
        std::fs::write(path.join("data"), b"native Windows fixture").unwrap();
        let root = Anchor::open(&path).unwrap();
        let safe = quicksave_platform::SafeRoot::open(&path).unwrap();
        let identity = safe.identity().unwrap();
        assert_eq!(
            root.identity(),
            RootIdentity {
                device: identity.device,
                file_id: identity.file_id
            }
        );
        let (_, observed) = safe.read_file("data").unwrap();
        let metadata = root.metadata(Some("data"), Some(&observed)).unwrap();
        let NativeMetadata::Windows(metadata) = metadata else {
            panic!("Windows metadata cannot use UID/GID");
        };
        assert_eq!(metadata.identity.file_id, observed.file_id);
        assert_eq!(metadata.stamp().unwrap(), observed);
        assert_eq!(root.root_stamp().unwrap().file_id, identity.file_id);
        assert!(!root.trusted_change_stamps().unwrap());
        let parent = Anchor::open(&sandbox).unwrap();
        assert!(root.inside(&parent));
        assert!(!parent.inside(&root));
        assert!(root.metadata(Some("../outside"), None).is_err());
        root.check().unwrap();
    }
}
