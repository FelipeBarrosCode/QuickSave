// SPDX-License-Identifier: GPL-3.0-only

fn main() {
    let manifest = tauri_build::AppManifest::new().commands(&[
        "get_capabilities",
        "get_directories",
        "discover_applications",
        "authorize_operation",
        "initialize_repository",
        "backup_folder",
        "list_snapshots",
        "restore_snapshot",
        "operation_status",
        "operation_history",
    ]);
    tauri_build::try_build(tauri_build::Attributes::new().app_manifest(manifest))
        .expect("QuickSave command permission generation failed");
}
