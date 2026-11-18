// SPDX-License-Identifier: GPL-3.0-only

fn main() {
    let manifest = tauri_build::AppManifest::new().commands(&[
        "workspace_query",
        "workspace_prepare",
        "workspace_execute",
    ]);
    tauri_build::try_build(tauri_build::Attributes::new().app_manifest(manifest))
        .expect("QuickSave command permission generation failed");
}
