// SPDX-License-Identifier: GPL-3.0-only
fn main() {
    println!("cargo:rerun-if-changed=src/bundles/mac_inventory.m");
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("macos") {
        cc::Build::new()
            .file("src/bundles/mac_inventory.m")
            .flag("-fobjc-arc")
            .compile("quicksave_mac_inventory");
        for framework in ["Foundation", "AppKit"] {
            println!("cargo:rustc-link-lib=framework={framework}");
        }
    }
}
