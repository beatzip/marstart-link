```rust
use std::{env, fs, path::PathBuf};

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=src-tauri.manifest");

    let target_arch =
        env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_else(|_| "x86_64".into());

    let manifest_dir = PathBuf::from(
        env::var("CARGO_MANIFEST_DIR")
            .expect("CARGO_MANIFEST_DIR is not set"),
    );

    println!(
        "cargo:warning=Manifest dir: {}",
        manifest_dir.display()
    );

    println!(
        "cargo:warning=Target architecture: {}",
        target_arch
    );

    // ---------------------------------------------------------
    // SDK DLL paths
    // ---------------------------------------------------------

    let (wg_candidates, wintun_candidates): (Vec<&str>, Vec<&str>) =
        match target_arch.as_str() {
            "x86_64" => (
                vec![
                    "sdk/wireguard-nt/bin/amd64/wireguard.dll",
                    "sdk/wireguard-nt/amd64/wireguard.dll",
                    "sdk/wireguard-nt/wireguard-nt/bin/amd64/wireguard.dll",
                ],
                vec![
                    "sdk/wintun/bin/amd64/wintun.dll",
                    "sdk/wintun/amd64/wintun.dll",
                    "sdk/wintun/wintun/bin/amd64/wintun.dll",
                ],
            ),

            "aarch64" => (
                vec![
                    "sdk/wireguard-nt/bin/arm64/wireguard.dll",
                    "sdk/wireguard-nt/arm64/wireguard.dll",
                    "sdk/wireguard-nt/wireguard-nt/bin/arm64/wireguard.dll",
                ],
                vec![
                    "sdk/wintun/bin/arm64/wintun.dll",
                    "sdk/wintun/arm64/wintun.dll",
                    "sdk/wintun/wintun/bin/arm64/wintun.dll",
                ],
            ),

            other => {
                panic!("Unsupported architecture: {}", other);
            }
        };

    // ---------------------------------------------------------
    // Resources dir
    // ---------------------------------------------------------

    let resources_dir = manifest_dir.join("resources");

    fs::create_dir_all(&resources_dir)
        .expect("Failed to create resources directory");

    println!(
        "cargo:warning=Resources dir: {}",
        resources_dir.display()
    );

    // ---------------------------------------------------------
    // Copy helper
    // ---------------------------------------------------------

    fn copy_first_existing(
        manifest_dir: &PathBuf,
        candidates: &[&str],
        dest: &PathBuf,
        label: &str,
    ) {
        for rel in candidates {
            let src = manifest_dir.join(rel);

            println!(
                "cargo:warning=Checking {} at {}",
                label,
                src.display()
            );

            if src.exists() {
                fs::copy(&src, dest)
                    .unwrap_or_else(|e| {
                        panic!(
                            "Failed to copy {} from {}: {}",
                            label,
                            src.display(),
                            e
                        )
                    });

                println!(
                    "cargo:warning=Copied {} from {}",
                    label,
                    src.display()
                );

                return;
            }
        }

        panic!(
            "{} not found in any expected SDK path",
            label
        );
    }

    // ---------------------------------------------------------
    // Copy WireGuard DLL
    // ---------------------------------------------------------

    copy_first_existing(
        &manifest_dir,
        &wg_candidates,
        &resources_dir.join("wireguard.dll"),
        "wireguard.dll",
    );

    // ---------------------------------------------------------
    // Copy Wintun DLL
    // ---------------------------------------------------------

    copy_first_existing(
        &manifest_dir,
        &wintun_candidates,
        &resources_dir.join("wintun.dll"),
        "wintun.dll",
    );

    // ---------------------------------------------------------
    // Windows manifest
    // ---------------------------------------------------------

    let mut res = winres::WindowsResource::new();

    res.set_manifest_file("src-tauri.manifest");

    res.compile()
        .expect("Failed to compile Windows resources");

    println!("cargo:warning=build.rs completed successfully");
}
```
