// src-tauri/build.rs

use std::env;
use std::fs;
use std::path::{Path, PathBuf};

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=src-tauri.manifest");
    println!("cargo:rerun-if-changed=tauri.conf.json");
    println!("cargo:rerun-if-changed=icons");
    println!("cargo:rerun-if-changed=resources");

    let target_arch = env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_else(|_| "x86_64".to_string());

    let manifest_dir =
        PathBuf::from(env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR is not set"));

    println!("cargo:warning=Manifest dir: {}", manifest_dir.display());
    println!("cargo:warning=Target architecture: {}", target_arch);

    let resources_dir = manifest_dir.join("resources");
    fs::create_dir_all(&resources_dir).expect("Failed to create resources directory");

    println!("cargo:warning=Resources dir: {}", resources_dir.display());

    let (wireguard_candidates, wintun_candidates) = match target_arch.as_str() {
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
        other => panic!("Unsupported architecture: {}", other),
    };

    copy_dll_if_exists(
        &manifest_dir,
        &resources_dir,
        "wireguard.dll",
        &wireguard_candidates,
    );
    copy_dll_if_exists(
        &manifest_dir,
        &resources_dir,
        "wintun.dll",
        &wintun_candidates,
    );

    // Build Tauri configuration (does NOT fail if DLLs are missing)
    tauri_build::build();

    println!("cargo:warning=build.rs completed successfully");
}

fn copy_dll_if_exists(
    manifest_dir: &Path,
    resources_dir: &Path,
    dll_name: &str,
    candidates: &[&str],
) {
    for rel_path in candidates {
        let src = manifest_dir.join(rel_path);
        println!("cargo:warning=Checking {} at {}", dll_name, src.display());

        if src.exists() {
            let dest = resources_dir.join(dll_name);
            match fs::copy(&src, &dest) {
                Ok(_) => {
                    println!("cargo:warning=Copied {} from {}", dll_name, src.display());
                    return;
                }
                Err(e) => {
                    println!(
                        "cargo:warning=Failed to copy {} from {}: {}",
                        dll_name,
                        src.display(),
                        e
                    );
                    // Continue to next candidate
                    continue;
                }
            }
        }
    }

    println!(
        "cargo:warning={} not found in SDK paths. It will be downloaded in CI.",
        dll_name
    );
}
