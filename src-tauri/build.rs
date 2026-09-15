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

    let wireguard_candidates = match target_arch.as_str() {
        "x86_64" => {
            vec![
                "sdk/wireguard-nt/bin/amd64/wireguard.dll",
                "sdk/wireguard-nt/amd64/wireguard.dll",
                "sdk/wireguard-nt/wireguard-nt/bin/amd64/wireguard.dll",
            ]
        }
        "aarch64" => {
            vec![
                "sdk/wireguard-nt/bin/arm64/wireguard.dll",
                "sdk/wireguard-nt/arm64/wireguard.dll",
                "sdk/wireguard-nt/wireguard-nt/bin/arm64/wireguard.dll",
            ]
        }
        other => panic!("Unsupported architecture: {}", other),
    };

    copy_dll_if_exists(
        &manifest_dir,
        &resources_dir,
        "wireguard.dll",
        &wireguard_candidates,
    );

    // Build Tauri configuration (does NOT fail if DLLs are missing)
    tauri_build::build();

    // On Windows, embed the application manifest that requests Administrator
    // elevation (requireAdministrator).  This is REQUIRED for WireGuard-NT
    // driver installation via WireGuardCreateAdapter -> DriverInstall ->
    // SetupCopyOEMInfW.  Without this manifest, the Windows loader will NOT
    // show a UAC prompt and the app will silently run unprivileged — driver
    // installation will then fail with ERROR_ACCESS_DENIED (5).
    //
    // Implementation:
    // - We pass /MANIFESTUAC:requireAdministrator to the MSVC linker as a
    //   best-effort (works when the linker honours it; may be overridden by
    //   Tauri's build system).
    // - We also deploy a <binary>.exe.manifest file in the target directory.
    //   Windows auto-loads <binary>.exe.manifest from the binary's directory
    //   at process startup, providing a reliable fallback.
    // - For production builds, run `embed_manifest.bat` (see docs/) after
    //   `tauri build` completes.  This uses mt.exe to embed the manifest
    //   directly into the PE as an RT_MANIFEST resource.
    #[cfg(target_os = "windows")]
    {
        // Best-effort: linker flag
        println!("cargo:rustc-link-arg=/MANIFESTUAC:YES,level=requireAdministrator,uiAccess=false");
        println!(
            "cargo:warning=Manifest UAC: /MANIFESTUAC:requireAdministrator (best-effort linker flag)"
        );

        // Reliable fallback: deploy <binary>.exe.manifest alongside the binary.
        // On Windows, the binary name preserves hyphens (e.g., marstart-link.exe).
        let pkg_name = env::var("CARGO_PKG_NAME").unwrap_or_else(|_| "marstart-link".to_string());
        let manifest_src = manifest_dir.join("src-tauri.manifest");

        let out_dir_str = std::env::var("OUT_DIR").unwrap_or_else(|_| ".".to_string());
        let out_dir = Path::new(&out_dir_str);

        // Copy to OUT_DIR
        let _ = std::fs::copy(
            &manifest_src,
            out_dir.join(format!("{}.exe.manifest", pkg_name)),
        );

        // Copy to target dir (3 levels up from OUT_DIR/build/pkg-hash/out)
        let target_dir = out_dir.join("..").join("..").join("..");
        let dest = target_dir.join(format!("{}.exe.manifest", pkg_name));
        if let Err(e) = std::fs::copy(&manifest_src, &dest) {
            println!("cargo:warning=Failed to copy .exe.manifest: {e}");
        } else {
            println!(
                "cargo:warning=Manifest deployed to {}.exe.manifest (Windows auto-loads this at startup)",
                pkg_name
            );
        }

        // Write a helper script for production post-link manifest embedding
        let helper = manifest_dir.join("embed_manifest.bat");
        let helper_content = format!(
            "@echo off\r\n\
             REM Embeds requireAdministrator manifest into the MARSTART LINK binary.\r\n\
             REM Run AFTER `tauri build` completes.\r\n\
             REM Usage: embed_manifest.bat <path_to_exe>\r\n\
             set \"MT=\"\r\n\
             for /f \"delims=\" %%i in ('dir /b /s \"C:\\Program Files (x86)\\Windows Kits\\10\\bin\\*\\x64\\mt.exe\" 2^>nul') do set \"MT=%%i\"\r\n\
             if not defined MT (\r\n\
             echo ERROR: mt.exe not found under Windows Kits\\10\\bin -- install the Windows SDK (Desktop Build Tools)\r\n\
             exit /b 1\r\n\
             )\r\n\
             if \"%~1\"==\"\" (\r\n\
             echo Usage: embed_manifest.bat ^<path_to_exe^>\r\n\
             exit /b 1\r\n\
             )\r\n\
             %MT% -manifest \"{}\" -outputresource:\"%~1;#1\" -nologo\r\n\
             if errorlevel 1 (\r\n\
             echo ERROR: mt.exe failed\r\n\
             exit /b 1\r\n\
             )\r\n\
             echo Manifest embedded successfully: requireAdministrator\r\n",
            manifest_src.display()
        );
        let _ = std::fs::write(&helper, helper_content);
        println!(
            "cargo:warning=Helper script: {} (run after tauri build for production manifest embedding)",
            helper.display()
        );
    }

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
