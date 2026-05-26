use std::{env, fs, path::PathBuf};

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=src-tauri.manifest");

    let target_arch = env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_default();
    let manifest_dir = PathBuf::from(
        env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR is not set")
    );

    let (wg_dll, wintun_dll) = match target_arch.as_str() {
        "x86_64" => (
            "sdk/wireguard-nt/bin/amd64/wireguard.dll",
            "sdk/wintun/bin/amd64/wintun.dll",
        ),
        "aarch64" => (
            "sdk/wireguard-nt/arm64/wireguard.dll",
            "sdk/wintun/arm64/wintun.dll",
        ),
        _ => panic!("Unsupported architecture: {}", target_arch),
    };

    let resources_dir = manifest_dir.join("resources");
    fs::create_dir_all(&resources_dir).expect("Failed to create resources dir");

    for (src_rel, name) in [(wg_dll, "wireguard.dll"), (wintun_dll, "wintun.dll")] {
        let src_path = manifest_dir.join(src_rel);
        let dest_path = resources_dir.join(name);

        if src_path.exists() {
            fs::copy(&src_path, &dest_path).expect(&format!("Failed to copy {}", name));
            println!("cargo:warning=Copied {} to resources", name);
        } else {
            println!("cargo:warning=DLL not found at {}. Run SDK fetch.", src_path.display());
        }
    }

    let mut res = winres::WindowsResource::new();
    res.set_manifest_file("src-tauri.manifest");
    res.compile().expect("Failed to compile manifest");
}