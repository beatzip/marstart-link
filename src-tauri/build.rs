use std::{env, fs, path::PathBuf};

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=src-tauri.manifest");

    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let resources_dir = manifest_dir.join("resources");
    fs::create_dir_all(&resources_dir).expect("Failed to create resources dir");

    // === Скачиваем SDK автоматически, если их нет ===
    download_sdk_if_missing(&manifest_dir);

    // Пути после скачивания
    let wireguard_src = resources_dir.join("wireguard.dll");
    let wintun_src = resources_dir.join("wintun.dll");

    if !wireguard_src.exists() || !wintun_src.exists() {
        panic!("DLL files not found even after download attempt");
    }

    // Копируем в resources (для бандла)
    fs::copy(&wireguard_src, resources_dir.join("wireguard.dll"))
        .expect("Failed to copy wireguard.dll");
    fs::copy(&wintun_src, resources_dir.join("wintun.dll"))
        .expect("Failed to copy wintun.dll");

    // Windows manifest
    let mut res = winres::WindowsResource::new();
    res.set_manifest_file("src-tauri.manifest");
    res.compile().expect("Failed to compile Windows resources");

    println!("cargo:warning=build.rs completed successfully");
}

// Автоматическая загрузка SDK
fn download_sdk_if_missing(manifest_dir: &PathBuf) {
    let sdk_dir = manifest_dir.join("sdk");
    let wireguard_dll = sdk_dir.join("wireguard-nt/bin/amd64/wireguard.dll");

    if wireguard_dll.exists() {
        return; // уже есть
    }

    println!("cargo:warning=SDK not found. Downloading...");

    std::fs::create_dir_all(&sdk_dir).ok();

    // WireGuard-NT
    let wg_zip = sdk_dir.join("wireguard-nt.zip");
    let _ = reqwest::blocking::get("https://download.wireguard.com/wireguard-nt/wireguard-nt-1.1.zip")
        .expect("Failed to download wireguard-nt")
        .copy_to(&mut std::fs::File::create(&wg_zip).unwrap());

    zip_extract::extract(std::fs::File::open(&wg_zip).unwrap(), &sdk_dir, true).ok();

    // Wintun
    let wintun_zip = sdk_dir.join("wintun.zip");
    let _ = reqwest::blocking::get("https://www.wintun.net/builds/wintun-0.14.1.zip")
        .expect("Failed to download wintun")
        .copy_to(&mut std::fs::File::create(&wintun_zip).unwrap());

    zip_extract::extract(std::fs::File::open(&wintun_zip).unwrap(), &sdk_dir, true).ok();

    println!("cargo:warning=SDKs downloaded successfully");
}