//! CRIT-5 fix: Secure key storage via Windows Credential Manager.

use keyring::Entry;
use base64::Engine;  // <-- добавить

const KEYRING_SERVICE: &str = "game-accelerator-wg-key";

#[tauri::command]
pub fn keyring_set(profile_id: String, private_key: String) -> Result<(), String> {
    if private_key.is_empty() {
        return Err("private_key must not be empty".into());
    }

    let decoded = base64::engine::general_purpose::STANDARD
        .decode(private_key.trim())
        .map_err(|e| format!("Invalid Base64 private key: {e}"))?;
    if decoded.len() != 32 {
        return Err(format!(
            "Private key must decode to 32 bytes, got {}",
            decoded.len()
        ));
    }

    let entry = Entry::new(KEYRING_SERVICE, &profile_id)
        .map_err(|e| format!("keyring::Entry::new failed: {e}"))?;
    entry
        .set_password(private_key.trim())
        .map_err(|e| format!("keyring set_password failed: {e}"))?;

    tracing::info!(profile_id = %profile_id, "Private key stored in OS credential manager");
    Ok(())
}

#[tauri::command]
pub fn keyring_get(profile_id: String) -> Result<String, String> {
    let entry = Entry::new(KEYRING_SERVICE, &profile_id)
        .map_err(|e| format!("keyring::Entry::new failed: {e}"))?;
    let key = entry
        .get_password()
        .map_err(|e| format!("keyring get_password failed (profile not found?): {e}"))?;
    Ok(key)
}

#[tauri::command]
pub fn keyring_delete(profile_id: String) -> Result<(), String> {
    let entry = Entry::new(KEYRING_SERVICE, &profile_id)
        .map_err(|e| format!("keyring::Entry::new failed: {e}"))?;
    match entry.delete_password() {   // <-- исправлено
        Ok(_) => {
            tracing::info!(profile_id = %profile_id, "Private key removed from OS credential manager");
            Ok(())
        }
        Err(keyring::Error::NoEntry) => Ok(()),
        Err(e) => Err(format!("keyring delete_password failed: {e}")),
    }
}