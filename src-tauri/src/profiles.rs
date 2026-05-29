//! CRIT-5 fix: Secure key storage via Windows Credential Manager.
//!
//! Private keys MUST NOT be stored in WebView localStorage (plaintext JSON).
//! This module provides Tauri IPC commands that front-end uses instead.
//!
//! Storage model:
//!   - Profile metadata (name, endpoint, address, allowedIps, dnsServers, publicKey)
//!     → stored by the front-end in localStorage (not a secret).
//!   - PrivateKey                                              
//!     → stored in Windows Credential Manager via `keyring` crate.
//!     The JS side stores only the profile ID, never the key bytes.

use keyring::Entry;

/// Service name used as the "target" in Windows Credential Manager.
const KEYRING_SERVICE: &str = "game-accelerator-wg-key";

// ============================================================================
// Tauri IPC Commands
// ============================================================================

/// Store a WireGuard private key (Base64) in the OS credential manager.
/// Called from JS when the user saves a profile.
/// The profile ID is used as the username/account name in the vault entry.
#[tauri::command]
pub fn keyring_set(profile_id: String, private_key: String) -> Result<(), String> {
    if private_key.is_empty() {
        return Err("private_key must not be empty".into());
    }

    // Basic sanity: key must be 32-byte Base64
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

/// Retrieve the WireGuard private key (Base64) from the OS credential manager.
/// Returns an error string if the key was not previously saved.
#[tauri::command]
pub fn keyring_get(profile_id: String) -> Result<String, String> {
    let entry = Entry::new(KEYRING_SERVICE, &profile_id)
        .map_err(|e| format!("keyring::Entry::new failed: {e}"))?;
    let key = entry
        .get_password()
        .map_err(|e| format!("keyring get_password failed (profile not found?): {e}"))?;
    Ok(key)
}

/// Delete a stored key when the user removes a profile.
#[tauri::command]
pub fn keyring_delete(profile_id: String) -> Result<(), String> {
    let entry = Entry::new(KEYRING_SERVICE, &profile_id)
        .map_err(|e| format!("keyring::Entry::new failed: {e}"))?;
    // If the entry doesn't exist, that's not an error for deletion.
    match entry.delete_credential() {
        Ok(_) => {
            tracing::info!(profile_id = %profile_id, "Private key removed from OS credential manager");
            Ok(())
        }
        Err(keyring::Error::NoEntry) => Ok(()), // already gone
        Err(e) => Err(format!("keyring delete_password failed: {e}")),
    }
}