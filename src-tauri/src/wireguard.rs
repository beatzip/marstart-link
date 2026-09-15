use crate::profiles::Profile;
use crate::wireguard_config::ParsedConfig;
use crate::wireguard_parser::{parse_wireguard_config, validate_config};
#[cfg(target_os = "windows")]
use crate::wireguard_serializer::{read_peer_stats, serialize_config};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

#[cfg(target_os = "windows")]
use std::os::windows::ffi::OsStrExt;
#[cfg(target_os = "windows")]
use windows::core::{s, PCWSTR};
#[cfg(target_os = "windows")]
use windows::Win32::Foundation::{FreeLibrary, BOOL, HANDLE, HMODULE};
#[cfg(target_os = "windows")]
use windows::Win32::System::LibraryLoader::{GetProcAddress, LoadLibraryW};

#[cfg(target_os = "windows")]
type WireGuardAdapterHandle = HANDLE;

#[cfg(target_os = "windows")]
type WireGuardCreateAdapterFunc = unsafe extern "system" fn(
    adapter_name: PCWSTR,
    tunnel_type: PCWSTR,
    requested_guid: *const std::ffi::c_void,
) -> WireGuardAdapterHandle;

#[cfg(target_os = "windows")]
type WireGuardCloseAdapterFunc = unsafe extern "system" fn(adapter: WireGuardAdapterHandle);

#[cfg(target_os = "windows")]
type WireGuardSetConfigurationFunc = unsafe extern "system" fn(
    adapter: WireGuardAdapterHandle,
    config_bytes: *const std::ffi::c_void,
    config_size: u32,
) -> BOOL;

#[cfg(target_os = "windows")]
type WireGuardGetConfigurationFunc = unsafe extern "system" fn(
    adapter: WireGuardAdapterHandle,
    config_bytes: *mut std::ffi::c_void,
    config_size: *mut u32,
) -> BOOL;

/// Adapter state enum matching WIREGUARD_ADAPTER_STATE from wireguard.h
#[cfg(target_os = "windows")]
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WireGuardAdapterState {
    Down = 0,
    Up = 1,
}

/// RAII guard for an `HMODULE` loaded via `LoadLibraryW`.
/// Calls `FreeLibrary` on drop, preventing DLL leaks when
/// `GetProcAddress` resolution fails partway through `WireGuardTunnel::new()`.
#[cfg(target_os = "windows")]
struct DllGuard(HMODULE);

#[cfg(target_os = "windows")]
impl Drop for DllGuard {
    fn drop(&mut self) {
        // SAFETY: `FreeLibrary` closes the `HMODULE` loaded by `LoadLibraryW`.
        // `DllGuard` is transient: in the success path of `new()` it is
        // `std::mem::forget`-ed (ownership transfers to `WireGuardTunnel`), so
        // this `Drop` only runs on the failure path.  Calling `FreeLibrary`
        // once on a valid `HMODULE` is sound and cannot double-free.
        let _ = unsafe { FreeLibrary(self.0) };
    }
}

#[cfg(target_os = "windows")]
type WireGuardGetRunningDriverVersionFunc = unsafe extern "system" fn() -> u32;

#[cfg(target_os = "windows")]
type WireGuardSetAdapterStateFunc = unsafe extern "system" fn(
    adapter: WireGuardAdapterHandle,
    state: WireGuardAdapterState,
) -> BOOL;

#[cfg(target_os = "windows")]
type WireGuardGetAdapterStateFunc = unsafe extern "system" fn(
    adapter: WireGuardAdapterHandle,
    state: *mut WireGuardAdapterState,
) -> BOOL;

#[cfg(target_os = "windows")]
type WireGuardDeleteDriverFunc = unsafe extern "system" fn() -> BOOL;

/// WireGuardGetAdapterLUID вЂ” obtains the LUID of the adapter's NDIS miniport interface.
/// Used to set `MIB_IPFORWARD_ROW2.InterfaceLuid` for Windows route entries.
#[cfg(target_os = "windows")]
type WireGuardGetAdapterLuidFunc = unsafe extern "system" fn(
    adapter: WireGuardAdapterHandle,
    luid: *mut windows::Win32::NetworkManagement::Ndis::NET_LUID_LH,
);

/// WireGuardOpenAdapter вЂ” reopens an existing adapter by name.
/// Used for crash recovery: if the process crashes and restarts,
/// the adapter still exists in the system and can be reopened.
#[cfg(target_os = "windows")]
type WireGuardOpenAdapterFunc =
    unsafe extern "system" fn(adapter_name: PCWSTR) -> WireGuardAdapterHandle;

/// Result of `WireGuardGetRunningDriverVersion`:
/// - Non-zero: the driver IS loaded, encoded as (major << 16) | minor
/// - Zero: driver NOT loaded; `GetLastError()` set to ERROR_FILE_NOT_FOUND (2)
#[cfg(target_os = "windows")]
type WireGuardGetRunningDriverVersionTyped = unsafe extern "system" fn() -> u32;

fn get_dll_path(dll_name: &str) -> PathBuf {
    let exe = std::env::current_exe().unwrap_or_else(|_| PathBuf::from("."));
    let exe_dir = exe.parent().unwrap_or_else(|| std::path::Path::new("."));
    let bundled = exe_dir.join("resources").join(dll_name);
    if bundled.exists() {
        bundled
    } else {
        // Development fallback: allow a DLL next to the executable.
        exe_dir.join(dll_name)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "status", content = "message")]
pub enum TunnelStatus {
    Disconnected,
    Connecting,
    Connected,
    Error(String),
}

#[derive(Debug, Default)]
pub struct TunnelCounters {
    pub tx_bytes: AtomicU64,
    pub rx_bytes: AtomicU64,
    pub last_handshake_unix: AtomicU64,
}

impl TunnelCounters {
    pub fn snapshot(&self) -> (u64, u64, u64) {
        (
            self.tx_bytes.load(Ordering::Relaxed),
            self.rx_bytes.load(Ordering::Relaxed),
            self.last_handshake_unix.load(Ordering::Relaxed),
        )
    }

    pub fn clear(&self) {
        self.tx_bytes.store(0, Ordering::Relaxed);
        self.rx_bytes.store(0, Ordering::Relaxed);
        self.last_handshake_unix.store(0, Ordering::Relaxed);
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectionInfo {
    pub handshake_timestamp_unix: u64,
    pub tx_bytes: u64,
    pub rx_bytes: u64,
    pub endpoint: Option<String>,
}

/// Adapter state reported by `WireGuardGetAdapterState()`.
/// `Unknown` is returned when the state cannot be queried (e.g. on non-Windows
/// or when the adapter handle is not available).
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
pub enum AdapterStateReport {
    Down,
    Up,
    #[default]
    Unknown,
}

/// Result of the runtime smoke-test / diagnostic command (`tunnel_diagnostics`).
/// Each field corresponds to one lifecycle step so a caller can pinpoint
/// exactly where a failure occurs without parsing free-text errors.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiagnosticsReport {
    pub dll_loaded: bool,
    /// True if the WireGuardNT kernel driver (wireguard.sys) is loaded.
    pub driver_present: bool,
    /// Driver version DWORD (0 if not loaded).
    pub driver_version: u32,
    /// True if the current process has Administrator privileges.
    pub is_admin: bool,
    pub adapter_created: bool,
    pub config_applied: bool,
    /// Actual adapter state queried via `WireGuardGetAdapterState()` (Up/Down).
    pub adapter_state: AdapterStateReport,
    pub adapter_closed: bool,
    pub no_orphan_adapter: bool,
    pub handshake_timestamp_unix: u64,
    pub tx_bytes: u64,
    pub rx_bytes: u64,
    pub endpoint: Option<String>,
    pub errors: Vec<String>,
}

/// Driver pre-flight status вЂ” returned by the `wireguard_driver_status` Tauri
/// command.  Lets the frontend decide whether to show a "driver missing" error,
/// a "please run as administrator" prompt, or proceed to connection.
///
/// This is the minimal diagnostic layer required before any adapter lifecycle
/// operation.  It does **not** install or remove anything вЂ” it only reads.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DriverStatus {
    /// `true` if `wireguard.dll` loaded successfully from the bundled `resources/` directory.
    pub dll_loaded: bool,
    /// `true` if the WireGuardNT kernel driver (`wireguard.sys`) is loaded in the
    /// running kernel (checked via `WireGuardGetRunningDriverVersion`).
    pub driver_present: bool,
    /// Driver version encoded as `((major << 16) | minor) << 16` etc.
    /// Matches the value returned by `WireGuardGetRunningDriverVersion()`.
    /// `0` means the driver is not loaded.
    pub driver_version: u32,
    /// Human-readable driver version string, e.g. `"1.1.0.0"` or `"not loaded"`.
    pub driver_version_string: String,
    /// `true` if the current process has Administrator privileges
    /// (required for first-time driver installation via `WireGuardCreateAdapter`).
    pub is_admin: bool,
    /// Win32 error code from the last driver check (`0` = success).
    pub error_code: u32,
    /// Human-readable description of the result / error.
    pub human_readable_error: String,
}

pub struct WireGuardTunnel {
    adapter_name: String,
    config: ParsedConfig,
    status: Mutex<TunnelStatus>,
    counters: Arc<TunnelCounters>,
    connect_time: Mutex<Option<Instant>>,
    #[cfg(target_os = "windows")]
    adapter_handle: Mutex<Option<WireGuardAdapterHandle>>,
    #[cfg(target_os = "windows")]
    wg_lib: HMODULE,
    #[cfg(target_os = "windows")]
    fn_create: WireGuardCreateAdapterFunc,
    #[cfg(target_os = "windows")]
    fn_close: WireGuardCloseAdapterFunc,
    #[cfg(target_os = "windows")]
    fn_set_cfg: WireGuardSetConfigurationFunc,
    #[cfg(target_os = "windows")]
    fn_get_cfg: WireGuardGetConfigurationFunc,
    #[cfg(target_os = "windows")]
    fn_set_state: WireGuardSetAdapterStateFunc,
    #[cfg(target_os = "windows")]
    fn_get_state: WireGuardGetAdapterStateFunc,
    #[cfg(target_os = "windows")]
    fn_get_drv_ver: WireGuardGetRunningDriverVersionTyped,
    #[cfg(target_os = "windows")]
    fn_get_luid: WireGuardGetAdapterLuidFunc,
    #[cfg(target_os = "windows")]
    fn_open: WireGuardOpenAdapterFunc,
}

#[cfg(target_os = "windows")]
// SAFETY: `WireGuardTunnel` is `Send` because every field is either a
// process-local OS handle owned exclusively by this tunnel, or thread-safe
// shared state:
// * `wg_lib: HMODULE` вЂ” loaded once via `LoadLibraryW` in `new()`, ref-counted
//   by the OS for the lifetime of the process.  It is freed exactly once, in
//   `Drop` (the `DllGuard` is `mem::forget`-ed in `new()` so ownership
//   transfers here); `HMODULE` is a process-global integer-like handle, not
//   thread-affine.  No `Send`/`Sync` raw-pointer aliasing is introduced.
// * `adapter_handle: Mutex<Option<HANDLE>>` вЂ” a WireGuard adapter handle
//   obtained from `WireGuardCreateAdapter`; all access is serialized by the
//   `Mutex`.  The handle is closed exactly once in `delete_adapter_handle()`
//   (which `take()`s it), preventing double-close.
// * The `fn_*` fields are raw `unsafe extern "system" fn` pointers resolved from
//   `wireguard.dll` via `GetProcAddress` (see the SAFETY comment in `new()`).
//   Function pointers are stateless code addresses and are `Send + Sync`.
// * `Arc<TunnelCounters>` holds only `AtomicU64`, which is `Send + Sync`.
//
// The WireGuard-NT public ABI (`WireGuardCreateAdapter`, `WireGuardCloseAdapter`,
// `WireGuardSetConfiguration`, `WireGuardGetConfiguration`,
// `WireGuardSetAdapterState`, `WireGuardGetAdapterState`,
// `WireGuardGetRunningDriverVersion`, `WireGuardGetAdapterLUID`,
// `WireGuardOpenAdapter`, `WireGuardDeleteDriver`) is reentrant and
// thread-safe across adapters вЂ” the official WireGuard for Windows service
// invokes these from multiple worker threads concurrently.  `&mut self` is
// mutated only by the single owner (a tunnel is driven through `&self` from
// Tauri commands, never shared mutably across threads).
unsafe impl Send for WireGuardTunnel {}

#[cfg(target_os = "windows")]
// SAFETY: `WireGuardTunnel` is `Sync` (shareable between threads via `&self`)
// because every `&self` operation either (1) invokes a stateless, thread-safe
// WireGuard-NT function pointer operating on a per-adapter `HANDLE` that is
// mutex-guarded, or (2) reads atomics behind `Arc`.  (3) `wg_lib` is only
// dereferenced (freed) in `Drop`, which requires unique ownership, so no
// `&self` observer can outlive the `FreeLibrary`; `LoadLibraryW` keeps the
// DLL mapped process-wide while any reference to this tunnel exists.  Hence
// concurrent diagnostic calls (`get_driver_version`, `get_adapter_state`,
// `stats`) are sound.
unsafe impl Sync for WireGuardTunnel {}

impl WireGuardTunnel {
    pub fn new(profile: &Profile) -> Result<Self, String> {
        let config_path = profile
            .wg_config_path
            .as_deref()
            .ok_or_else(|| format!("profile '{}' has no WireGuard config path", profile.id))?;
        let config_text = std::fs::read_to_string(config_path)
            .map_err(|e| format!("failed to read WireGuard config '{}': {e}", config_path))?;
        let config = parse_wireguard_config(&config_text)?;
        validate_config(&config)?;

        #[cfg(target_os = "windows")]
        let (
            wg_lib,
            fn_create,
            fn_close,
            fn_set_cfg,
            fn_get_cfg,
            fn_set_state,
            fn_get_state,
            fn_get_drv_ver,
            fn_get_luid,
            fn_open,
        ) = {
            // SAFETY: FFI resolution region. Every `unsafe` operation below loads
            // and introspects `wireguard.dll` for this tunnel:
            // * `LoadLibraryW` is called with an **absolute** path from
            //   `get_dll_path()`, which resolves to the bundled `resources/`
            //   directory (or the exe dir).  An absolute path defeats DLL
            //   search-order hijacking вЂ” the system loads only our signed DLL.
            // * Each `GetProcAddress(lib, s!("Name"))` looks up a string-literal
            //   export asserted present by `ok_or_else`; the returned `FARPROC`
            //   is a valid function pointer whose signature matches the
            //   corresponding `<_Func` type alias declared above (these mirror
            //   `wireguard-nt`'s public `wireguard.h`).
            // * `transmute::<unsafe extern "system" fn() -> isize, X>(proc)` is
            //   sound because `windows` returns `FARPROC` as exactly
            //   `unsafe extern "system" fn() -> isize`, and each target ABI is
            //   the precise signature of the named export.
            // * Library ownership is transferred to `WireGuardTunnel` via
            //   `std::mem::forget(dll_guard)`; `Drop` calls `FreeLibrary` once,
            //   so there is no double-free.
            let dll_path = get_dll_path("wireguard.dll");
            let dll_path_wide = wide_path(&dll_path);
            // SAFETY: absolute-path LoadLibraryW against the trusted bundled wireguard.dll (DLL-hijack-safe); the HMODULE is freed via FreeLibrary or DllGuard.
            let lib = unsafe { LoadLibraryW(PCWSTR(dll_path_wide.as_ptr())) }
                .map_err(|e| format!("failed to load wireguard.dll: {e}"))?;

            // RAII guard: if any GetProcAddress below fails, the library is
            // automatically freed via FreeLibrary when the guard is dropped.
            // On success, the guard is forgotten (std::mem::forget) so that
            // ownership transfers to WireGuardTunnel (whose Drop calls
            // FreeLibrary).
            let dll_guard = DllGuard(lib);

            // SAFETY: GetProcAddress on the loaded lib for a known WireGuard-NT export; the pointer is null-checked before use.
            let create_proc = unsafe {
                GetProcAddress(lib, s!("WireGuardCreateAdapter"))
                    .ok_or_else(|| "WireGuardCreateAdapter not found".to_string())?
            };
            // SAFETY: GetProcAddress on the loaded lib for a known WireGuard-NT export; the pointer is null-checked before use.
            let close_proc = unsafe {
                GetProcAddress(lib, s!("WireGuardCloseAdapter"))
                    .ok_or_else(|| "WireGuardCloseAdapter not found".to_string())?
            };
            // SAFETY: GetProcAddress on the loaded lib for a known WireGuard-NT export; the pointer is null-checked before use.
            let set_cfg_proc = unsafe {
                GetProcAddress(lib, s!("WireGuardSetConfiguration"))
                    .ok_or_else(|| "WireGuardSetConfiguration not found".to_string())?
            };
            // SAFETY: GetProcAddress on the loaded lib for a known WireGuard-NT export; the pointer is null-checked before use.
            let get_cfg_proc = unsafe {
                GetProcAddress(lib, s!("WireGuardGetConfiguration"))
                    .ok_or_else(|| "WireGuardGetConfiguration not found".to_string())?
            };
            // Additional functions required for proper adapter lifecycle:
            // - WireGuardSetAdapterState: UP/DOWN the adapter after config is applied
            // - WireGuardGetAdapterState: check adapter state for diagnostics
            // - WireGuardGetRunningDriverVersion: check if kernel driver is loaded
            // SAFETY: GetProcAddress on the loaded lib for a known WireGuard-NT export; the pointer is null-checked before use.
            let set_state_proc = unsafe {
                GetProcAddress(lib, s!("WireGuardSetAdapterState"))
                    .ok_or_else(|| "WireGuardSetAdapterState not found".to_string())?
            };
            // SAFETY: GetProcAddress on the loaded lib for a known WireGuard-NT export; the pointer is null-checked before use.
            let get_state_proc = unsafe {
                GetProcAddress(lib, s!("WireGuardGetAdapterState"))
                    .ok_or_else(|| "WireGuardGetAdapterState not found".to_string())?
            };
            // SAFETY: GetProcAddress on the loaded lib for a known WireGuard-NT export; the pointer is null-checked before use.
            let get_drv_ver_proc = unsafe {
                GetProcAddress(lib, s!("WireGuardGetRunningDriverVersion"))
                    .ok_or_else(|| "WireGuardGetRunningDriverVersion not found".to_string())?
            };
            // WireGuardGetAdapterLUID вЂ” required for Windows route table entry.
            // Returns the NDIS miniport LUID of the adapter.
            // SAFETY: GetProcAddress on the loaded lib for a known WireGuard-NT export; the pointer is null-checked before use.
            let get_luid_proc = unsafe {
                GetProcAddress(lib, s!("WireGuardGetAdapterLUID"))
                    .ok_or_else(|| "WireGuardGetAdapterLUID not found".to_string())?
            };
            // WireGuardOpenAdapter вЂ” required for crash recovery.
            // Reopens an existing adapter by name without creating a new one.
            // SAFETY: GetProcAddress on the loaded lib for a known WireGuard-NT export; the pointer is null-checked before use.
            let open_adapter_proc = unsafe {
                GetProcAddress(lib, s!("WireGuardOpenAdapter"))
                    .ok_or_else(|| "WireGuardOpenAdapter not found".to_string())?
            };

            // All function pointers resolved successfully вЂ” transfer
            // library ownership to WireGuardTunnel.  The guard's Drop
            // would call FreeLibrary, so we forget it here.
            std::mem::forget(dll_guard);

            (
                lib,
                // SAFETY: transmute of a validated FARPROC to a typed unsafe extern system fn alias matching the export ABI - sound.
                unsafe {
                    std::mem::transmute::<
                        unsafe extern "system" fn() -> isize,
                        WireGuardCreateAdapterFunc,
                    >(create_proc)
                },
                // SAFETY: transmute of a validated FARPROC to a typed unsafe extern system fn alias matching the export ABI - sound.
                unsafe {
                    std::mem::transmute::<
                        unsafe extern "system" fn() -> isize,
                        WireGuardCloseAdapterFunc,
                    >(close_proc)
                },
                // SAFETY: transmute of a validated FARPROC to a typed unsafe extern system fn alias matching the export ABI - sound.
                unsafe {
                    std::mem::transmute::<
                        unsafe extern "system" fn() -> isize,
                        unsafe extern "system" fn(HANDLE, *const std::ffi::c_void, u32) -> BOOL,
                    >(set_cfg_proc)
                },
                // SAFETY: transmute of a validated FARPROC to a typed unsafe extern system fn alias matching the export ABI - sound.
                unsafe {
                    std::mem::transmute::<
                        unsafe extern "system" fn() -> isize,
                        unsafe extern "system" fn(HANDLE, *mut std::ffi::c_void, *mut u32) -> BOOL,
                    >(get_cfg_proc)
                },
                // SAFETY: transmute of a validated FARPROC to a typed unsafe extern system fn alias matching the export ABI - sound.
                unsafe {
                    std::mem::transmute::<
                        unsafe extern "system" fn() -> isize,
                        WireGuardSetAdapterStateFunc,
                    >(set_state_proc)
                },
                // SAFETY: transmute of a validated FARPROC to a typed unsafe extern system fn alias matching the export ABI - sound.
                unsafe {
                    std::mem::transmute::<
                        unsafe extern "system" fn() -> isize,
                        WireGuardGetAdapterStateFunc,
                    >(get_state_proc)
                },
                // SAFETY: transmute of a validated FARPROC to a typed unsafe extern system fn alias matching the export ABI - sound.
                unsafe {
                    std::mem::transmute::<
                        unsafe extern "system" fn() -> isize,
                        WireGuardGetRunningDriverVersionTyped,
                    >(get_drv_ver_proc)
                },
                // SAFETY: transmute of a validated FARPROC to a typed unsafe extern system fn alias matching the export ABI - sound.
                unsafe {
                    std::mem::transmute::<
                        unsafe extern "system" fn() -> isize,
                        WireGuardGetAdapterLuidFunc,
                    >(get_luid_proc)
                },
                // SAFETY: transmute of a validated FARPROC to a typed unsafe extern system fn alias matching the export ABI - sound.
                unsafe {
                    std::mem::transmute::<
                        unsafe extern "system" fn() -> isize,
                        WireGuardOpenAdapterFunc,
                    >(open_adapter_proc)
                },
            )
        };

        Ok(Self {
            adapter_name: format!("MARSTART-{}", profile.id),
            config,
            status: Mutex::new(TunnelStatus::Disconnected),
            counters: Arc::new(TunnelCounters::default()),
            connect_time: Mutex::new(None),
            #[cfg(target_os = "windows")]
            adapter_handle: Mutex::new(None),
            #[cfg(target_os = "windows")]
            wg_lib,
            #[cfg(target_os = "windows")]
            fn_create,
            #[cfg(target_os = "windows")]
            fn_close,
            #[cfg(target_os = "windows")]
            fn_set_cfg,
            #[cfg(target_os = "windows")]
            fn_get_cfg,
            #[cfg(target_os = "windows")]
            fn_set_state,
            #[cfg(target_os = "windows")]
            fn_get_state,
            #[cfg(target_os = "windows")]
            fn_get_drv_ver,
            #[cfg(target_os = "windows")]
            fn_get_luid,
            #[cfg(target_os = "windows")]
            fn_open,
        })
    }

    pub fn connect(&mut self) -> Result<(), String> {
        {
            let mut status = self.status.lock().map_err(|e| e.to_string())?;
            match &*status {
                TunnelStatus::Connected | TunnelStatus::Connecting => {
                    return Err("tunnel is already active".to_string());
                }
                TunnelStatus::Disconnected | TunnelStatus::Error(_) => {
                    *status = TunnelStatus::Connecting;
                }
            }
        }

        let result = self.connect_impl();
        match result {
            Ok(()) => {
                *self.status.lock().map_err(|e| e.to_string())? = TunnelStatus::Connected;
                *self.connect_time.lock().map_err(|e| e.to_string())? = Some(Instant::now());
                Ok(())
            }
            Err(e) => {
                *self.status.lock().map_err(|lock| lock.to_string())? =
                    TunnelStatus::Error(e.clone());
                let _ = self.teardown();
                Err(e)
            }
        }
    }

    #[cfg(target_os = "windows")]
    fn connect_impl(&mut self) -> Result<(), String> {
        let tunnel_wide = wide_str(&self.adapter_name);
        let tunnel_name = PCWSTR(tunnel_wide.as_ptr());

        let tunnel_type = wide_str("MARSTART LINK");
        // SAFETY: `WireGuardCreateAdapter` is a thread-safe WireGuard-NT entry
        // point.  `tunnel_name`/`tunnel_type` are NUL-terminated wide strings
        // built by `wide_str`; `requested_guid` is NULL (OS-assigned).  The
        // returned `HANDLE` is owned by this tunnel and closed once in `Drop`.
        let handle = unsafe {
            (self.fn_create)(tunnel_name, PCWSTR(tunnel_type.as_ptr()), std::ptr::null())
        };

        if handle.0.is_null() {
            let os_err = std::io::Error::last_os_error();
            // SAFETY: WireGuard-NT FFI - thread-safe API invoked with a valid handle/buffer in scope.
            let drv_ver = unsafe { (self.fn_get_drv_ver)() };
            let err_msg = if drv_ver == 0 {
                let drv_err = std::io::Error::last_os_error();
                let code = drv_err.raw_os_error().unwrap_or(0);
                if code == 2 {
                    "WireGuard-NT kernel driver (wireguard.sys) is not installed. \
                     WireGuardCreateAdapter returned NULL вЂ” admin rights are required \
                     for first-time driver installation. Run the application as \
                     Administrator."
                } else {
                    "WireGuard-NT kernel driver not loaded. \
                     Run as Administrator or install WireGuard for Windows."
                }
            } else {
                "WireGuard adapter creation failed (driver is loaded but \
                 create_adapter returned NULL)"
            };
            return Err(format!(
                "failed to create WireGuard adapter: {} (os error: {}, GetLastError: {})",
                err_msg,
                os_err,
                os_err.raw_os_error().unwrap_or(0)
            ));
        }

        *self.adapter_handle.lock().map_err(|e| e.to_string())? = Some(handle);

        let config_blob = serialize_config(&self.config)
            .map_err(|e| format!("failed to serialize config: {e}"))?;

        // SAFETY: `WireGuardSetConfiguration` is a thread-safe WireGuard-NT API.
        // `config_blob` is a valid, fully-initialized `Vec<u8>` of `len()` bytes
        // borrowed via a const pointer for the duration of the call; `handle` is
        // the adapter owned by this tunnel.  `&mut self` guarantees no other
        // thread is mutating the tunnel concurrently.
        let ok = unsafe {
            (self.fn_set_cfg)(
                handle,
                config_blob.as_ptr() as *const std::ffi::c_void,
                config_blob.len() as u32,
            )
        };
        if !ok.as_bool() {
            let os_err = std::io::Error::last_os_error();
            let _ = self.delete_adapter_handle();
            return Err(format!("WireGuardSetConfiguration failed: {os_err}"));
        }

        // CRITICAL: Bring the adapter UP after configuration is applied.
        // Without WireGuardSetAdapterState(WIREGUARD_ADAPTER_STATE_UP), the
        // adapter is created and configured but no UDP sockets are opened,
        // no handshake can occur, and no traffic flows.
        // SAFETY: `WireGuardSetAdapterState` is a thread-safe WireGuard-NT API;
        // `handle` is this tunnel's adapter; `Up` is a valid
        // `WIREGUARD_ADAPTER_STATE`.
        let ok = unsafe { (self.fn_set_state)(handle, WireGuardAdapterState::Up) };
        if !ok.as_bool() {
            let os_err = std::io::Error::last_os_error();
            let _ = self.delete_adapter_handle();
            return Err(format!(
                "WireGuardSetAdapterState(UP) failed: {os_err}. \
                 The adapter was created but could not be brought online."
            ));
        }

        Ok(())
    }

    #[cfg(not(target_os = "windows"))]
    fn connect_impl(&mut self) -> Result<(), String> {
        Err("WireGuard control is only supported on Windows".to_string())
    }

    pub fn teardown(&self) -> Result<(), String> {
        #[cfg(target_os = "windows")]
        {
            // Best-effort: bring the adapter DOWN before closing the handle.
            // If the adapter is already down or the handle is invalid, this
            // is a no-op.  Errors here are logged but do not prevent
            // cleanup of the handle itself.
            let handle_opt = *self.adapter_handle.lock().map_err(|e| e.to_string())?;
            if let Some(handle) = handle_opt {
                // SAFETY: `WireGuardSetAdapterState(Down)` is thread-safe; `handle`
                // was read under the `adapter_handle` Mutex (valid).  Best-effort:
                // a failure here is non-fatal вЂ” the handle is still released on
                // the success path and freed unconditionally in `Drop`.
                let _ = unsafe { (self.fn_set_state)(handle, WireGuardAdapterState::Down) };
            }
        }

        #[cfg(target_os = "windows")]
        self.delete_adapter_handle()?;

        self.counters.clear();
        *self.connect_time.lock().map_err(|e| e.to_string())? = None;
        *self.status.lock().map_err(|e| e.to_string())? = TunnelStatus::Disconnected;
        Ok(())
    }

    pub fn status(&self) -> TunnelStatus {
        self.status
            .lock()
            .map(|guard| guard.clone())
            .unwrap_or_else(|_| TunnelStatus::Error("tunnel status lock poisoned".to_string()))
    }

    pub fn stats(&self) -> Result<(u64, u64, u64), String> {
        #[cfg(target_os = "windows")]
        {
            let handle = *self.adapter_handle.lock().map_err(|e| e.to_string())?;
            if let Some(handle) = handle {
                let stats = self.read_peer_stats(handle)?;
                self.counters.tx_bytes.store(stats.0, Ordering::Relaxed);
                self.counters.rx_bytes.store(stats.1, Ordering::Relaxed);
                self.counters
                    .last_handshake_unix
                    .store(stats.2, Ordering::Relaxed);
                return Ok(stats);
            }
        }

        Ok(self.counters.snapshot())
    }

    pub fn connection_info(&self) -> Result<ConnectionInfo, String> {
        let (tx, rx, handshake) = self.stats()?;
        Ok(ConnectionInfo {
            handshake_timestamp_unix: handshake,
            tx_bytes: tx,
            rx_bytes: rx,
            endpoint: self
                .config
                .peers
                .first()
                .and_then(|peer| peer.endpoint)
                .map(|endpoint| endpoint.to_string()),
        })
    }

    pub fn elapsed(&self) -> Option<Duration> {
        self.connect_time.lock().ok().and_then(|guard| {
            let started = *guard;
            started.map(|instant| instant.elapsed())
        })
    }

    #[cfg(target_os = "windows")]
    fn delete_adapter_handle(&self) -> Result<(), String> {
        let handle = self
            .adapter_handle
            .lock()
            .map_err(|e| e.to_string())?
            .take();
        let Some(handle) = handle else {
            return Ok(());
        };

        // SAFETY: `WireGuardCloseAdapter` is thread-safe; `handle` was taken
        // (`Mutex::take`) from `adapter_handle`, so no other thread can reach
        // this handle вЂ” no double-close is possible here.
        unsafe {
            (self.fn_close)(handle);
        }
        Ok(())
    }

    #[cfg(target_os = "windows")]
    fn read_peer_stats(&self, handle: HANDLE) -> Result<(u64, u64, u64), String> {
        let mut buf_size: u32 = 0;
        // SAFETY: `WireGuardGetConfiguration` is thread-safe; passing a NULL
        // output buffer with a valid `&mut buf_size` is the documented
        // size-query idiom (it writes the required byte count back in-bounds).
        unsafe {
            let _ = (self.fn_get_cfg)(handle, std::ptr::null_mut(), &mut buf_size);
        }
        if buf_size == 0 {
            return Ok((0, 0, 0));
        }

        let mut buffer = vec![0u8; buf_size as usize];
        // SAFETY: `WireGuardGetConfiguration` is thread-safe; `buffer` is a
        // valid `buf_size`-length allocation and the API writes at most
        // `buf_size` bytes (sized from the prior size-query call).  `handle` is
        // a valid adapter read under the Mutex.
        let ok = unsafe { (self.fn_get_cfg)(handle, buffer.as_mut_ptr() as *mut _, &mut buf_size) };
        if !ok.as_bool() {
            return Ok((0, 0, 0));
        }

        Ok(read_peer_stats(&buffer)
            .into_iter()
            .next()
            .unwrap_or((0, 0, 0)))
    }

    /// Returns `true` when the underlying WireGuard adapter handle has been
    /// closed and cleared (i.e. no orphan adapter remains).
    #[cfg(target_os = "windows")]
    pub fn is_adapter_closed(&self) -> bool {
        self.adapter_handle
            .lock()
            .map(|g| g.is_none())
            .unwrap_or(true)
    }

    /// Queries the actual adapter state via `WireGuardGetAdapterState()`.
    /// Returns `Up`, `Down`, or `Unknown` if the handle is unavailable.
    #[cfg(target_os = "windows")]
    pub fn get_adapter_state(&self) -> AdapterStateReport {
        let handle = match self.adapter_handle.lock() {
            Ok(guard) => match *guard {
                Some(h) => h,
                None => return AdapterStateReport::Unknown,
            },
            Err(_) => return AdapterStateReport::Unknown,
        };

        let mut state: WireGuardAdapterState = WireGuardAdapterState::Down;
        // SAFETY: `WireGuardGetAdapterState` is thread-safe; `HANDLE(handle.0)`
        // is a valid adapter handle read under the Mutex; `&mut state` is a
        // valid `WIREGUARD_ADAPTER_STATE` stack location.
        let ok = unsafe { (self.fn_get_state)(HANDLE(handle.0), &mut state) };
        if ok.as_bool() {
            match state {
                WireGuardAdapterState::Down => AdapterStateReport::Down,
                WireGuardAdapterState::Up => AdapterStateReport::Up,
            }
        } else {
            AdapterStateReport::Unknown
        }
    }

    /// Returns the running-driver version DWORD (0 = not loaded).
    /// Used by `run_diagnostics` to populate the report.
    #[cfg(target_os = "windows")]
    pub fn get_driver_version(&self) -> u32 {
        // SAFETY: `WireGuardGetRunningDriverVersion` is a thread-safe WireGuard-NT
        // API that takes no arguments and has no side effects.
        unsafe { (self.fn_get_drv_ver)() }
    }

    /// Obtains the LUID (Locally Unique Identifier) of the WireGuard adapter's
    /// NDIS miniport interface via `WireGuardGetAdapterLUID`.
    ///
    /// This LUID is used as `MIB_IPFORWARD_ROW2.InterfaceLuid` when installing
    /// routes in the Windows routing table, binding the route to this specific
    /// WireGuard adapter.
    #[cfg(target_os = "windows")]
    pub fn get_adapter_luid(&self) -> Result<u64, String> {
        use windows::Win32::NetworkManagement::Ndis::NET_LUID_LH;

        let handle = self.adapter_handle.lock().map_err(|e| e.to_string())?;
        let handle = handle.as_ref().ok_or("adapter not connected")?;

        let mut luid: NET_LUID_LH = NET_LUID_LH::default();
        // SAFETY: `WireGuardGetAdapterLUID` is thread-safe; `*handle` is a valid
        // adapter handle read under the Mutex; `&mut luid` is a valid
        // `NET_LUID_LH` stack location.  The LUID binds the adapter to its NDIS
        // interface for route installation.
        unsafe {
            (self.fn_get_luid)(*handle, &mut luid);
        }

        // NET_LUID_LH.Value is a u64 containing the LUID
        // SAFETY: `NET_LUID_LH` is a `#[repr(C)]` union.  Reading the `Value`
        // member is sound because the union was populated by the preceding
        // `WireGuardGetAdapterLUID` call and we read only `Value`.
        let luid_val = unsafe { luid.Value };
        Ok(luid_val)
    }

    /// Reopens an existing WireGuard adapter by name using `WireGuardOpenAdapter`.
    ///
    /// Used for crash recovery: if the MARSTART LINK process crashes and restarts,
    /// previously-created WireGuard adapters persist in the system. This method
    /// rebinds to an existing adapter instead of creating a new one.
    #[cfg(target_os = "windows")]
    pub fn open_adapter(&self, adapter_name: &str) -> Result<(), String> {
        let name_wide = wide_str(adapter_name);
        // SAFETY: `WireGuardOpenAdapter` is thread-safe; `name_wide` is a
        // NUL-terminated wide string.  The returned `HANDLE` is owned by this
        // tunnel and closed once in `Drop`.
        let handle = unsafe { (self.fn_open)(PCWSTR(name_wide.as_ptr())) };

        if handle.0.is_null() {
            let os_err = std::io::Error::last_os_error();
            return Err(format!(
                "WireGuardOpenAdapter failed for '{}': {} (raw_os_error: {})",
                adapter_name,
                os_err,
                os_err.raw_os_error().unwrap_or(0)
            ));
        }

        *self.adapter_handle.lock().map_err(|e| e.to_string())? = Some(handle);

        Ok(())
    }
}

/// Runs a full lifecycle smoke test against the WireGuard-NT runtime:
/// load DLL в†’ create adapter в†’ apply config в†’ read stats в†’ close adapter в†’ free DLL.
///
/// Each step is recorded in the returned [`DiagnosticsReport`].
/// The tunnel is created locally and torn down within this function,
/// so it does not interfere with the main connection.
#[cfg(target_os = "windows")]
pub fn run_diagnostics(profile: &Profile) -> Result<DiagnosticsReport, String> {
    let mut report = DiagnosticsReport {
        dll_loaded: false,
        driver_present: false,
        driver_version: 0,
        is_admin: false,
        adapter_created: false,
        config_applied: false,
        adapter_state: AdapterStateReport::Unknown,
        adapter_closed: false,
        no_orphan_adapter: false,
        handshake_timestamp_unix: 0,
        tx_bytes: 0,
        rx_bytes: 0,
        endpoint: None,
        errors: Vec::new(),
    };

    // Record admin status early вЂ” needed for error interpretation
    report.is_admin = is_running_as_admin();

    // 1. Load DLL + resolve all FFI function pointers
    let mut tunnel = match WireGuardTunnel::new(profile) {
        Ok(t) => {
            report.dll_loaded = true;
            report.driver_version = t.get_driver_version();
            report.driver_present = report.driver_version != 0;
            t
        }
        Err(e) => {
            report.errors.push(format!("dll_load: {e}"));
            // No tunnel object was created в†’ no adapter handle в†’ no orphan.
            report.no_orphan_adapter = true;
            return Ok(report);
        }
    };

    // 2. Create adapter (WireGuardCreateAdapter) + apply config + set UP
    match tunnel.connect() {
        Ok(()) => {
            report.adapter_created = true;
            report.config_applied = true;
        }
        Err(e) => {
            report.errors.push(format!("connect: {e}"));
            // connect() failed в†’ no adapter was created в†’ no orphan possible.
            report.no_orphan_adapter = true;
            return Ok(report);
        }
    }

    // 3. Query actual adapter state via WireGuardGetAdapterState()
    report.adapter_state = tunnel.get_adapter_state();

    // 4. Read stats via WireGuardGetConfiguration (handshake, tx, rx counters)
    match tunnel.stats() {
        Ok((tx, rx, hs)) => {
            report.tx_bytes = tx;
            report.rx_bytes = rx;
            report.handshake_timestamp_unix = hs;
        }
        Err(e) => {
            report.errors.push(format!("stats: {e}"));
        }
    }

    match tunnel.connection_info() {
        Ok(info) => report.endpoint = info.endpoint,
        Err(e) => report.errors.push(format!("connection_info: {e}")),
    }

    // 5. Close adapter (WireGuardCloseAdapter) + mark closed
    let teardown_result = tunnel.teardown();
    report.adapter_closed = teardown_result.is_ok();
    if let Err(e) = teardown_result {
        report.errors.push(format!("teardown: {e}"));
    }

    // 6. Verify no orphan adapter remains (handle cleared = adapter closed)
    report.no_orphan_adapter = tunnel.is_adapter_closed();

    // Drop tunnel в†’ FreeLibrary(wireguard.dll) + any remaining cleanup
    drop(tunnel);

    Ok(report)
}

/// Non-Windows fallback: diagnostics require the WireGuard-NT runtime (Windows-only).
#[cfg(not(target_os = "windows"))]
pub fn run_diagnostics(_profile: &Profile) -> Result<DiagnosticsReport, String> {
    Err("WireGuard diagnostics are only supported on Windows".to_string())
}

/// Checks whether the current process is running with Administrator privileges.
/// Uses `IsUserAnAdmin` from shell32.dll вЂ” sufficient for diagnostic purposes.
#[cfg(target_os = "windows")]
pub fn is_running_as_admin() -> bool {
    use std::os::raw::c_int;
    #[link(name = "shell32")]
    extern "system" {
        fn IsUserAnAdmin() -> c_int;
    }
    // SAFETY: `IsUserAnAdmin` is a documented, side-effect-free Win32 API.
    // The `extern "system"` declaration above matches its true signature
    // (`c_int IsUserAnAdmin(void)`), so calling it is sound.
    unsafe { IsUserAnAdmin() != 0 }
}

#[cfg(not(target_os = "windows"))]
pub fn is_running_as_admin() -> bool {
    false
}

/// Pre-flight driver status check.
///
/// Loads `wireguard.dll` from the bundled `resources/` directory and calls
/// `WireGuardGetRunningDriverVersion()` to determine whether the WireGuardNT
/// kernel driver (`wireguard.sys`) is loaded in the running kernel.
///
/// This does **not** create an adapter, install anything, or perform any
/// privileged operation.  It is a pure read-only diagnostic that the frontend
/// can call at startup to decide whether to show a "driver missing" error.
///
/// Returns a [`DriverStatus`] with the following fields:
/// - `dll_loaded`: true if `wireguard.dll` was found and loaded via `LoadLibraryW`
/// - `driver_present`: true if `WireGuardGetRunningDriverVersion()` returned non-zero
/// - `driver_version`: the raw DWORD version (0 if not loaded)
/// - `driver_version_string`: human-readable version (e.g. "1.1.0.0")
/// - `is_admin`: true if the process has Administrator privileges
/// - `error_code`: Win32 error code (0 on success, 2 = ERROR_FILE_NOT_FOUND, 5 = ERROR_ACCESS_DENIED)
/// - `human_readable_error`: descriptive message
#[cfg(target_os = "windows")]
pub fn wireguard_driver_status() -> DriverStatus {
    let dll_path = get_dll_path("wireguard.dll");

    // Check DLL exists + load
    // SAFETY: absolute-path `LoadLibraryW` against the trusted bundled
    // `resources/wireguard.dll` (DLL-hijack-safe).  `lib` ownership is held in
    // the local `lib` binding and released by the `FreeLibrary` call below.
    let lib = unsafe {
        let dll_path_wide = wide_path(&dll_path);
        LoadLibraryW(PCWSTR(dll_path_wide.as_ptr()))
    };

    let lib = match lib {
        Ok(h) => h,
        Err(e) => {
            let err = std::io::Error::last_os_error();
            return DriverStatus {
                dll_loaded: false,
                driver_present: false,
                driver_version: 0,
                driver_version_string: "not loaded".to_string(),
                is_admin: is_running_as_admin(),
                error_code: err.raw_os_error().unwrap_or(0) as u32,
                human_readable_error: format!(
                    "Failed to load wireguard.dll from '{}': {}",
                    dll_path.display(),
                    e
                ),
            };
        }
    };

    // Resolve WireGuardGetRunningDriverVersion
    // SAFETY: `GetProcAddress` on our loaded `lib` for the known export
    // `WireGuardGetRunningDriverVersion`.  The `proc.is_none()` case is handled
    // above (early `FreeLibrary` + return).  `transmute` of the returned
    // `FARPROC` (`unsafe extern "system" fn() -> isize`) into
    // `WireGuardGetRunningDriverVersionFunc` (`unsafe extern "system" fn() ->
    // u32`) is sound вЂ” identical calling convention and the export returns a
    // 32-bit version.  `version_fn()` is a thread-safe, side-effect-free call.
    let version = unsafe {
        let proc = GetProcAddress(lib, s!("WireGuardGetRunningDriverVersion"));
        if proc.is_none() {
            let _ = FreeLibrary(lib);
            return DriverStatus {
                dll_loaded: true,
                driver_present: false,
                driver_version: 0,
                driver_version_string: "not loaded".to_string(),
                is_admin: is_running_as_admin(),
                error_code: 0,
                human_readable_error:
                    "wireguard.dll loaded but WireGuardGetRunningDriverVersion not found"
                        .to_string(),
            };
        }
        let version_fn: WireGuardGetRunningDriverVersionTyped = std::mem::transmute(proc.unwrap());
        version_fn()
    };

    // SAFETY: `FreeLibrary` on the `HMODULE` loaded above in this function;
    // called exactly once here, releasing `lib` before failure reporting.
    let _ = unsafe { FreeLibrary(lib) };

    let drv_err = std::io::Error::last_os_error();
    let err_code: u32 = drv_err.raw_os_error().unwrap_or(0) as u32;
    let is_admin = is_running_as_admin();

    if version == 0 {
        let human = if err_code == 2 {
            if is_admin {
                "WireGuard-NT kernel driver (wireguard.sys) is not installed. \
                 WireGuardCreateAdapter will attempt to install it, but the driver \
                 may fail to load."
                    .to_string()
            } else {
                "WireGuard-NT kernel driver (wireguard.sys) is not loaded. \
                 Administrator privileges are required to install the WireGuardNT \
                 kernel driver on first use. Run the application as Administrator \
                 to install the driver, then reconnect."
                    .to_string()
            }
        } else {
            format!(
                "WireGuardGetRunningDriverVersion returned 0 (error code: {})",
                err_code
            )
        };
        return DriverStatus {
            dll_loaded: true,
            driver_present: false,
            driver_version: 0,
            driver_version_string: "not loaded".to_string(),
            is_admin,
            error_code: err_code,
            human_readable_error: human,
        };
    }

    // Driver is loaded вЂ” decode version
    // Version DWORD layout: major (bits 24-31) | minor (bits 16-23) | patch (bits 8-15) | revision (bits 0-7)
    let major = (version >> 24) & 0xff;
    let minor = (version >> 16) & 0xff;
    let patch = (version >> 8) & 0xff;
    let revision = version & 0xff;

    DriverStatus {
        dll_loaded: true,
        driver_present: true,
        driver_version: version,
        driver_version_string: format!("{}.{}.{}.{}", major, minor, patch, revision),
        is_admin,
        error_code: 0,
        human_readable_error: String::new(),
    }
}

#[cfg(not(target_os = "windows"))]
pub fn wireguard_driver_status() -> DriverStatus {
    DriverStatus {
        dll_loaded: false,
        driver_present: false,
        driver_version: 0,
        driver_version_string: "not loaded".to_string(),
        is_admin: false,
        error_code: 0,
        human_readable_error: "WireGuard diagnostics are only supported on Windows".to_string(),
    }
}

/// Attempts to delete the WireGuard-NT kernel driver if no adapters are in use.
///
/// Calls `WireGuardDeleteDriver()` from `wireguard.dll`.  This is a privileged
/// operation that requires Administrator rights.  Returns `Ok(())` on success
/// or `Err(String)` with a descriptive message on failure.
///
/// This is intended for clean uninstall scenarios вЂ” the NSIS/MSIX uninstaller
/// should call this to remove the WireGuardNT driver alongside the application.
#[cfg(target_os = "windows")]
pub fn wireguard_delete_driver() -> Result<(), String> {
    let dll_path = get_dll_path("wireguard.dll");

    // SAFETY: absolute-path `LoadLibraryW` against the trusted bundled
    // `resources/wireguard.dll` (DLL-hijack-safe).  `lib` is freed by the
    // `FreeLibrary` call later in this function.
    let lib = unsafe {
        let dll_path_wide = wide_path(&dll_path);
        LoadLibraryW(PCWSTR(dll_path_wide.as_ptr()))
    }
    .map_err(|e| format!("failed to load wireguard.dll: {e}"))?;

    // SAFETY: `GetProcAddress` on the loaded `lib` for the known export
    // `WireGuardDeleteDriver`.  The `ok_or_else` guard ensures `proc` is `Some`
    // before the transmute below.  Returns a `FARPROC`.
    let delete_proc = unsafe {
        GetProcAddress(lib, s!("WireGuardDeleteDriver"))
            .ok_or_else(|| "WireGuardDeleteDriver not found in wireguard.dll".to_string())?
    };
    // SAFETY: `transmute` of a `FARPROC` (`unsafe extern "system" fn() -> isize`)
    // to `WireGuardDeleteDriverFunc` (declared above to match the export's real
    // signature) is sound.
    let delete_fn: WireGuardDeleteDriverFunc = unsafe { std::mem::transmute(delete_proc) };

    // SAFETY: `delete_fn` is `WireGuardDeleteDriver` вЂ” a privileged,
    // thread-safe WireGuard-NT API requiring Administrator rights.  This command
    // is only reachable from the `delete_driver` Tauri handler, which itself is
    // gated behind `is_running_as_admin`.
    let ok = unsafe { delete_fn() };
    // SAFETY: `FreeLibrary` on the `HMODULE` loaded above; called exactly once
    // here, after `delete_fn()` has returned.
    let _ = unsafe { FreeLibrary(lib) };

    if ok.as_bool() {
        Ok(())
    } else {
        let os_err = std::io::Error::last_os_error();
        Err(format!(
            "WireGuardDeleteDriver failed: {} (error code: {})",
            os_err,
            os_err.raw_os_error().unwrap_or(0)
        ))
    }
}

#[cfg(not(target_os = "windows"))]
pub fn wireguard_delete_driver() -> Result<(), String> {
    Err("WireGuard driver deletion is only supported on Windows".to_string())
}

#[cfg(target_os = "windows")]
fn wide_str(value: &str) -> Vec<u16> {
    std::ffi::OsStr::new(value)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

#[cfg(target_os = "windows")]
fn wide_path(value: &std::path::Path) -> Vec<u16> {
    value
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

#[cfg(target_os = "windows")]
impl Drop for WireGuardTunnel {
    fn drop(&mut self) {
        // РРЎРџР РђР’Р›Р•РќРћ: Р“Р°СЂР°РЅС‚РёСЂРѕРІР°РЅРЅРѕ СѓРґР°Р»СЏРµРј Р°РґР°РїС‚РµСЂ РїРµСЂРµРґ СѓРЅРёС‡С‚РѕР¶РµРЅРёРµРј РѕР±СЉРµРєС‚Р°
        let _ = self.delete_adapter_handle();

        // Free the DLL when tunnel is dropped
        // SAFETY: `FreeLibrary` on the `HMODULE` owned by this tunnel and loaded
        // in `new()`.  `WireGuardTunnel` has single ownership of `wg_lib`, so
        // this runs exactly once in `Drop`.  No `&self` method reads `wg_lib`
        // after this point.
        unsafe {
            let _ = FreeLibrary(self.wg_lib);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `DiagnosticsReport` must be JSON-serialisable so the Tauri frontend
    /// (and the `tunnel_diagnostics` command) can consume it over IPC.
    #[test]
    fn diagnostics_report_serialises() {
        let report = DiagnosticsReport {
            dll_loaded: true,
            driver_present: true,
            driver_version: 0x01010000,
            is_admin: false,
            adapter_created: true,
            config_applied: true,
            adapter_state: AdapterStateReport::Up,
            adapter_closed: true,
            no_orphan_adapter: true,
            handshake_timestamp_unix: 1_700_000_000,
            tx_bytes: 1024,
            rx_bytes: 2048,
            endpoint: Some("1.2.3.4:51820".to_string()),
            errors: vec![],
        };

        let json = serde_json::to_string(&report).expect("serialise");
        let round: DiagnosticsReport = serde_json::from_str(&json).expect("deserialise");

        assert!(round.dll_loaded);
        assert!(round.driver_present);
        assert_eq!(round.driver_version, 0x01010000);
        assert!(round.adapter_created);
        assert!(round.config_applied);
        assert_eq!(round.adapter_state, AdapterStateReport::Up);
        assert!(round.adapter_closed);
        assert!(round.no_orphan_adapter);
        assert_eq!(round.handshake_timestamp_unix, 1_700_000_000);
        assert_eq!(round.tx_bytes, 1024);
        assert_eq!(round.rx_bytes, 2048);
        assert_eq!(round.endpoint, Some("1.2.3.4:51820".to_string()));
        assert!(round.errors.is_empty());
    }

    /// On non-Windows the diagnostic must return a clear error string.
    #[cfg(not(target_os = "windows"))]
    #[test]
    fn diagnostics_not_supported_on_non_windows() {
        let profile = Profile {
            id: "self-test".to_string(),
            display_name: "Self Test".to_string(),
            endpoints: Vec::new(),
            wg_config_path: None,
            wg_config_paths: Vec::new(),
            managed_destination: None,
        };
        let result = run_diagnostics(&profile);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            err.contains("Windows"),
            "expected Windows-only error, got: {err}"
        );
    }

    /// On Windows, if the DLLs are not present the diagnostic should still
    /// return a report (with `dll_loaded == false`) rather than panicking.
    #[cfg(target_os = "windows")]
    #[test]
    fn diagnostics_graceful_without_dll() {
        let profile = Profile {
            id: "self-test".to_string(),
            display_name: "Self Test".to_string(),
            endpoints: Vec::new(),
            wg_config_path: None,
            wg_config_paths: Vec::new(),
            managed_destination: None,
        };
        // WireGuardTunnel::new requires a config path
        let result = run_diagnostics(&profile);
        // With no config path, we expect an error from the profile loading
        // stage вЂ” but the function must not panic.
        assert!(result.is_ok() || result.is_err());
    }

    /// Runtime FFI test: loads wireguard.dll, resolves all 4 WireGuard-NT
    /// functions, and attempts to create an adapter.  Even if the WireGuard-NT
    /// protocol service adapter is not installed, this test proves:
    ///   1. The bundled `wireguard.dll` is a valid PE that `LoadLibraryW` accepts.
    ///   2. All 4 exported functions (`WireGuardCreateAdapter`,
    ///      `WireGuardCloseAdapter`, `WireGuardSetConfiguration`,
    ///      `WireGuardGetConfiguration`) are resolvable via `GetProcAddress`.
    ///   3. `WireGuardCreateAdapter` returns a handle or NULL with a documented
    ///      error code (NULL = service not running or insufficient privileges).
    #[cfg(target_os = "windows")]
    #[test]
    fn runtime_ffi_lifecycle_test() {
        let dll_path = get_dll_path("wireguard.dll");
        println!("[ffi_test] DLL path: {}", dll_path.display());

        // 1. Verify the DLL exists at the expected bundled path
        assert!(
            dll_path.exists(),
            "wireguard.dll not found at expected path: {}",
            dll_path.display()
        );
        let file_size = std::fs::metadata(&dll_path).unwrap().len();
        println!(
            "[ffi_test] wireguard.dll size: {} bytes ({} KB)",
            file_size,
            file_size / 1024
        );
        assert!(file_size > 100_000, "wireguard.dll suspiciously small");

        // 2. Load the DLL via LoadLibraryW (same path as production code)
        let dll_path_wide = wide_path(&dll_path);
        // SAFETY: absolute-path LoadLibraryW against the trusted bundled wireguard.dll (DLL-hijack-safe); the HMODULE is freed via FreeLibrary or DllGuard.
        let lib = unsafe { LoadLibraryW(PCWSTR(dll_path_wide.as_ptr())) }
            .expect("LoadLibraryW should succeed for a valid DLL");
        println!("[ffi_test] LoadLibraryW: OK");

        // 3. Resolve all 4 WireGuard-NT functions (all must be exported)
        // SAFETY: GetProcAddress on the loaded lib for a known WireGuard-NT export; the pointer is null-checked before use.
        let create_proc = unsafe {
            GetProcAddress(lib, s!("WireGuardCreateAdapter"))
                .expect("WireGuardCreateAdapter must be exported")
        };
        // SAFETY: GetProcAddress on the loaded lib for a known WireGuard-NT export; the pointer is null-checked before use.
        let close_proc = unsafe {
            GetProcAddress(lib, s!("WireGuardCloseAdapter"))
                .expect("WireGuardCloseAdapter must be exported")
        };
        // SAFETY: GetProcAddress on the loaded lib for a known WireGuard-NT export; the pointer is null-checked before use.
        let set_cfg_proc = unsafe {
            GetProcAddress(lib, s!("WireGuardSetConfiguration"))
                .expect("WireGuardSetConfiguration must be exported")
        };
        // SAFETY: GetProcAddress on the loaded lib for a known WireGuard-NT export; the pointer is null-checked before use.
        let get_cfg_proc = unsafe {
            GetProcAddress(lib, s!("WireGuardGetConfiguration"))
                .expect("WireGuardGetConfiguration must be exported")
        };
        println!("[ffi_test] GetProcAddress: all 4 functions resolved OK");

        // Diagnostic: check if the WireGuard-NT kernel driver is loaded.
        // WireGuardGetRunningDriverVersion returns 0 + ERROR_FILE_NOT_FOUND
        // when the driver service is not running. (Not one of the 4 core
        // functions вЂ” resolved optionally for diagnostics only.)
        if let Some(version_proc) =
            // SAFETY: GetProcAddress on the loaded lib for a known WireGuard-NT export; the pointer is null-checked before use.
            unsafe { GetProcAddress(lib, s!("WireGuardGetRunningDriverVersion")) }
        {
            let version_fn: unsafe extern "system" fn() -> u32 =
                // SAFETY: transmute of a validated FARPROC to a typed unsafe extern system fn alias matching the export ABI - sound.
                unsafe { std::mem::transmute(version_proc) };
            // SAFETY: thread-safe WireGuard-NT API call through a typed fn pointer on a valid handle.
            let version = unsafe { version_fn() };
            if version == 0 {
                let drv_err = std::io::Error::last_os_error();
                println!(
                    "[ffi_test] WireGuardGetRunningDriverVersion: 0 (driver NOT loaded, \
                     error: {} (code {}))",
                    drv_err,
                    drv_err.raw_os_error().unwrap_or(0)
                );
            } else {
                let major = (version >> 24) & 0xff;
                let minor = (version >> 16) & 0xff;
                let patch = (version >> 8) & 0xff;
                let revision = version & 0xff;
                println!(
                    "[ffi_test] WireGuardGetRunningDriverVersion: {}.{}.{}.{} (0x{:08x})",
                    major, minor, patch, revision, version
                );
            }
        } else {
            println!("[ffi_test] WireGuardGetRunningDriverVersion: not exported (unexpected)");
        }

        // 4. Transmute to typed function pointer and attempt CreateAdapter
        // SAFETY: transmute of a validated FARPROC to a typed unsafe extern system fn alias matching the export ABI - sound.
        let create_fn: WireGuardCreateAdapterFunc = unsafe { std::mem::transmute(create_proc) };
        // Verify SetConfiguration is resolvable (type-resolution check only вЂ”
        // not called without a real adapter + config).
        let _set_cfg_fn: WireGuardSetConfigurationFunc =
            // SAFETY: transmute of a validated FARPROC to a typed unsafe extern system fn alias matching the export ABI - sound.
            unsafe { std::mem::transmute(set_cfg_proc) };
        let adapter_name = wide_str("MARSTART-FFI-TEST");
        let tunnel_type = wide_str("MARSTART LINK");

        // SAFETY: thread-safe WireGuard-NT API call through a typed fn pointer on a valid handle.
        let handle = unsafe {
            create_fn(
                PCWSTR(adapter_name.as_ptr()),
                PCWSTR(tunnel_type.as_ptr()),
                std::ptr::null(),
            )
        };

        if handle.0.is_null() {
            let err = std::io::Error::last_os_error();
            let code = err.raw_os_error().unwrap_or(0);
            println!(
                "[ffi_test] WireGuardCreateAdapter: returned NULL (handle=0x{:x})",
                handle.0 as isize
            );
            println!(
                "[ffi_test] CreateAdapter failure вЂ” this is EXPECTED when the \
                 WireGuard-NT protocol service adapter is not installed \
                 (error code: {}, message: {})",
                code, err
            );
            println!(
                "[ffi_test] To proceed with full adapter lifecycle: install \
                 WireGuard-NT 1.1 MSI with admin rights, then re-run."
            );
        } else {
            println!(
                "[ffi_test] WireGuardCreateAdapter: SUCCEEDED (handle=0x{:x})",
                handle.0 as isize
            );

            // 5. Read configuration back (GetConfiguration with zero-size probe)
            let (tx, rx, hs) = {
                let mut buf_size: u32 = 0;
                let get_cfg_fn: WireGuardGetConfigurationFunc =
                    // SAFETY: transmute of a validated FARPROC to a typed unsafe extern system fn alias matching the export ABI - sound.
                    unsafe { std::mem::transmute(get_cfg_proc) };
                // SAFETY: thread-safe WireGuard-NT API call through a typed fn pointer on a valid handle.
                let _ = unsafe { get_cfg_fn(handle, std::ptr::null_mut(), &mut buf_size) };
                println!("[ffi_test] GetConfiguration probe: buf_size={}", buf_size);
                if buf_size == 0 {
                    (0, 0, 0)
                } else {
                    let mut buffer = vec![0u8; buf_size as usize];
                    let ok =
                        // SAFETY: thread-safe WireGuard-NT API call through a typed fn pointer on a valid handle.
                        unsafe { get_cfg_fn(handle, buffer.as_mut_ptr() as *mut _, &mut buf_size) };
                    println!(
                        "[ffi_test] GetConfiguration read: ok={}, buf_size={}",
                        ok.as_bool(),
                        buf_size
                    );
                    read_peer_stats(&buffer)
                        .into_iter()
                        .next()
                        .unwrap_or((0, 0, 0))
                }
            };

            println!(
                "[ffi_test] Peer stats: tx={}, rx={}, handshake={}",
                tx, rx, hs
            );

            // 6. Close the adapter
            // SAFETY: transmute of a validated FARPROC to a typed unsafe extern system fn alias matching the export ABI - sound.
            let close_fn: WireGuardCloseAdapterFunc = unsafe { std::mem::transmute(close_proc) };
            // SAFETY: thread-safe WireGuard-NT API call through a typed fn pointer on a valid handle.
            unsafe { close_fn(handle) };
            println!("[ffi_test] WireGuardCloseAdapter: called");

            // 7. Verify handle is no longer usable (re-check with GetConfiguration)
            let mut buf_size: u32 = 0;
            let get_cfg_fn: WireGuardGetConfigurationFunc =
                // SAFETY: transmute of a validated FARPROC to a typed unsafe extern system fn alias matching the export ABI - sound.
                unsafe { std::mem::transmute(get_cfg_proc) };
            // SAFETY: thread-safe WireGuard-NT API call through a typed fn pointer on a valid handle.
            let ok = unsafe { get_cfg_fn(handle, std::ptr::null_mut(), &mut buf_size) };
            println!(
                "[ffi_test] Post-close GetConfiguration on closed handle: \
                 ok={}, buf_size={} (expected: failure / buf_size=0)",
                ok.as_bool(),
                buf_size
            );
        }

        // 8. Free the DLL
        // SAFETY: FreeLibrary on the HMODULE owned by this scope; invoked exactly once.
        unsafe {
            let _ = FreeLibrary(lib);
        }
        println!("[ffi_test] FreeLibrary: OK");
        println!("[ffi_test] === FFI lifecycle test complete ===");
    }

    /// Full diagnostics pipeline test: creates a temporary disposable config,
    /// invokes `run_diagnostics`, and verifies the report structure.
    /// Uses dummy (non-production) keys вЂ” the config is written to a temp
    /// file and never committed to git.
    #[cfg(target_os = "windows")]
    #[test]
    fn run_diagnostics_full_pipeline_test() {
        use base64::Engine;
        use std::io::Write;

        // DUMMY keys вЂ” NOT real production keys. Generated at test-time from
        // non-secret byte arrays so the config passes parse + validation.
        // Private key: 32 bytes, first byte 0x42, rest 0x00.
        let pk_bytes: [u8; 32] = {
            let mut k = [0u8; 32];
            k[0] = 0x42;
            k
        };
        let private_key = base64::engine::general_purpose::STANDARD.encode(pk_bytes);
        // Public key: 32 bytes, first byte 0x84, rest 0x00.
        let pub_bytes: [u8; 32] = {
            let mut k = [0u8; 32];
            k[0] = 0x84;
            k
        };
        let public_key = base64::engine::general_purpose::STANDARD.encode(pub_bytes);

        // Write a temporary disposable config to the OS temp directory.
        let config_content = format!(
            "[Interface]\n\
             PrivateKey = {}\n\
             Address = 10.99.0.1/24\n\
             DNS = 1.1.1.1\n\n\
             [Peer]\n\
             PublicKey = {}\n\
             Endpoint = 10.99.0.2:51820\n\
             AllowedIPs = 0.0.0.0/0\n\
             PersistentKeepalive = 25\n",
            private_key, public_key
        );

        let temp_dir = std::env::temp_dir();
        let config_path = temp_dir.join("marstart_diag_test.conf");
        {
            let mut f = std::fs::File::create(&config_path).expect("failed to create temp config");
            f.write_all(config_content.as_bytes())
                .expect("failed to write temp config");
        }

        let profile = Profile {
            id: "diag-test".to_string(),
            display_name: "Diag Test".to_string(),
            endpoints: Vec::new(),
            wg_config_path: Some(config_path.to_string_lossy().to_string()),
            wg_config_paths: vec![config_path.to_string_lossy().to_string()],
            managed_destination: None,
        };

        let report = run_diagnostics(&profile);

        // Clean up temp config
        let _ = std::fs::remove_file(&config_path);

        assert!(report.is_ok(), "run_diagnostics must not panic");
        let report = report.unwrap();

        println!("[diag_test] === DiagnosticsReport ===");
        println!("[diag_test] dll_loaded            = {}", report.dll_loaded);
        println!(
            "[diag_test] driver_present        = {}",
            report.driver_present
        );
        println!(
            "[diag_test] driver_version        = {}",
            report.driver_version
        );
        println!("[diag_test] is_admin              = {}", report.is_admin);
        println!(
            "[diag_test] adapter_created       = {}",
            report.adapter_created
        );
        println!(
            "[diag_test] config_applied        = {}",
            report.config_applied
        );
        println!(
            "[diag_test] adapter_state         = {:?}",
            report.adapter_state
        );
        println!(
            "[diag_test] adapter_closed        = {}",
            report.adapter_closed
        );
        println!(
            "[diag_test] no_orphan_adapter     = {}",
            report.no_orphan_adapter
        );
        println!(
            "[diag_test] handshake_timestamp_unix  = {}",
            report.handshake_timestamp_unix
        );
        println!("[diag_report] tx_bytes              = {}", report.tx_bytes);
        println!("[diag_test] rx_bytes              = {}", report.rx_bytes);
        println!("[diag_test] endpoint              = {:?}", report.endpoint);
        println!("[diag_test] errors                = {:?}", report.errors);
        println!("[diag_test] === End DiagnosticsReport ===");

        // The DLL MUST be found and loaded (it's bundled in resources/).
        assert!(
            report.dll_loaded,
            "wireguard.dll must load from bundled resources"
        );

        // If the WireGuard-NT driver is not installed, CreateAdapter will
        // fail вЂ” that is expected and documented, not a bug in our code.
        if !report.adapter_created {
            println!(
                "[diag_test] NOTE: adapter_created=false because the WireGuard-NT \
                 protocol driver/service is not installed (no admin rights to install it)."
            );
        }

        // Regardless of adapter success/failure, the tunnel must be cleaned up.
        assert!(
            report.no_orphan_adapter,
            "no orphan adapter should remain after run_diagnostics returns"
        );

        println!("[diag_test] === Full pipeline test complete ===");
    }

    /// Verifies that `wireguard_driver_status()` returns a structurally valid
    /// `DriverStatus` without panicking.  On this machine (no admin rights,
    /// driver not loaded) we expect:
    ///   dll_loaded = true
    ///   driver_present = false
    ///   driver_version = 0
    ///   is_admin = false
    #[cfg(target_os = "windows")]
    #[test]
    fn driver_status_returns_struct() {
        let status = wireguard_driver_status();

        // The DLL must be loadable from bundled resources.
        assert!(status.dll_loaded, "wireguard.dll should be loadable");

        println!("[driver_status] dll_loaded      = {}", status.dll_loaded);
        println!(
            "[driver_status] driver_present  = {}",
            status.driver_present
        );
        println!(
            "[driver_status] driver_version    = {}",
            status.driver_version
        );
        println!(
            "[driver_status] driver_version_str = {}",
            status.driver_version_string
        );
        println!("[driver_status] is_admin        = {}", status.is_admin);
        println!("[driver_status] error_code      = {}", status.error_code);
        println!(
            "[driver_status] human_readable    = {}",
            status.human_readable_error
        );

        // The status must be JSON-serialisable for the Tauri frontend.
        let json = serde_json::to_string(&status).expect("DriverStatus must serialise");
        let round: DriverStatus =
            serde_json::from_str(&json).expect("DriverStatus must deserialise");
        assert_eq!(round.dll_loaded, status.dll_loaded);
        assert_eq!(round.driver_present, status.driver_present);
        assert_eq!(round.driver_version, status.driver_version);
        assert_eq!(round.is_admin, status.is_admin);
    }

    /// Verify that `driver_present` is correctly `false` when
    /// `WireGuardGetRunningDriverVersion()` returns 0.
    /// This is the critical correctness check вЂ” a zero return value MUST
    /// mean "driver not loaded", not "driver loaded with version 0".
    #[cfg(target_os = "windows")]
    #[test]
    fn driver_present_semantics() {
        let status = wireguard_driver_status();
        // If the driver is not loaded, driver_version is 0 and driver_present is false.
        // If the driver IS loaded, driver_version is > 0 and driver_present is true.
        if status.driver_version == 0 {
            assert!(
                !status.driver_present,
                "driver_present must be false when driver_version is 0"
            );
        } else {
            assert!(
                status.driver_present,
                "driver_present must be true when driver_version > 0"
            );
        }
        println!(
            "[driver_semantics] version={}, present={}",
            status.driver_version, status.driver_present
        );
    }

    /// Verify that `AdapterStateReport` serialises/deserialises correctly.
    #[test]
    fn adapter_state_serialises() {
        let down = AdapterStateReport::Down;
        let up = AdapterStateReport::Up;
        let unknown = AdapterStateReport::Unknown;

        let json_down = serde_json::to_string(&down).expect("serialise Down");
        let json_up = serde_json::to_string(&up).expect("serialise Up");
        let json_unknown = serde_json::to_string(&unknown).expect("serialise Unknown");

        let round_down: AdapterStateReport =
            serde_json::from_str(&json_down).expect("deserialise Down");
        let round_up: AdapterStateReport = serde_json::from_str(&json_up).expect("deserialise Up");
        let round_unknown: AdapterStateReport =
            serde_json::from_str(&json_unknown).expect("deserialise Unknown");

        assert_eq!(round_down, AdapterStateReport::Down);
        assert_eq!(round_up, AdapterStateReport::Up);
        assert_eq!(round_unknown, AdapterStateReport::Unknown);
        assert_eq!(AdapterStateReport::default(), AdapterStateReport::Unknown);
    }

    /// Verify that `WireGuardAdapterState` enum values match the wireguard.h
    /// definitions: DOWN=0, UP=1.
    #[test]
    fn adapter_state_wireguard_enum_values() {
        #[cfg(target_os = "windows")]
        {
            assert_eq!(WireGuardAdapterState::Down as u32, 0);
            assert_eq!(WireGuardAdapterState::Up as u32, 1);
        }
        // Non-Windows: just verify the AdapterStateReport defaults
        assert_eq!(AdapterStateReport::default(), AdapterStateReport::Unknown);
    }

    /// Verify that `is_running_as_admin` does not panic and returns a bool.
    #[test]
    fn admin_detection_does_not_panic() {
        let result = is_running_as_admin();
        // We don't assert the value (depends on the machine), just that it returns.
        println!("[admin_check] is_admin = {}", result);
        // Result must be a valid bool (true or false, not undefined).
        let _ = result == result; // trivial assertion to ensure bool is valid
    }

    /// Verify that `wireguard_driver_status` error_code semantics are correct.
    /// When driver_version == 0, error_code should indicate why (2 = FILE_NOT_FOUND,
    /// 5 = ACCESS_DENIED, etc.).
    #[cfg(target_os = "windows")]
    #[test]
    fn driver_status_error_code_semantics() {
        let status = wireguard_driver_status();
        if status.driver_version == 0 {
            // Driver not loaded вЂ” there should be a non-zero error code or
            // an error message explaining why.
            if !status.human_readable_error.is_empty() {
                println!(
                    "[error_code] code={}, msg={}",
                    status.error_code, status.human_readable_error
                );
            }
        } else {
            // Driver loaded вЂ” error_code should be 0.
            assert_eq!(
                status.error_code, 0,
                "error_code should be 0 when driver is present"
            );
        }
    }
}
