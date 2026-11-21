#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use meshvault_desktop::DesktopVaultBridge;

#[cfg(feature = "tauri-app")]
fn main() {
    use std::path::PathBuf;
    use std::sync::Arc;
    use tauri::State;
    use uuid::Uuid;

    let bridge = Arc::new(DesktopVaultBridge::new());

    #[tauri::command]
    fn unlock_vault(
        state: State<'_, Arc<DesktopVaultBridge>>,
        vault_dir: String,
        passphrase: String,
    ) -> Result<Uuid, String> {
        state.unlock_vault(&PathBuf::from(vault_dir), &passphrase)
    }

    #[tauri::command]
    fn lock_vault(state: State<'_, Arc<DesktopVaultBridge>>) {
        state.lock_vault();
    }

    #[tauri::command]
    fn list_media(
        state: State<'_, Arc<DesktopVaultBridge>>,
    ) -> Result<Vec<meshvault_desktop::DesktopMediaItem>, String> {
        state.list_media()
    }

    #[tauri::command]
    fn import_paths(
        state: State<'_, Arc<DesktopVaultBridge>>,
        paths: Vec<String>,
    ) -> Result<usize, String> {
        let p: Vec<PathBuf> = paths.into_iter().map(PathBuf::from).collect();
        state.import_dropped_paths(&p, 1_700_000_000_000)
    }

    tauri::Builder::default()
        .manage(bridge)
        .invoke_handler(tauri::generate_handler![
            unlock_vault,
            lock_vault,
            list_media,
            import_paths
        ])
        .run(tauri::generate_context!())
        .expect("error while running MeshVault CachyOS desktop application");
}

#[cfg(not(feature = "tauri-app"))]
fn main() {
    let _bridge = DesktopVaultBridge::new();
    println!(
        "meshvault-desktop core ready (build with `--features tauri-app` and WebKitGTK on CachyOS for GUI)"
    );
}
