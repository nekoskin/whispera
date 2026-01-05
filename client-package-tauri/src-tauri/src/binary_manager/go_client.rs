use std::path::PathBuf;
use tauri::{AppHandle, Manager};
use crate::binary_manager::search_utils::{gather_possible_paths, prepare_permissions};

#[cfg(windows)]
pub const GO_CLIENT_FILENAMES: &[&str] = &[
    "whispera-go-client-x86_64-pc-windows-msvc.exe",
    "whispera-go-client.exe",
    "whispera-client.exe"
];
#[cfg(not(windows))]
pub const GO_CLIENT_FILENAMES: &[&str] = &[
    "whispera-go-client",
    "whispera-client"
];

pub fn extract_go_client(app: &AppHandle) -> Result<PathBuf, String> {
    let app_data_dir = app.path().app_data_dir().map_err(|e| e.to_string())?;
    std::fs::create_dir_all(&app_data_dir).map_err(|e| e.to_string())?;
    let target_path = app_data_dir.join(GO_CLIENT_FILENAMES[0]);

    if target_path.exists() {
        if let Ok(metadata) = std::fs::metadata(&target_path) {
            if metadata.len() > 0 {
                #[cfg(windows)] { let _ = crate::binary_manager::wintun::extract_wintun_dll(app); }
                return Ok(target_path);
            }
            let _ = std::fs::remove_file(&target_path);
        }
    }
    
    match search_and_copy_go_client(app, &target_path) {
        Ok(path) => {
            #[cfg(windows)] { let _ = crate::binary_manager::wintun::extract_wintun_dll(app); }
            Ok(path)
        },
        Err(e) => Err(e)
    }
}

fn search_and_copy_go_client(app: &AppHandle, target_path: &PathBuf) -> Result<PathBuf, String> {
    let possible_paths = gather_possible_paths(app);
    let current_exe = std::env::current_exe().ok();

    for source_path in &possible_paths {
        if source_path.exists() {
            if current_exe.as_ref().map(|exe| exe == source_path).unwrap_or(false) { continue; }
            if let Ok(metadata) = std::fs::metadata(source_path) { if metadata.len() == 0 { continue; } }
            if source_path == target_path { return Ok(target_path.clone()); }
            
            std::fs::copy(source_path, target_path).map_err(|e| format!("Failed to copy Go client: {}", e))?;
            prepare_permissions(target_path)?;
            return Ok(target_path.clone());
        }
    }
    Err(format!("Go client not found. Checked {} paths.", possible_paths.len()))
}
