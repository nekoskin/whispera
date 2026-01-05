use std::path::PathBuf;
use std::collections::HashSet;
use tauri::{AppHandle, Manager};

/// Извлекает wintun.dll из ресурсов
pub fn extract_wintun_dll(app: &AppHandle) -> Result<PathBuf, String> {
    let app_data_dir = app.path().app_data_dir()
        .map_err(|e| format!("Failed to get app data dir: {}", e))?;
    
    std::fs::create_dir_all(&app_data_dir)
        .map_err(|e| format!("Failed to create app data dir: {}", e))?;
    
    let target_path = app_data_dir.join("wintun.dll");

    if target_path.exists() {
        return Ok(target_path);
    }

    let mut possible_paths: Vec<PathBuf> = Vec::new();
    let mut seen_paths: HashSet<PathBuf> = HashSet::new();
    let current_exe = std::env::current_exe().ok();
    
    if let Ok(resource_dir) = app.path().resource_dir() {
        let candidate = resource_dir.join("wintun.dll");
        if seen_paths.insert(candidate.clone()) {
            possible_paths.push(candidate);
        }
    }
    
    if let Some(ref exe_path) = current_exe {
        if let Some(exe_dir) = exe_path.parent() {
            let direct = exe_dir.join("wintun.dll");
            if seen_paths.insert(direct.clone()) {
                possible_paths.push(direct);
            }
            let resources_path = exe_dir.join("resources").join("wintun.dll");
            if seen_paths.insert(resources_path.clone()) {
                possible_paths.push(resources_path);
            }
        }
    }
    
    if let Ok(current_dir) = std::env::current_dir() {
        let direct = current_dir.join("src-tauri").join("resources").join("wintun.dll");
        if seen_paths.insert(direct.clone()) {
            possible_paths.push(direct);
        }
        let nested = current_dir.join("client-package-tauri").join("src-tauri").join("resources").join("wintun.dll");
        if seen_paths.insert(nested.clone()) {
            possible_paths.push(nested);
        }
    }
    
    for source_path in &possible_paths {
        if source_path.exists() {
            std::fs::copy(source_path, &target_path)
                .map_err(|e| format!("Failed to copy wintun.dll from {:?}: {}", source_path, e))?;
            
            return Ok(target_path);
        }
    }
    
    let wintun_bin_paths = vec![
        app.path().resource_dir().ok().and_then(|r| Some(r.join("wintun").join("bin").join("amd64").join("wintun.dll"))),
        current_exe.as_ref().and_then(|exe| exe.parent().map(|p| p.join("resources").join("wintun").join("bin").join("amd64").join("wintun.dll"))),
    ];
    
    for wintun_path_opt in wintun_bin_paths {
        if let Some(wintun_path) = wintun_path_opt {
            if wintun_path.exists() {
                std::fs::copy(&wintun_path, &target_path)
                    .map_err(|e| format!("Failed to copy wintun.dll from {:?}: {}", wintun_path, e))?;
                return Ok(target_path);
            }
        }
    }

    Ok(target_path)
}
