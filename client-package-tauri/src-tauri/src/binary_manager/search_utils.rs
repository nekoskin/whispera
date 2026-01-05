use std::path::PathBuf;
use std::collections::HashSet;
use tauri::{AppHandle, Manager};
use crate::binary_manager::go_client::GO_CLIENT_FILENAMES;

pub fn gather_possible_paths(app: &AppHandle) -> Vec<PathBuf> {
    let mut paths = Vec::new();
    let mut seen = HashSet::new();
    let current_exe = std::env::current_exe().ok();

    if let Ok(resource_dir) = app.path().resource_dir() {
        for &name in GO_CLIENT_FILENAMES {
            let p = resource_dir.join(name);
            if seen.insert(p.clone()) { paths.push(p); }
        }
    }

    if let Some(ref exe_path) = current_exe {
        if let Some(exe_dir) = exe_path.parent() {
            for &name in GO_CLIENT_FILENAMES {
                let ps = [exe_dir.join(name), exe_dir.join("resources").join(name)];
                for p in ps { if seen.insert(p.clone()) { paths.push(p); } }
            }
        }
    }

    #[cfg(windows)]
    if let Ok(pf) = std::env::var("ProgramFiles") {
        let p = PathBuf::from(pf).join("Whispera Client").join(GO_CLIENT_FILENAMES[0]);
        if seen.insert(p.clone()) { paths.push(p); }
    }

    paths
}

pub fn prepare_permissions(_path: &PathBuf) -> Result<(), String> {
    #[cfg(not(windows))]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(_path)
            .map_err(|e| format!("Failed to get metadata: {}", e))?.permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(_path, perms).map_err(|e| format!("Failed to set permissions: {}", e))?;
    }
    Ok(())
}
