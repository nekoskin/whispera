use tauri::{AppHandle, State};
use tauri_plugin_shell::ShellExt;
use crate::types::{ConnectionConfig, GoClientState};
use crate::binary_manager::go_client::extract_go_client;
use crate::go_client::{args::build_args, supervisor::run_supervisor, stop_process, is_process_running};

#[tauri::command]
pub async fn get_go_client_path(app: AppHandle) -> Result<Option<String>, String> {
    match extract_go_client(&app) {
        Ok(path) => Ok(Some(path.to_string_lossy().to_string())),
        Err(_) => Ok(None),
    }
}

#[tauri::command]
pub async fn stop_go_client(state: State<'_, GoClientState>) -> Result<serde_json::Value, String> {
    state.stopping.store(true, std::sync::atomic::Ordering::SeqCst);
    let mut process_guard = state.process.lock().unwrap();
    if let Some(pid) = *process_guard {
        stop_process(pid);
        *process_guard = None;
        Ok(serde_json::json!({ "success": true }))
    } else { Err("Go client is not running".to_string()) }
}

#[tauri::command]
pub async fn check_go_client_process(pid: u32) -> Result<serde_json::Value, String> {
    Ok(serde_json::json!({ "running": is_process_running(pid), "pid": pid }))
}

#[tauri::command]
pub async fn start_go_client(
    config: ConnectionConfig,
    state: State<'_, GoClientState>,
    app: AppHandle,
) -> Result<serde_json::Value, String> {
    let _ = stop_go_client(state.clone()).await;

    let client_path = extract_go_client(&app)?;
    let args = build_args(&config);
    
    let (rx, child) = match app.shell().sidecar("whispera-go-client") {
        Ok(cmd) => cmd.args(args.clone()).spawn().map_err(|e| e.to_string())?,
        Err(_) => app.shell().command(client_path.to_string_lossy().to_string()).args(args.clone()).spawn().map_err(|e| e.to_string())?,
    };

    let pid = child.pid();
    *state.process.lock().unwrap() = Some(pid);
    state.stopping.store(false, std::sync::atomic::Ordering::SeqCst);

    let state_supervisor = Arc::clone(&state.process);
    let stopping_supervisor = Arc::clone(&state.stopping);
    tokio::spawn(run_supervisor(app.clone(), rx, pid, config, state_supervisor, stopping_supervisor, client_path, args));

    Ok(serde_json::json!({ "success": true, "pid": pid }))
}

use std::sync::Arc;
