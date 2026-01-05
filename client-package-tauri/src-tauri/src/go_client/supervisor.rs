use tauri::{AppHandle, Emitter};
use tauri_plugin_shell::process::CommandEvent;
use std::sync::{Arc, Mutex};
use std::sync::atomic::{AtomicBool, Ordering};
use tokio::sync::mpsc::Receiver;
use crate::types::ConnectionConfig;
use std::path::PathBuf;
use tauri_plugin_shell::ShellExt;

pub async fn run_supervisor(
    app: AppHandle,
    mut rx: Receiver<CommandEvent>,
    mut current_pid: u32,
    config: ConnectionConfig,
    state_mu: Arc<Mutex<Option<u32>>>,
    stopping: Arc<AtomicBool>,
    client_path: PathBuf,
    args: Vec<String>,
) {
    let mut restart_attempts = 0;
    loop {
        while let Some(event) = rx.recv().await {
            match event {
                CommandEvent::Stdout(line) => { app.emit("go-client-output", String::from_utf8_lossy(&line).trim()).ok(); }
                CommandEvent::Stderr(line) => {
                    let line_str = String::from_utf8_lossy(&line);
                    let trimmed = line_str.trim();
                    if trimmed.contains("[FATAL]") || trimmed.contains("[ERROR]") {
                        app.emit("go-client-error", trimmed).ok();
                    } else { app.emit("go-client-output", trimmed).ok(); }
                }
                CommandEvent::Terminated(term) => {
                    let code = term.code.unwrap_or(-1);
                    app.emit("go-client-output", format!("Go client (PID: {}) exited with code: {}", current_pid, code)).ok();
                    app.emit("go-client-exit", code).ok();
                    break;
                }
                _ => {}
            }
        }

        if stopping.load(Ordering::SeqCst) || !config.auto_restart { break; }

        restart_attempts += 1;
        if restart_attempts > 10 {
            app.emit("go-client-error", "[ERROR] Supervisor: Too many restart attempts").ok();
            break;
        }

        let delay = std::cmp::min(30, 2u64.pow(restart_attempts.min(5)));
        tokio::time::sleep(std::time::Duration::from_secs(delay)).await;
        
        if stopping.load(Ordering::SeqCst) { break; }

        let spawn_result = match app.shell().sidecar("whispera-go-client") {
            Ok(cmd) => cmd.args(args.clone()).spawn(),
            Err(_) => app.shell().command(client_path.to_string_lossy().to_string()).args(args.clone()).spawn(),
        };

        match spawn_result {
            Ok((new_rx, new_child)) => {
                rx = new_rx;
                current_pid = new_child.pid();
                *state_mu.lock().unwrap() = Some(current_pid);
                app.emit("go-client-output", format!("[INFO] Supervisor: Restarted Go client (PID: {})", current_pid)).ok();
            }
            Err(e) => {
                app.emit("go-client-error", format!("[ERROR] Supervisor: Failed to restart: {}", e)).ok();
            }
        }
    }
    *state_mu.lock().unwrap() = None;
}
