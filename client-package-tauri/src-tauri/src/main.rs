use tauri::Manager;
use tauri::api::process::{Command, CommandEvent};
use std::sync::{Arc, Mutex};
use std::process::Command as StdCommand;

struct AppState {
    child_process: Arc<Mutex<Option<tauri::api::process::CommandChild>>>,
    current_server_ip: Arc<Mutex<Option<String>>>,
}

fn get_default_gateway() -> String {
    let output = StdCommand::new("powershell")
        .args(["-Command", "Get-NetRoute -DestinationPrefix 0.0.0.0/0 | Select-Object -ExpandProperty NextHop"])
        .output()
        .expect("Failed to get gateway");
    
    String::from_utf8_lossy(&output.stdout).trim().to_string()
}

fn kill_all_processes() {
    println!("Cleaning up processes...");
    let _ = StdCommand::new("taskkill").args(["/F", "/IM", "whispera-go-client.exe"]).output();
    let _ = StdCommand::new("taskkill").args(["/F", "/IM", "hev-socks5-tunnel.exe"]).output();
}

fn setup_routes(server_ip: &str) {
    let gateway = get_default_gateway();
    println!("Setting up routes. Server: {}, Gateway: {}", server_ip, gateway);

    // 1. Route for VPN server via default gateway
    let _ = StdCommand::new("route")
        .args(["add", server_ip, "mask", "255.255.255.255", &gateway, "metric", "1"])
        .output();

    // 2. TUN routes (split 0.0.0.0/0 into two halves to override default)
    let _ = StdCommand::new("route")
        .args(["add", "0.0.0.0", "mask", "128.0.0.0", "10.0.85.1", "metric", "1"])
        .output();
    let _ = StdCommand::new("route")
        .args(["add", "128.0.0.0", "mask", "128.0.0.0", "10.0.85.1", "metric", "1"])
        .output();
}

fn remove_routes(server_ip: &str) {
    println!("Removing routes...");
    let _ = StdCommand::new("route").args(["delete", server_ip]).output();
    let _ = StdCommand::new("route").args(["delete", "0.0.0.0", "mask", "128.0.0.0"]).output();
    let _ = StdCommand::new("route").args(["delete", "128.0.0.0", "mask", "128.0.0.0"]).output();
}

#[tauri::command]
fn connect(key: String, state: tauri::State<AppState>) {
    println!("Connecting with key: {}", key);

    // Parse Server IP from key: whispera://IP:PORT?params
    let server_ip = if let Some(stripped) = key.strip_prefix("whispera://") {
        stripped.split(':').next().unwrap_or("").to_string()
    } else {
        println!("Invalid key format");
        return;
    };
    
    // Cleanup previous state
    {
        let mut child_guard = state.child_process.lock().unwrap();
        if child_guard.is_some() {
            kill_all_processes();
            if let Some(old_ip) = state.current_server_ip.lock().unwrap().as_ref() {
                remove_routes(old_ip);
            }
            *child_guard = None;
        }
    }

    let sidecar_res = Command::new_sidecar("whispera-go-client");
    if let Err(e) = sidecar_res {
         println!("Failed to create sidecar command: {}", e);
         return;
    }

    let (mut rx, child) = sidecar_res.unwrap()
        .args(["-key", &key])
        .spawn()
        .expect("Failed to spawn sidecar");

    *state.child_process.lock().unwrap() = Some(child);
    *state.current_server_ip.lock().unwrap() = Some(server_ip.clone());

    // Wait a bit for TUN interface to come up (rudimentary)
    let ip_clone = server_ip.clone();
    std::thread::spawn(move || {
        std::thread::sleep(std::time::Duration::from_secs(3));
        setup_routes(&ip_clone);
    });

    tauri::async_runtime::spawn(async move {
        while let Some(event) = rx.recv().await {
            match event {
                CommandEvent::Stdout(line) => println!("SIDECAR: {}", line),
                CommandEvent::Stderr(line) => println!("SIDECAR ERR: {}", line),
                _ => {}
            }
        }
    });
}

#[tauri::command]
fn disconnect(state: tauri::State<AppState>) {
    let mut child_guard = state.child_process.lock().unwrap();
    if child_guard.take().is_some() {
        kill_all_processes();
        if let Some(ip) = state.current_server_ip.lock().unwrap().take() {
            remove_routes(&ip);
        }
    } else {
        println!("No active connection.");
    }
}

fn main() {
    tauri::Builder::default()
        .manage(AppState {
            child_process: Arc::new(Mutex::new(None)),
            current_server_ip: Arc::new(Mutex::new(None)),
        })
        .invoke_handler(tauri::generate_handler![connect, disconnect])
        .setup(|app| {
            let window = app.get_window("main").unwrap();
            #[cfg(debug_assertions)]
            {
              window.open_devtools();
            }
            Ok(())
        })
        .build(tauri::generate_context!())
        .expect("error while building tauri application")
        .run(|_app_handle, event| {
            if let tauri::RunEvent::Exit = event {
                kill_all_processes();
                // Note: We can't easily access AppState here to clean routes dynamically if we don't have the IP.
                // For now, process kill is the main request.
            }
        });
}

