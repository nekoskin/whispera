// Prevents additional console window on Windows in release, DO NOT REMOVE!!
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

pub mod types;
pub mod http_utils;
pub mod binary_manager;
pub mod go_client;
pub mod commands;

use types::GoClientState;

fn main() {
    tauri::Builder::default()
        .plugin(tauri_plugin_shell::init())
        .manage(GoClientState::new())
        .invoke_handler(tauri::generate_handler![
            commands::check_go_client_process,
            commands::get_go_client_path,
            commands::start_go_client,
            commands::stop_go_client,
            commands::get_server_public_key,
            commands::get_server_traffic_stats,
            commands::get_client_config_by_key,
            commands::is_admin,
            commands::set_autostart,
            commands::get_autostart_status,
            commands::get_network_stats,
            commands::get_memory_usage,
            commands::get_active_connections
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
