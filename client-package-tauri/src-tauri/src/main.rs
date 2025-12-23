// Prevents additional console window on Windows in release, DO NOT REMOVE!!
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::sync::{Arc, Mutex};
use std::path::PathBuf;
use std::collections::HashSet;
use tauri::{AppHandle, Emitter, Manager, State};
use tauri_plugin_shell::process::CommandEvent;
use tauri_plugin_shell::ShellExt;
use serde::{Deserialize, Serialize};

#[cfg(windows)]
const GO_CLIENT_FILENAMES: &[&str] = &[
    "whispera-go-client-x86_64-pc-windows-msvc.exe", // Tauri 2.0 externalBin с суффиксом платформы
    "whispera-go-client.exe", // Fallback для dev режима
    "whispera-client.exe"
];
#[cfg(not(windows))]
const GO_CLIENT_FILENAMES: &[&str] = &[
    "whispera-go-client", // Будет добавлен суффикс платформы Tauri 2.0
    "whispera-client"
];

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ConnectionConfig {
    server_ip: String,
    server_port: u16,
    server_public_key: Option<String>,
    server_tcp_port: Option<u16>,
    server_ws_port: Option<u16>,
    server_ws2_port: Option<u16>,
    server_grpc_port: Option<u16>,      // Новый: gRPC transport
    server_quic_port: Option<u16>,      // Новый: QUIC transport
    server_http2_port: Option<u16>,     // Новый: HTTP/2 transport
    front_domain: Option<String>,       // Новый: domain fronting (DNS/TLS SNI)
    backend_domain: Option<String>,     // Новый: domain fronting (Host/authority)
    #[serde(default)]
    use_tap: bool,                      // Новый: использовать TAP вместо TUN (по умолчанию false)
    #[serde(default)]
    cert_pinning: bool,                 // Новый: включить certificate pinning (по умолчанию false)
    cert_pinning_file: Option<String>,  // Новый: файл с certificate pins
    client_private_key: Option<String>,
    #[serde(default)]
    proxy_mode: bool,                   // По умолчанию false (TUN mode)
    #[serde(default)]
    auto_profile: bool,                 // По умолчанию false
    #[serde(default)]
    monitoring: bool,                   // По умолчанию false
    app_profile: Option<String>,
    stun_server: Option<String>, // Опциональный STUN сервер для NAT discovery
    outbound_tag: Option<String>, // Опциональный outbound tag для маршрутизации
    // XHTTP параметры для VLESS протокола с Marionette обфускацией
    xhttp_public_key: Option<String>,  // XHTTP public key (ed25519, hex64)
    xhttp_short_id: Option<String>,     // XHTTP short ID (hex16)
    xhttp_server_name: Option<String>,  // XHTTP server name (e.g. example.com)
    xhttp_fingerprint: Option<String>,  // XHTTP TLS fingerprint: chrome|firefox|safari|edge
    // Дополнительные XHTTP параметры для приближения к Xray-core
    xhttp_mode: Option<String>,            // XHTTP mode: packet-up|stream-up|stream-one
    xhttp_max_concurrency: Option<u32>,    // XHTTP max concurrent streams (XMUX-like)
    xhttp_alpn: Option<String>,            // XHTTP ALPN list, e.g. "h2,http/1.1"
}

struct GoClientState {
    process: Arc<Mutex<Option<u32>>>, // Храним PID для остановки процесса
}

impl GoClientState {
    fn new() -> Self {
        Self {
            process: Arc::new(Mutex::new(None)),
        }
    }
}

/// Извлекает wintun.dll из ресурсов
fn extract_wintun_dll(app: &AppHandle) -> Result<PathBuf, String> {
    let app_data_dir = app.path().app_data_dir()
        .map_err(|e| format!("Failed to get app data dir: {}", e))?;
    
    // Создаем директорию, если не существует
    std::fs::create_dir_all(&app_data_dir)
        .map_err(|e| format!("Failed to create app data dir: {}", e))?;
    
    let target_path = app_data_dir.join("wintun.dll");

    // Проверяем, не извлечен ли уже
    if target_path.exists() {
        return Ok(target_path);
    }

    let mut possible_paths: Vec<PathBuf> = Vec::new();
    let mut seen_paths: HashSet<PathBuf> = HashSet::new();
    let current_exe = std::env::current_exe().ok();
    
    // 1. Пробуем найти в ресурсах Tauri
    if let Ok(resource_dir) = app.path().resource_dir() {
        let candidate = resource_dir.join("wintun.dll");
        if seen_paths.insert(candidate.clone()) {
            possible_paths.push(candidate);
        }
    }
    
    // 2. Добавляем пути относительно исполняемого файла
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
    
    // 3. Пробуем найти в исходной директории проекта (для dev режима)
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
    
    // 4. Пробуем найти в target/debug/resources (для dev режима)
    if let Some(ref exe_path) = current_exe {
        if let Some(exe_dir) = exe_path.parent() {
            if exe_dir.ends_with("debug") || exe_dir.ends_with("release") {
                let resources_path = exe_dir.join("resources").join("wintun.dll");
                if seen_paths.insert(resources_path.clone()) {
                    possible_paths.push(resources_path);
                }
            }
        }
    }

    // Ищем первый существующий файл
    for source_path in &possible_paths {
        if source_path.exists() {
            // Копируем в app_data_dir
            std::fs::copy(source_path, &target_path)
                .map_err(|e| format!("Failed to copy wintun.dll from {:?}: {}", source_path, e))?;
            
            return Ok(target_path);
        }
    }
    
    // Также проверяем папку wintun/bin/amd64/ (если распакован архив)
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

    // Если не нашли, возвращаем путь, но не ошибку (DLL может быть скачан автоматически)
    Ok(target_path)
}

/// Извлекает Go клиент из ресурсов
fn extract_go_client(app: &AppHandle) -> Result<PathBuf, String> {
    eprintln!("[DEBUG] extract_go_client called");
    let app_data_dir = app.path().app_data_dir()
        .map_err(|e| format!("Failed to get app data dir: {}", e))?;
    
    eprintln!("[DEBUG] AppData directory: {}", app_data_dir.display());
    
    // Создаем директорию, если не существует
    std::fs::create_dir_all(&app_data_dir)
        .map_err(|e| format!("Failed to create app data dir: {}", e))?;
    
    let target_path = app_data_dir.join(GO_CLIENT_FILENAMES[0]);
    eprintln!("[DEBUG] Target path in AppData: {}", target_path.display());

    // Проверяем, не извлечен ли уже в AppData
    if target_path.exists() {
        // Проверяем, что файл не пустой
        if let Ok(metadata) = std::fs::metadata(&target_path) {
            if metadata.len() > 0 {
                eprintln!("[INFO] Go client found in AppData: {} (size: {} bytes)", target_path.display(), metadata.len());
                // Также извлекаем wintun.dll при каждом запуске Go клиента (только на Windows)
                #[cfg(windows)]
                {
                    let _ = extract_wintun_dll(app);
                }
                return Ok(target_path);
            } else {
                eprintln!("[WARN] Go client in AppData is empty (0 bytes), will try to re-extract");
                // Удаляем пустой файл и продолжаем поиск
                let _ = std::fs::remove_file(&target_path);
            }
        }
    } else {
        eprintln!("[DEBUG] Go client not found in AppData, will search in other locations");
    }
    
    // ПРИОРИТЕТ 1: Проверяем рядом с exe приложения
    // Это самый важный путь - файл должен быть здесь после установки
    if let Some(ref exe_path) = std::env::current_exe().ok() {
        eprintln!("[DEBUG] Current exe path: {}", exe_path.display());
        if let Some(exe_dir) = exe_path.parent() {
            eprintln!("[DEBUG] Exe directory: {}", exe_dir.display());
            
            // Проверяем прямо рядом с exe
            let direct_path = exe_dir.join(GO_CLIENT_FILENAMES[0]);
            eprintln!("[DEBUG] Checking direct path: {}", direct_path.display());
            if direct_path.exists() {
                if let Ok(metadata) = std::fs::metadata(&direct_path) {
                    if metadata.len() > 0 {
                        eprintln!("[INFO] ✅ Go client found next to exe: {} (size: {} bytes)", direct_path.display(), metadata.len());
                        // Всегда копируем в AppData для будущего использования
                        eprintln!("[DEBUG] Copying to AppData: {} -> {}", direct_path.display(), target_path.display());
                        match std::fs::copy(&direct_path, &target_path) {
                            Ok(bytes_copied) => {
                                eprintln!("[SUCCESS] ✅ Go client copied to AppData: {} ({} bytes)", target_path.display(), bytes_copied);
                                #[cfg(windows)]
                                {
                                    let _ = extract_wintun_dll(app);
                                }
                                return Ok(target_path);
                            }
                            Err(e) => {
                                eprintln!("[WARN] Failed to copy to AppData: {}, using direct path", e);
                                // Используем прямой путь, если копирование не удалось
                                #[cfg(windows)]
                                {
                                    let _ = extract_wintun_dll(app);
                                }
                                return Ok(direct_path);
                            }
                        }
                    } else {
                        eprintln!("[WARN] Go client at {} is empty (0 bytes)", direct_path.display());
                    }
                }
            } else {
                eprintln!("[DEBUG] Go client not found at {}", direct_path.display());
            }
            
            // Также проверяем в поддиректориях рядом с exe
            for subdir in &["resources", "bin", "."] {
                let subdir_path = if *subdir == "." {
                    exe_dir.join(GO_CLIENT_FILENAMES[0])
                } else {
                    exe_dir.join(subdir).join(GO_CLIENT_FILENAMES[0])
                };
                
                eprintln!("[DEBUG] Checking subdirectory {}: {}", subdir, subdir_path.display());
                if subdir_path.exists() {
                    if let Ok(metadata) = std::fs::metadata(&subdir_path) {
                        if metadata.len() > 0 {
                            eprintln!("[INFO] ✅ Go client found in {}: {} (size: {} bytes)", subdir, subdir_path.display(), metadata.len());
                            // Копируем в AppData
                            eprintln!("[DEBUG] Copying to AppData: {} -> {}", subdir_path.display(), target_path.display());
                            match std::fs::copy(&subdir_path, &target_path) {
                                Ok(bytes_copied) => {
                                    eprintln!("[SUCCESS] ✅ Go client copied to AppData: {} ({} bytes)", target_path.display(), bytes_copied);
                                    #[cfg(windows)]
                                    {
                                        let _ = extract_wintun_dll(app);
                                    }
                                    return Ok(target_path);
                                }
                                Err(e) => {
                                    eprintln!("[WARN] Failed to copy to AppData: {}, using direct path", e);
                                    #[cfg(windows)]
                                    {
                                        let _ = extract_wintun_dll(app);
                                    }
                                    return Ok(subdir_path);
                                }
                            }
                        } else {
                            eprintln!("[WARN] Go client at {} is empty (0 bytes)", subdir_path.display());
                        }
                    }
                }
            }
        }
    } else {
        eprintln!("[WARN] Cannot get current exe path");
    }

    let mut possible_paths: Vec<PathBuf> = Vec::new();
    let mut seen_paths: HashSet<PathBuf> = HashSet::new();
    let current_exe = std::env::current_exe().ok();
    
    // 1. Пробуем найти в ресурсах Tauri
    if let Ok(resource_dir) = app.path().resource_dir() {
        for name in GO_CLIENT_FILENAMES {
            let candidate = resource_dir.join(name);
            if seen_paths.insert(candidate.clone()) {
                possible_paths.push(candidate);
            }
        }
    }
    
    // 2. Добавляем пути относительно исполняемого файла
    if let Some(ref exe_path) = current_exe {
        if let Some(exe_dir) = exe_path.parent() {
            for name in GO_CLIENT_FILENAMES {
                // Прямо рядом с exe
                let direct = exe_dir.join(name);
                if seen_paths.insert(direct.clone()) {
                    possible_paths.push(direct);
                }
                // В поддиректории resources
                let resources_path = exe_dir.join("resources").join(name);
                if seen_paths.insert(resources_path.clone()) {
                    possible_paths.push(resources_path);
                }
                // В поддиректории bin (для sidecar)
                let bin_path = exe_dir.join("bin").join(name);
                if seen_paths.insert(bin_path.clone()) {
                    possible_paths.push(bin_path);
                }
            }
        }
    }
    
    // 3. Пробуем найти в исходной директории проекта (для dev режима)
    if let Ok(current_dir) = std::env::current_dir() {
        for name in GO_CLIENT_FILENAMES {
            let direct = current_dir.join("src-tauri").join("resources").join(name);
            if seen_paths.insert(direct.clone()) {
                possible_paths.push(direct);
            }
            let nested = current_dir.join("client-package-tauri").join("src-tauri").join("resources").join(name);
            if seen_paths.insert(nested.clone()) {
                possible_paths.push(nested);
            }
        }
    }
    
    // 4. Пробуем найти в target/debug/resources (для dev режима)
    if let Some(ref exe_path) = current_exe {
        if let Some(exe_dir) = exe_path.parent() {
            for name in GO_CLIENT_FILENAMES {
                if exe_dir.ends_with("debug") || exe_dir.ends_with("release") {
                    let resources_path = exe_dir.join("resources").join(name);
                    if seen_paths.insert(resources_path.clone()) {
                        possible_paths.push(resources_path);
                    }
                }
            }
        }
    }
    
    // 5. Для установленного приложения на Windows - ищем в директории установки
    #[cfg(windows)]
    {
        if let Some(ref exe_path) = current_exe {
            if let Some(exe_dir) = exe_path.parent() {
                // Для установленного приложения Tauri, externalBin может быть в той же директории
                for name in GO_CLIENT_FILENAMES {
                    // Проверяем родительские директории (для случаев, когда exe в поддиректории)
                    if let Some(parent) = exe_dir.parent() {
                        let parent_direct = parent.join(name);
                        if seen_paths.insert(parent_direct.clone()) {
                            possible_paths.push(parent_direct);
                        }
                    }
                    // Проверяем на уровень выше в resources
                    if let Some(parent) = exe_dir.parent() {
                        let parent_resources = parent.join("resources").join(name);
                        if seen_paths.insert(parent_resources.clone()) {
                            possible_paths.push(parent_resources);
                        }
                    }
                }
            }
        }
        
        // Также пробуем найти в стандартных местах установки
        if let Ok(program_files) = std::env::var("ProgramFiles") {
            let program_files_path = PathBuf::from(program_files);
            for name in GO_CLIENT_FILENAMES {
                let candidate = program_files_path.join("Whispera Client").join(name);
                if seen_paths.insert(candidate.clone()) {
                    possible_paths.push(candidate);
                }
                let candidate_resources = program_files_path.join("Whispera Client").join("resources").join(name);
                if seen_paths.insert(candidate_resources.clone()) {
                    possible_paths.push(candidate_resources);
                }
            }
        }
        
        // Пробуем LocalAppData
        if let Ok(local_app_data) = std::env::var("LOCALAPPDATA") {
            let local_app_data_path = PathBuf::from(local_app_data);
            for name in GO_CLIENT_FILENAMES {
                let candidate = local_app_data_path.join("Programs").join("whispera-client").join(name);
                if seen_paths.insert(candidate.clone()) {
                    possible_paths.push(candidate);
                }
            }
        }
    }

    // Ищем первый существующий файл
    for source_path in &possible_paths {
        if source_path.exists() {
            if current_exe.as_ref().map(|exe| exe == source_path).unwrap_or(false) {
                continue;
            }
            
            // Проверяем размер файла перед копированием
            if let Ok(metadata) = std::fs::metadata(source_path) {
                if metadata.len() == 0 {
                    eprintln!("[WARN] Skipping empty file: {}", source_path.display());
                    continue;
                }
                eprintln!("[INFO] Found Go client at: {} (size: {} bytes)", source_path.display(), metadata.len());
            }
            
            // Если файл уже в AppData, используем его напрямую
            if source_path == &target_path {
                eprintln!("[INFO] Using Go client from AppData: {}", target_path.display());
                #[cfg(windows)]
                {
                    let _ = extract_wintun_dll(app);
                }
                return Ok(target_path);
            }
            
            // Копируем в app_data_dir
            eprintln!("[INFO] Copying Go client from {} to {}", source_path.display(), target_path.display());
            std::fs::copy(source_path, &target_path)
                .map_err(|e| format!("Failed to copy Go client from {:?}: {}", source_path, e))?;
            
            eprintln!("[SUCCESS] Go client copied to: {}", target_path.display());
            
            #[cfg(not(windows))]
            {
                use std::os::unix::fs::PermissionsExt;
                let mut perms = std::fs::metadata(&target_path)
                    .map_err(|e| format!("Failed to get metadata: {}", e))?
                    .permissions();
                perms.set_mode(0o755);
                std::fs::set_permissions(&target_path, perms)
                    .map_err(|e| format!("Failed to set permissions: {}", e))?;
            }
            
            // Также извлекаем wintun.dll при копировании Go клиента (только на Windows)
            #[cfg(windows)]
            {
                let _ = extract_wintun_dll(app);
            }
            return Ok(target_path);
        }
    }

    // Если не нашли, возвращаем ошибку с информацией о проверенных путях
    let checked_paths: Vec<String> = possible_paths.iter()
        .map(|p| format!("  - {} ({})", p.display(), if p.exists() { "EXISTS" } else { "not found" }))
        .collect();
    
    let error_msg = format!(
        "Go client not found. Expected filename: {}\nChecked {} paths:\n{}\n\nPlease ensure the Go client binary is included in the application bundle or manually copy it to:\n  {}",
        GO_CLIENT_FILENAMES[0],
        possible_paths.len(),
        checked_paths.join("\n"),
        target_path.display()
    );
    
    eprintln!("[ERROR] {}", error_msg);
    Err(error_msg)
}

#[tauri::command]
async fn get_go_client_path(app: AppHandle) -> Result<Option<String>, String> {
    match extract_go_client(&app) {
        Ok(path) => Ok(Some(path.to_string_lossy().to_string())),
        Err(_) => Ok(None),
    }
}

#[tauri::command]
async fn start_go_client(
    config: ConnectionConfig,
    state: State<'_, GoClientState>,
    app: AppHandle,
) -> Result<serde_json::Value, String> {
    // Получаем PID существующего процесса и освобождаем мьютекс перед await
    let existing_pid = {
        let process_guard = state.process.lock().unwrap();
        *process_guard
    };
    
    if existing_pid.is_some() {
        // Проверяем, что процесс еще работает, и останавливаем его если работает
        #[cfg(windows)]
        {
            use std::process::Command;
            if let Some(pid) = existing_pid {
                let output = Command::new("tasklist")
                    .args(&["/FI", &format!("PID eq {}", pid)])
                    .output()
                    .ok();
                if let Some(output) = output {
                    let output_str = String::from_utf8_lossy(&output.stdout);
                    if output_str.contains(&pid.to_string()) {
                        // Процесс еще работает - останавливаем его
                        eprintln!("[INFO] Stopping existing Go client process (PID: {})", pid);
                        let _ = Command::new("taskkill")
                            .args(&["/F", "/PID", &pid.to_string()])
                            .output();
                        // Даем время процессу завершиться (мьютекс уже освобожден)
                        tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
                    }
                }
            }
        }
        #[cfg(not(windows))]
        {
            // Для Linux/macOS останавливаем процесс
            if let Some(pid) = existing_pid {
                use std::process::Command;
                eprintln!("[INFO] Stopping existing Go client process (PID: {})", pid);
                let _ = Command::new("kill")
                    .args(&["-TERM", &pid.to_string()])
                    .output();
                tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
            }
        }
        // Очищаем PID из состояния (мьютекс освобожден, нужно заблокировать снова)
        let mut process_guard = state.process.lock().unwrap();
        *process_guard = None;
    }

    // Сначала пробуем получить путь через extract_go_client (для fallback)
    // Но не требуем успеха - sidecar может работать без этого
    let client_path = extract_go_client(&app).unwrap_or_else(|e| {
        eprintln!("[WARN] extract_go_client failed: {}, will try sidecar first", e);
        // Возвращаем путь к AppData, даже если файл не найден - sidecar может работать
        let app_data_dir = app.path().app_data_dir().unwrap_or_else(|_| {
            std::env::temp_dir().join("whispera-client")
        });
        std::fs::create_dir_all(&app_data_dir).ok();
        app_data_dir.join(GO_CLIENT_FILENAMES[0])
    });
    
    // Проверяем, что файл существует и доступен (только если не используем sidecar)
    // Sidecar не требует существования файла в AppData
    if client_path.exists() {
        // Проверяем размер файла (должен быть > 0)
        if let Ok(metadata) = std::fs::metadata(&client_path) {
            let file_size = metadata.len();
            eprintln!("[INFO] Go client binary found: {} (size: {} bytes)", client_path.display(), file_size);
            if file_size == 0 {
                let error_msg = format!("Go client binary is empty (0 bytes) at: {}", client_path.display());
                eprintln!("[WARN] {}", error_msg);
                // Не возвращаем ошибку - sidecar может работать
            }
        }
        
        // Проверяем права на выполнение (для Unix)
        #[cfg(not(windows))]
        {
            use std::os::unix::fs::PermissionsExt;
            if let Ok(metadata) = std::fs::metadata(&client_path) {
                let perms = metadata.permissions();
                if perms.mode() & 0o111 == 0 {
                    eprintln!("[WARN] Go client at {} is not executable, will try sidecar", client_path.display());
                    // Не возвращаем ошибку - sidecar может работать
                }
            }
        }
    } else {
        eprintln!("[INFO] Go client not found at {}, will try sidecar", client_path.display());
    }

    // Формируем аргументы
    // Приоритет: GRPC > QUIC > HTTP2 > WS2 > WS > TCP > UDP
    let mut args = vec![];

    // XHTTP параметры (приоритет над обычным server-pub для TCP соединений)
    let has_xhttp = config.xhttp_public_key.is_some() 
        && config.xhttp_short_id.is_some() 
        && config.xhttp_server_name.is_some();
    
    if has_xhttp {
        // XHTTP режим - используем VLESS протокол с Marionette обфускацией
        if let Some(ref xhttp_pub) = config.xhttp_public_key {
            let trimmed = xhttp_pub.trim();
            if !trimmed.is_empty() {
                args.push("-xhttp-public-key".to_string());
                args.push(trimmed.to_string());
                eprintln!("[INFO] XHTTP public key provided (length: {})", trimmed.len());
            }
        }
        if let Some(ref xhttp_short_id) = config.xhttp_short_id {
            let trimmed = xhttp_short_id.trim();
            if !trimmed.is_empty() {
                args.push("-xhttp-short-id".to_string());
                args.push(trimmed.to_string());
                eprintln!("[INFO] XHTTP short ID provided (length: {})", trimmed.len());
            }
        }
        if let Some(ref xhttp_server_name) = config.xhttp_server_name {
            let trimmed = xhttp_server_name.trim();
            if !trimmed.is_empty() {
                args.push("-xhttp-server-name".to_string());
                args.push(trimmed.to_string());
                eprintln!("[INFO] XHTTP server name: {}", trimmed);
            }
        }
        if let Some(ref xhttp_fingerprint) = config.xhttp_fingerprint {
            let trimmed = xhttp_fingerprint.trim();
            if !trimmed.is_empty() {
                args.push("-xhttp-fingerprint".to_string());
                args.push(trimmed.to_string());
                eprintln!("[INFO] XHTTP fingerprint: {}", trimmed);
            }
        }
        // Дополнительные XHTTP настройки (mode, maxConcurrency, ALPN)
        if let Some(ref mode) = config.xhttp_mode {
            let trimmed = mode.trim();
            if !trimmed.is_empty() {
                args.push("-xhttp-mode".to_string());
                args.push(trimmed.to_string());
                eprintln!("[INFO] XHTTP mode: {}", trimmed);
            }
        }
        if let Some(max_conc) = config.xhttp_max_concurrency {
            if max_conc > 0 {
                args.push("-xhttp-max-concurrency".to_string());
                args.push(max_conc.to_string());
                eprintln!("[INFO] XHTTP max concurrency: {}", max_conc);
            }
        }
        if let Some(ref alpn) = config.xhttp_alpn {
            let trimmed = alpn.trim();
            if !trimmed.is_empty() {
                args.push("-xhttp-alpn".to_string());
                args.push(trimmed.to_string());
                eprintln!("[INFO] XHTTP ALPN: {}", trimmed);
            }
        }
        // Enable core obfuscation for Marionette integration
        args.push("-core-enable".to_string());
        eprintln!("[INFO] ✅ XHTTP+VLESS mode enabled with Marionette obfuscation");
        eprintln!("[INFO] ⚠️ NOT using -server-pub (deprecated) - using XHTTP instead");
    } else {
        // Обычный режим - устарел, рекомендуется использовать XHTTP
        // Добавляем публичный ключ только если он не пустой
        if let Some(ref pub_key) = config.server_public_key {
            let trimmed_key = pub_key.trim();
            if !trimmed_key.is_empty() {
                args.push("-server-pub".to_string());
                args.push(trimmed_key.to_string());
                eprintln!("[INFO] Server public key provided (length: {})", trimmed_key.len());
            } else {
                eprintln!("[WARN] Server public key is empty or whitespace only!");
            }
        } else {
            eprintln!("[ERROR] Server public key is missing in config! This will cause Go client to exit immediately.");
            let error_msg = "Server public key is missing. Cannot start Go client.";
            app.emit("go-client-error", error_msg).ok();
            return Err(error_msg.to_string());
        }
    }

    // Domain fronting (если указано)
    if let Some(ref front_domain) = config.front_domain {
        if !front_domain.trim().is_empty() {
            args.push("-front-domain".to_string());
            args.push(front_domain.trim().to_string());
        }
    }
    if let Some(ref backend_domain) = config.backend_domain {
        if !backend_domain.trim().is_empty() {
            args.push("-backend-domain".to_string());
            args.push(backend_domain.trim().to_string());
        }
    }

    // Новые транспорты (приоритет выше, чем старые)
    if let Some(grpc_port) = config.server_grpc_port {
        args.push("-server-grpc".to_string());
        args.push(format!("{}:{}", config.server_ip, grpc_port));
        eprintln!("[INFO] Using gRPC transport on port {}", grpc_port);
    } else if let Some(quic_port) = config.server_quic_port {
        args.push("-server-quic".to_string());
        args.push(format!("{}:{}", config.server_ip, quic_port));
        eprintln!("[INFO] Using QUIC transport on port {}", quic_port);
    } else if let Some(http2_port) = config.server_http2_port {
        args.push("-server-http2".to_string());
        args.push(format!("https://{}:{}", config.server_ip, http2_port));
        eprintln!("[INFO] Using HTTP/2 transport on port {}", http2_port);
    } else {
        // Определяем TCP порт
        let tcp_port = config.server_tcp_port
            .unwrap_or_else(|| if config.server_port == 51820 { 4443 } else { config.server_port });
        
        // Если используется XHTTP, то для порта 4443 используем ТОЛЬКО XHTTP через TCP
        // НЕ добавляем UDP, dual-mode и WebSocket, так как сервер отклоняет обычные TCP подключения
        if has_xhttp && tcp_port == 4443 {
            // XHTTP режим - используем только TCP с XHTTP, без UDP и WebSocket fallbacks
            // Новый клиент принимает только флаг -server (без -server-tcp)
            args.push("-server".to_string());
            args.push(format!("{}:{}", config.server_ip, tcp_port));
            // TLS уже включен в XHTTP, не нужно добавлять отдельно
            // НЕ добавляем -tls и -tls-skip-verify, так как XHTTP сам управляет TLS
            eprintln!("[INFO] ✅ XHTTP mode: Using TCP port {} with XHTTP+VLESS (no UDP, no dual-mode, no WebSocket, no separate TLS flags)", tcp_port);
            eprintln!("[INFO] XHTTP parameters: pub={}... shortId={}... serverName={}", 
                config.xhttp_public_key.as_ref().map(|k| &k[..16.min(k.len())]).unwrap_or(""),
                config.xhttp_short_id.as_ref().map(|k| &k[..8.min(k.len())]).unwrap_or(""),
                config.xhttp_server_name.as_ref().map(|k| k.as_str()).unwrap_or(""));
        } else {
            // Обычный режим - используем UDP и TCP с dual-mode
            // UDP основной
            args.push("-server".to_string());
            args.push(format!("{}:{}", config.server_ip, config.server_port));

            // TCP fallback (включаем dual-mode для одновременного подключения)
            // Новый клиент принимает только флаг -server (без -server-tcp)
            args.push("-server".to_string());
            args.push(format!("{}:{}", config.server_ip, tcp_port));
            
            // Включаем dual-mode для одновременного подключения UDP и TCP
            args.push("-dual-mode".to_string());
            
            // Для порта 4443 включаем TLS, так как сервер требует TLS
            if tcp_port == 4443 {
                args.push("-tls".to_string());
                args.push("-tls-skip-verify".to_string());
                eprintln!("[INFO] TCP with TLS enabled for port 4443 (dual-mode)");
            } else {
                eprintln!("[INFO] TCP fallback enabled for port {} (dual-mode, no TLS)", tcp_port);
            }

            // WebSocket fallbacks (если UDP и TCP не работают)
            // Сервер слушает WebSocket на 8080 и HTTP/2 WebSocket на 8443
            let ws_port = config.server_ws_port.unwrap_or(8080); // WebSocket порт
            let ws2_port = config.server_ws2_port.unwrap_or(8443); // HTTP/2 WebSocket
            args.push("-server-ws2".to_string());
            args.push(format!("wss://{}:{}/ws", config.server_ip, ws2_port));
            args.push("-server-ws".to_string());
            args.push(format!("wss://{}:{}/ws", config.server_ip, ws_port));
            eprintln!("[INFO] Transport priority: UDP+TCP (dual-mode) > WS2 > WS");
            eprintln!("[INFO] WebSocket ports: WS2={} (HTTP/2, TLS), WS={} (unified, TLS)", ws2_port, ws_port);
        }
    }

    if config.proxy_mode {
        args.push("-proxy-mode".to_string());
        eprintln!("[INFO] ⚠️ PROXY MODE ENABLED - IP packets will NOT be routed through VPN!");
        eprintln!("[INFO] ⚠️ To route IP packets, disable proxy mode and use TUN mode instead");
    } else {
        eprintln!("[INFO] ✅ TUN MODE - IP packets will be routed through VPN");
    }

    if config.auto_profile {
        args.push("-auto-profile".to_string());
    }

    if config.monitoring {
        args.push("-monitoring".to_string());
    }

    if let Some(ref app_profile) = config.app_profile {
        args.push("-app-profile".to_string());
        args.push(app_profile.clone());
    }

    // TAP interface (если включен)
    if config.use_tap {
        args.push("-use-tap".to_string());
        eprintln!("[INFO] Using TAP interface (L2) instead of TUN (L3)");
    }

    // Certificate pinning (если включен)
    if config.cert_pinning {
        args.push("-cert-pinning".to_string());
        if let Some(ref pinning_file) = config.cert_pinning_file {
            if !pinning_file.trim().is_empty() {
                args.push("-cert-pinning-file".to_string());
                args.push(pinning_file.trim().to_string());
            }
        }
        eprintln!("[INFO] Certificate pinning enabled");
    }

    // Добавляем STUN сервер для NAT discovery (если указан)
    // STUN сервер отправляет IP в интернет для проверки публичного IP адреса
    if let Some(ref stun_server) = config.stun_server {
        if !stun_server.is_empty() {
            args.push("-stun".to_string());
            args.push(stun_server.clone());
            eprintln!("[INFO] STUN сервер включен: {} (IP будет отправляться в интернет для проверки)", stun_server);
        }
    }

    // Добавляем outbound tag для маршрутизации (если указан)
    if let Some(ref outbound_tag) = config.outbound_tag {
        if !outbound_tag.trim().is_empty() {
            args.push("-outbound-tag".to_string());
            args.push(outbound_tag.trim().to_string());
            eprintln!("[INFO] Outbound tag установлен: {} (будет отправлен серверу после handshake)", outbound_tag);
        }
    }

    // Включаем детальное логирование пакетов для мониторинга трафика
    args.push("-verbose-packets".to_string());
    
    // НЕ используем -udp-only, чтобы при неудаче UDP клиент мог использовать TCP/WebSocket fallback
    // Это важно для работы в сетях, где UDP может быть заблокирован
    // args.push("-udp-only".to_string()); // Закомментировано для поддержки fallback

    // Логируем аргументы для отладки (через emit, чтобы видеть в GUI)
    let args_str = args.join(" ");
    eprintln!("[DEBUG] ========== GO CLIENT STARTUP ==========");
    eprintln!("[DEBUG] Client path: {}", client_path.display());
    eprintln!("[DEBUG] Client exists: {}", client_path.exists());
    if client_path.exists() {
        if let Ok(metadata) = std::fs::metadata(&client_path) {
            eprintln!("[DEBUG] Client size: {} bytes", metadata.len());
        }
    }
    eprintln!("[DEBUG] Arguments ({} total):", args.len());
    for (i, arg) in args.iter().enumerate() {
        eprintln!("[DEBUG]   [{}] {}", i, arg);
    }
    eprintln!("[DEBUG] Full command: {} {}", client_path.display(), args_str);
    eprintln!("[DEBUG] ========================================");
    
    let debug_msg = format!("[DEBUG] Starting Go client: {} {}", client_path.display(), args_str);
    eprintln!("{}", debug_msg); // Также в консоль для отладки
    
    // Пробуем отправить событие несколько раз с разными способами
    if let Err(e) = app.emit("go-client-output", &debug_msg) {
        eprintln!("[ERROR] Failed to emit go-client-output: {}", e);
    }
    
    // Также пробуем через все окна
    if let Some(window) = app.get_webview_window("main") {
        if let Err(e) = window.emit("go-client-output", &debug_msg) {
            eprintln!("[ERROR] Failed to emit to window: {}", e);
        }
    }
    
    // Запускаем процесс через Tauri shell plugin (как в Prizrak-Box)
    // Используем sidecar API для встроенного Go клиента
    // Tauri 2.0 автоматически добавляет суффикс платформы к имени из externalBin
    let (mut rx, child) = match app.shell().sidecar("whispera-go-client") {
        Ok(cmd) => {
            eprintln!("[INFO] Using sidecar for Go client");
            cmd.args(args.clone()).spawn()
                .map_err(|e| {
                    let error_msg = format!("Failed to spawn sidecar: {}. Args: {}", e, args_str);
                    eprintln!("ERROR: {}", error_msg);
                    app.emit("go-client-error", &error_msg).ok();
                    error_msg
                })?
        }
        Err(e) => {
            // Если sidecar не найден, используем путь напрямую через shell
            eprintln!("[WARN] Sidecar not found ({}), using direct path: {}", e, client_path.display());
            
            // Проверяем, что файл существует перед запуском
            if !client_path.exists() {
                // Пробуем еще раз извлечь файл с подробным логированием
                eprintln!("[INFO] Go client not found at {}, attempting to extract...", client_path.display());
                match extract_go_client(&app) {
                    Ok(extracted_path) => {
                        eprintln!("[SUCCESS] Successfully extracted Go client to: {}", extracted_path.display());
                        // Используем извлеченный путь
                        app.shell()
                            .command(extracted_path.to_string_lossy().to_string())
                            .args(args.clone())
                            .spawn()
                            .map_err(|e| {
                                let error_msg = format!("Failed to start Go client at {}: {}. Args: {}", 
                                    extracted_path.display(), e, args_str);
                                eprintln!("ERROR: {}", error_msg);
                                app.emit("go-client-error", &error_msg).ok();
                                error_msg
                            })?
                    }
                    Err(extract_err) => {
                        // Показываем подробную ошибку с инструкциями
                        let error_msg = format!(
                            "Go client not found and cannot be extracted.\n\nSidecar error: {}\nExtract error: {}\n\nExpected location: {}\n\nPlease:\n1. Find whispera-go-client-x86_64-pc-windows-msvc.exe in the application installation directory\n2. Copy it to: {}\n3. Restart the application",
                            e, extract_err, client_path.display(), client_path.display()
                        );
                        eprintln!("ERROR: {}", error_msg);
                        app.emit("go-client-error", &error_msg).ok();
                        return Err(error_msg);
                    }
                }
            } else {
                eprintln!("[INFO] Using Go client from: {}", client_path.display());
                app.shell()
                    .command(client_path.to_string_lossy().to_string())
                    .args(args.clone())
                    .spawn()
                    .map_err(|e| {
                        let error_msg = format!("Failed to start Go client at {}: {}. Args: {}", 
                            client_path.display(), e, args_str);
                        eprintln!("ERROR: {}", error_msg);
                        app.emit("go-client-error", &error_msg).ok();
                        error_msg
                    })?
            }
        }
    };

    let pid = child.pid();
    eprintln!("[DEBUG] Go client spawned with PID: {}", pid);
    let startup_msg = format!("[DEBUG] Go client process started (PID: {})", pid);
    eprintln!("[DEBUG] Emitting startup message: {}", startup_msg);
    if let Err(e) = app.emit("go-client-output", &startup_msg) {
        eprintln!("[ERROR] Failed to emit go-client-output (startup): {}", e);
    }
    // Также пробуем через окно
    if let Some(window) = app.get_webview_window("main") {
        if let Err(e) = window.emit("go-client-output", &startup_msg) {
            eprintln!("[ERROR] Failed to emit to window (startup): {}", e);
        }
    }
    
    // Немедленно проверяем, не завершился ли процесс (как в Prizrak-Box)
    let app_check = app.clone();
    let pid_check = pid;
    tokio::spawn(async move {
        tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
        #[cfg(windows)]
        {
            use std::process::Command;
            if let Ok(output) = Command::new("tasklist")
                .args(&["/FI", &format!("PID eq {}", pid_check)])
                .output()
            {
                let output_str = String::from_utf8_lossy(&output.stdout);
                if !output_str.contains(&pid_check.to_string()) {
                    let msg = format!("[ERROR] Go client process (PID: {}) exited immediately after start. Check if client binary exists and is executable.", pid_check);
                    eprintln!("{}", msg);
                    if let Err(e) = app_check.emit("go-client-error", &msg) {
                        eprintln!("[ERROR] Failed to emit error message: {}", e);
                    }
                    // Также через окно
                    if let Some(window) = app_check.get_webview_window("main") {
                        if let Err(e) = window.emit("go-client-error", &msg) {
                            eprintln!("[ERROR] Failed to emit error to window: {}", e);
                        }
                    }
                } else {
                    let msg = format!("[INFO] Go client process (PID: {}) is running", pid_check);
                    eprintln!("{}", msg);
                    if let Err(e) = app_check.emit("go-client-output", &msg) {
                        eprintln!("[ERROR] Failed to emit info message: {}", e);
                    }
                }
            }
        }
    });
    
    // Обрабатываем события от процесса (stdout, stderr, exit) - как в Prizrak-Box
    let app_events = app.clone();
    let process_arc = Arc::clone(&state.process);
    let output_counters = Arc::new(std::sync::Mutex::new((0u32, 0u32))); // (stdout_count, stderr_count)
    
    // Отправляем тестовое событие сразу после запуска
    let test_msg = format!("[TEST] Event system is working. Process PID: {}", pid);
    eprintln!("{}", test_msg);
    if let Err(e) = app_events.emit("go-client-output", &test_msg) {
        eprintln!("[ERROR] Failed to emit test message: {}", e);
    }
    // Также через окно
    if let Some(window) = app.get_webview_window("main") {
        if let Err(e) = window.emit("go-client-output", &test_msg) {
            eprintln!("[ERROR] Failed to emit test message to window: {}", e);
        }
    }
    
    // Таймаут для проверки, не завис ли процесс
    let timeout_task = {
        let app_timeout = app_events.clone();
        let pid_timeout = pid;
        let counters_timeout = Arc::clone(&output_counters);
        tokio::spawn(async move {
            tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
            let (stdout_count, stderr_count) = *counters_timeout.lock().unwrap();
            if stdout_count == 0 && stderr_count == 0 {
                let warning = format!("[WARN] Go client (PID: {}) produced no output in 5 seconds. Process may be stuck or crashed silently.", pid_timeout);
                eprintln!("{}", warning);
                if let Err(e) = app_timeout.emit("go-client-error", &warning) {
                    eprintln!("[ERROR] Failed to emit go-client-error: {}", e);
                }
            }
        })
    };
    
    tokio::spawn(async move {
        eprintln!("[DEBUG] Starting event loop for Go client process (PID: {})", pid);
        let event_count = Arc::new(std::sync::Mutex::new(0u32));
        let last_event_time = Arc::new(std::sync::Mutex::new(std::time::Instant::now()));
        
        // Таймаут для проверки, что события приходят
        let app_timeout_check = app_events.clone();
        let last_event_time_check = Arc::clone(&last_event_time);
        let event_count_check = Arc::clone(&event_count);
        let pid_for_timeout = pid;
        let _event_timeout = tokio::spawn(async move {
            loop {
                tokio::time::sleep(tokio::time::Duration::from_secs(10)).await;
                let elapsed = last_event_time_check.lock().unwrap().elapsed();
                let count = *event_count_check.lock().unwrap();
                if elapsed.as_secs() > 10 && count == 0 {
                    let warning = format!("[WARN] No events received from Go client (PID: {}) in 10 seconds. Process may be stuck or not producing output.", pid_for_timeout);
                    eprintln!("{}", warning);
                    if let Err(e) = app_timeout_check.emit("go-client-error", &warning) {
                        eprintln!("[ERROR] Failed to emit timeout warning: {}", e);
                    }
                }
            }
        });
        
        while let Some(event) = rx.recv().await {
            let mut count = event_count.lock().unwrap();
            *count += 1;
            let current_count = *count;
            drop(count); // Освобождаем мьютекс перед использованием
            *last_event_time.lock().unwrap() = std::time::Instant::now();
            eprintln!("[DEBUG] Received event #{}: {:?}", current_count, std::mem::discriminant(&event));
            match event {
                CommandEvent::Stdout(line) => {
                    let mut counters = output_counters.lock().unwrap();
                    counters.0 += 1;
                    let stdout_count = counters.0;
                    // line это Vec<u8>, конвертируем в String
                    let line_str = String::from_utf8_lossy(&line);
                    let trimmed = line_str.trim();
                    if !trimmed.is_empty() {
                        eprintln!("[STDOUT #{}] {}", stdout_count, trimmed);
                        if let Err(e) = app_events.emit("go-client-output", trimmed) {
                            eprintln!("[ERROR] Failed to emit go-client-output: {}", e);
                        }
                    }
                }
                CommandEvent::Stderr(line) => {
                    let mut counters = output_counters.lock().unwrap();
                    counters.1 += 1;
                    let stderr_count = counters.1;
                    // line это Vec<u8>, конвертируем в String
                    let line_str = String::from_utf8_lossy(&line);
                    let trimmed = line_str.trim();
                    if !trimmed.is_empty() {
                        eprintln!("[STDERR #{}] {}", stderr_count, trimmed);
                        // Отправляем в go-client-output для всех сообщений (включая INFO)
                        // go-client-error только для реальных ошибок
                        if trimmed.contains("[FATAL]") || trimmed.contains("[ERROR]") || trimmed.contains("error:") || trimmed.contains("failed:") {
                            if let Err(e) = app_events.emit("go-client-error", trimmed) {
                                eprintln!("[ERROR] Failed to emit go-client-error: {}", e);
                            }
                        } else {
                            // INFO, DEBUG, INIT и другие сообщения идут в go-client-output
                            if let Err(e) = app_events.emit("go-client-output", trimmed) {
                                eprintln!("[ERROR] Failed to emit go-client-output: {}", e);
                            }
                        }
                    }
                }
                CommandEvent::Terminated(term) => {
                    timeout_task.abort(); // Отменяем таймаут
                    // term.code это Option<i32>
                    let code = term.code.unwrap_or(-1);
                    process_arc.lock().unwrap().take();
                    let (stdout_count, stderr_count) = *output_counters.lock().unwrap();
                    let exit_msg = if code == 0 {
                        format!("Go client exited normally (code: {})", code)
                    } else {
                        format!("Go client exited with error code: {} (received {} stdout, {} stderr events)", code, stdout_count, stderr_count)
                    };
                    eprintln!("{}", exit_msg);
                    if let Err(e) = app_events.emit("go-client-output", &exit_msg) {
                        eprintln!("[ERROR] Failed to emit go-client-output (exit): {}", e);
                    }
                    if let Err(e) = app_events.emit("go-client-exit", code) {
                        eprintln!("[ERROR] Failed to emit go-client-exit: {}", e);
                    }
                    
                    eprintln!("[EXIT] Exit code: {}, stdout events: {}, stderr events: {}", code, stdout_count, stderr_count);
                    if stdout_count == 0 && stderr_count == 0 {
                        let warning = format!("[ERROR] Go client produced NO OUTPUT before exit (code: {}). This usually means:\n  1. Client binary is missing or not executable\n  2. Client crashed immediately on startup\n  3. Client cannot write to stdout/stderr\n  4. Missing dependencies (wintun.dll on Windows)\n  Check the client binary path and permissions.", code);
                        eprintln!("{}", warning);
                        if let Err(e) = app_events.emit("go-client-error", &warning) {
                            eprintln!("[ERROR] Failed to emit go-client-error (no output): {}", e);
                        }
                    } else {
                        // Есть вывод, но процесс все равно упал - это может быть ошибка в аргументах
                        let warning = format!("[ERROR] Go client exited with code {} after producing {} stdout and {} stderr messages. Check the output above for error details.", code, stdout_count, stderr_count);
                        eprintln!("{}", warning);
                        if let Err(e) = app_events.emit("go-client-error", &warning) {
                            eprintln!("[ERROR] Failed to emit go-client-error: {}", e);
                        }
                    }
                    let final_count = *event_count.lock().unwrap();
                    eprintln!("[DEBUG] Event loop ended for Go client process (total events: {})", final_count);
                    break;
                }
                _ => {}
            }
        }
    });

    // Сохраняем только PID (нужно заблокировать мьютекс снова)
    {
        let mut process_guard = state.process.lock().unwrap();
        *process_guard = Some(pid);
    }

    Ok(serde_json::json!({
        "success": true,
        "pid": pid
    }))
}

#[tauri::command]
async fn check_go_client_process(pid: u32) -> Result<serde_json::Value, String> {
    #[cfg(windows)]
    {
        use std::process::Command;
        let output = Command::new("tasklist")
            .args(&["/FI", &format!("PID eq {}", pid)])
            .output()
            .map_err(|e| format!("Failed to check process: {}", e))?;
        
        let output_str = String::from_utf8_lossy(&output.stdout);
        let running = output_str.contains(&pid.to_string());
        
        Ok(serde_json::json!({
            "running": running,
            "pid": pid
        }))
    }
    
    #[cfg(not(windows))]
    {
        use std::process::Command;
        let output = Command::new("ps")
            .args(&["-p", &pid.to_string()])
            .output()
            .map_err(|e| format!("Failed to check process: {}", e))?;
        
        let running = !output.stdout.is_empty();
        
        Ok(serde_json::json!({
            "running": running,
            "pid": pid
        }))
    }
}

#[tauri::command]
async fn stop_go_client(state: State<'_, GoClientState>) -> Result<serde_json::Value, String> {
    let mut process_guard = state.process.lock().unwrap();
    
    if let Some(pid) = *process_guard {
        #[cfg(windows)]
        {
            use std::process::Command;
            Command::new("taskkill")
                .args(&["/F", "/PID", &pid.to_string()])
                .output()
                .map_err(|e| format!("Failed to kill process: {}", e))?;
        }
        #[cfg(not(windows))]
        {
            use std::process::Command;
            Command::new("kill")
                .args(&["-9", &pid.to_string()])
                .output()
                .map_err(|e| format!("Failed to kill process: {}", e))?;
        }
        *process_guard = None;
        Ok(serde_json::json!({ "success": true }))
    } else {
        Err("Go client is not running".to_string())
    }
}

// Создаем HTTP клиент с поддержкой сертификатов
// Использует HTTPS для всех запросов
// Поддерживает как доверенные сертификаты (Let's Encrypt), так и самоподписанные (для обратной совместимости)
fn create_http_client() -> Result<reqwest::Client, String> {
    reqwest::Client::builder()
        .danger_accept_invalid_certs(true) // Принимаем самоподписанные сертификаты (для обратной совместимости)
        // Примечание: с Let's Encrypt сертификатами это не требуется, но не мешает работе
        .timeout(std::time::Duration::from_secs(5))
        .build()
        .map_err(|e| format!("Failed to create HTTP client: {}", e))
}

#[tauri::command]
async fn get_server_public_key(server_ip: String) -> Result<serde_json::Value, String> {
    // Используем только HTTPS порты для безопасности
    let api_ports = vec![8081, 8443, 443];
    let client = create_http_client()?;
    
    for port in api_ports {
        // Все порты используют HTTPS
        let url = format!("https://{}:{}/api/system/info", server_ip, port);
        
        match client.get(&url).send().await {
            Ok(response) => {
                if response.status().is_success() {
                    if let Ok(json) = response.json::<serde_json::Value>().await {
                        if let Some(pub_key) = json.get("server_pub")
                            .or_else(|| json.get("serverPublicKey"))
                            .and_then(|v| v.as_str()) {
                            return Ok(serde_json::json!({
                                "success": true,
                                "key": pub_key
                            }));
                        }
                    }
                } else {
                    // Продолжаем пробовать другие порты при неуспешном статусе
                    continue;
                }
            }
            Err(e) => {
                // Логируем только реальные ошибки (не таймауты/соединения)
                // TLS ошибки от внешних сканеров игнорируем
                if !e.is_timeout() && !e.is_connect() {
                    eprintln!("[DEBUG] API request error on port {}: {}", port, e);
                }
                continue;
            }
        }
    }
    
    Err("Failed to get server public key from any HTTPS port".to_string())
}

#[tauri::command]
async fn get_server_traffic_stats(server_ip: String, token: Option<String>) -> Result<serde_json::Value, String> {
    // Используем только HTTPS порты для безопасности
    let api_ports = vec![8081, 8443, 443];
    let client = create_http_client()?;
    
    for port in api_ports {
        // Все порты используют HTTPS
        let url = format!("https://{}:{}/api/stats/traffic", server_ip, port);
        
        let mut request = client.get(&url);
        
        if let Some(ref t) = token {
            request = request.header("Authorization", format!("Bearer {}", t));
        }
        
        match request.send().await {
            Ok(response) => {
                if response.status().is_success() {
                    if let Ok(json) = response.json::<serde_json::Value>().await {
                        return Ok(serde_json::json!({
                            "success": true,
                            "data": json
                        }));
                    }
                } else {
                    // Продолжаем пробовать другие порты
                    continue;
                }
            }
            Err(e) => {
                // Игнорируем ошибки от внешних сканеров
                if !e.is_timeout() && !e.is_connect() {
                    eprintln!("[DEBUG] Traffic stats request error on port {}: {}", port, e);
                }
                continue;
            }
        }
    }
    
    Err("Failed to get traffic stats from any HTTPS port".to_string())
}

#[cfg(windows)]
#[tauri::command]
async fn is_admin() -> Result<bool, String> {
    use winapi::um::winnt::TOKEN_QUERY;
    use winapi::um::processthreadsapi::GetCurrentProcess;
    use winapi::um::processthreadsapi::OpenProcessToken;
    use winapi::um::winnt::HANDLE;
    use winapi::um::handleapi::CloseHandle;
    use winapi::um::winbase::GetTokenInformation;
    use winapi::um::winnt::TokenElevation;
    use std::ptr;
    
    // Используем структуру из winapi
    #[repr(C)]
    struct TOKEN_ELEVATION {
        TokenIsElevated: winapi::shared::minwindef::DWORD,
    }
    
    unsafe {
        let mut token: HANDLE = ptr::null_mut();
        let process = GetCurrentProcess();
        
        if OpenProcessToken(process, TOKEN_QUERY, &mut token) == 0 {
            return Ok(false);
        }
        
        let mut elevation = TOKEN_ELEVATION { TokenIsElevated: 0 };
        let mut size: winapi::shared::minwindef::DWORD = 0;
        
        let result = GetTokenInformation(
            token,
            TokenElevation,
            &mut elevation as *mut _ as *mut _,
            std::mem::size_of::<TOKEN_ELEVATION>() as u32,
            &mut size,
        );
        
        CloseHandle(token);
        
        Ok(result != 0 && elevation.TokenIsElevated != 0)
    }
}

#[cfg(not(windows))]
#[tauri::command]
async fn is_admin() -> Result<bool, String> {
    // На Linux/macOS проверяем через sudo
    use std::process::Command;
    let output = Command::new("id")
        .arg("-u")
        .output()
        .map_err(|e| format!("Failed to check admin: {}", e))?;
    
    if output.status.success() {
        let uid = String::from_utf8_lossy(&output.stdout).trim().parse::<u32>().unwrap_or(1000);
        Ok(uid == 0)
    } else {
        Ok(false)
    }
}

#[cfg(windows)]
#[tauri::command]
async fn set_autostart(enabled: bool) -> Result<serde_json::Value, String> {
    use std::process::Command;
    use std::path::PathBuf;
    
    // Получаем путь к исполняемому файлу
    let exe_path = std::env::current_exe()
        .map_err(|e| format!("Failed to get exe path: {}", e))?;
    
    let exe_path_str = exe_path.to_string_lossy().replace('\\', "\\\\");
    let task_name = "WhisperaClientAutostart";
    
    if enabled {
        // Создаем задачу в Task Scheduler с правами администратора
        // Используем schtasks для создания задачи, которая запускается при входе пользователя
        // с правами администратора (highest level)
        let xml_content = format!(
            r#"<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.4" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Description>Whispera Client Auto-start with Administrator privileges</Description>
    <Author>Whispera</Author>
  </RegistrationInfo>
  <Triggers>
    <LogonTrigger>
      <Enabled>true</Enabled>
      <UserId>{}</UserId>
    </LogonTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author">
      <UserId>{}</UserId>
      <LogonType>InteractiveToken</LogonType>
      <RunLevel>HighestAvailable</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <AllowHardTerminate>true</AllowHardTerminate>
    <StartWhenAvailable>true</StartWhenAvailable>
    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
    <IdleSettings>
      <StopOnIdleEnd>false</StopOnIdleEnd>
      <RestartOnIdle>false</RestartOnIdle>
    </IdleSettings>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
    <Hidden>false</Hidden>
    <RunOnlyIfIdle>false</RunOnlyIfIdle>
    <WakeToRun>false</WakeToRun>
    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
    <Priority>7</Priority>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>{}</Command>
    </Exec>
  </Actions>
</Task>"#,
            whoami::username(),
            whoami::username(),
            exe_path_str
        );
        
        // Сохраняем XML во временный файл
        let temp_dir = std::env::temp_dir();
        let xml_path = temp_dir.join("whispera_autostart.xml");
        std::fs::write(&xml_path, xml_content)
            .map_err(|e| format!("Failed to write XML: {}", e))?;
        
        // Создаем задачу через schtasks
        let output = Command::new("schtasks")
            .args(&[
                "/Create",
                "/TN", task_name,
                "/XML", &xml_path.to_string_lossy(),
                "/F" // Принудительно (force)
            ])
            .output()
            .map_err(|e| format!("Failed to create task: {}", e))?;
        
        // Удаляем временный файл
        let _ = std::fs::remove_file(&xml_path);
        
        if output.status.success() {
            Ok(serde_json::json!({
                "success": true,
                "message": "Autostart enabled with administrator privileges"
            }))
        } else {
            let error_msg = String::from_utf8_lossy(&output.stderr);
            Err(format!("Failed to create task: {}", error_msg))
        }
    } else {
        // Удаляем задачу
        let output = Command::new("schtasks")
            .args(&["/Delete", "/TN", task_name, "/F"])
            .output()
            .map_err(|e| format!("Failed to delete task: {}", e))?;
        
        if output.status.success() {
            Ok(serde_json::json!({
                "success": true,
                "message": "Autostart disabled"
            }))
        } else {
            // Игнорируем ошибку, если задача не существует
            let error_msg = String::from_utf8_lossy(&output.stderr);
            if error_msg.contains("does not exist") {
                Ok(serde_json::json!({
                    "success": true,
                    "message": "Autostart already disabled"
                }))
            } else {
                Err(format!("Failed to delete task: {}", error_msg))
            }
        }
    }
}

#[cfg(not(windows))]
#[tauri::command]
async fn set_autostart(enabled: bool) -> Result<serde_json::Value, String> {
    // На Linux/macOS используем systemd или launchd
    #[cfg(target_os = "linux")]
    {
        use std::fs;
        use std::path::PathBuf;
        
        let exe_path = std::env::current_exe()
            .map_err(|e| format!("Failed to get exe path: {}", e))?;
        
        let service_file = format!(
            r#"[Unit]
Description=Whispera Client
After=network.target

[Service]
Type=simple
ExecStart={} --autostart
Restart=always
User=root

[Install]
WantedBy=multi-user.target"#,
            exe_path.display()
        );
        
        let service_path = PathBuf::from("/etc/systemd/system/whispera-client.service");
        
        if enabled {
            fs::write(&service_path, service_file)
                .map_err(|e| format!("Failed to write service file: {}", e))?;
            
            use std::process::Command;
            Command::new("systemctl")
                .args(&["enable", "whispera-client.service"])
                .output()
                .map_err(|e| format!("Failed to enable service: {}", e))?;
            
            Ok(serde_json::json!({
                "success": true,
                "message": "Autostart enabled"
            }))
        } else {
            use std::process::Command;
            Command::new("systemctl")
                .args(&["disable", "whispera-client.service"])
                .output()
                .ok();
            
            fs::remove_file(&service_path).ok();
            
            Ok(serde_json::json!({
                "success": true,
                "message": "Autostart disabled"
            }))
        }
    }
    
    #[cfg(target_os = "macos")]
    {
        use std::fs;
        use std::path::PathBuf;
        
        let exe_path = std::env::current_exe()
            .map_err(|e| format!("Failed to get exe path: {}", e))?;
        
        let plist_content = format!(
            r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.whispera.client</string>
    <key>ProgramArguments</key>
    <array>
        <string>{}</string>
        <string>--autostart</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
</dict>
</plist>"#,
            exe_path.display()
        );
        
        let plist_path = PathBuf::from(format!(
            "{}/Library/LaunchAgents/com.whispera.client.plist",
            std::env::var("HOME").unwrap_or_default()
        ));
        
        if enabled {
            fs::write(&plist_path, plist_content)
                .map_err(|e| format!("Failed to write plist: {}", e))?;
            
            use std::process::Command;
            Command::new("launchctl")
                .args(&["load", &plist_path.to_string_lossy()])
                .output()
                .map_err(|e| format!("Failed to load plist: {}", e))?;
            
            Ok(serde_json::json!({
                "success": true,
                "message": "Autostart enabled"
            }))
        } else {
            use std::process::Command;
            Command::new("launchctl")
                .args(&["unload", &plist_path.to_string_lossy()])
                .output()
                .ok();
            
            fs::remove_file(&plist_path).ok();
            
            Ok(serde_json::json!({
                "success": true,
                "message": "Autostart disabled"
            }))
        }
    }
    
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        Err("Autostart not supported on this platform".to_string())
    }
}

#[cfg(windows)]
#[tauri::command]
async fn get_autostart_status() -> Result<serde_json::Value, String> {
    use std::process::Command;
    
    let task_name = "WhisperaClientAutostart";
    
    let output = Command::new("schtasks")
        .args(&["/Query", "/TN", task_name, "/FO", "LIST"])
        .output()
        .map_err(|e| format!("Failed to query task: {}", e))?;
    
    if output.status.success() {
        Ok(serde_json::json!({
            "enabled": true,
            "message": "Autostart is enabled"
        }))
    } else {
        let error_msg = String::from_utf8_lossy(&output.stderr);
        if error_msg.contains("does not exist") {
            Ok(serde_json::json!({
                "enabled": false,
                "message": "Autostart is disabled"
            }))
        } else {
            Err(format!("Failed to query task: {}", error_msg))
        }
    }
}

#[cfg(not(windows))]
#[tauri::command]
async fn get_autostart_status() -> Result<serde_json::Value, String> {
    #[cfg(target_os = "linux")]
    {
        use std::process::Command;
        let output = Command::new("systemctl")
            .args(&["is-enabled", "whispera-client.service"])
            .output()
            .map_err(|e| format!("Failed to check service: {}", e))?;
        
        Ok(serde_json::json!({
            "enabled": output.status.success(),
            "message": if output.status.success() { "Autostart is enabled" } else { "Autostart is disabled" }
        }))
    }
    
    #[cfg(target_os = "macos")]
    {
        use std::path::PathBuf;
        let plist_path = PathBuf::from(format!(
            "{}/Library/LaunchAgents/com.whispera.client.plist",
            std::env::var("HOME").unwrap_or_default()
        ));
        
        Ok(serde_json::json!({
            "enabled": plist_path.exists(),
            "message": if plist_path.exists() { "Autostart is enabled" } else { "Autostart is disabled" }
        }))
    }
    
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        Ok(serde_json::json!({
            "enabled": false,
            "message": "Autostart not supported on this platform"
        }))
    }
}

#[tauri::command]
async fn get_client_config_by_key(server_ip: String, private_key: String) -> Result<serde_json::Value, String> {
    // Используем только HTTPS порты для безопасности
    let api_ports = vec![8081, 8443, 443];
    
    let request_body = serde_json::json!({
        "privateKey": private_key
    });
    
    // Создаем клиент с поддержкой самоподписанных сертификатов
    let client = create_http_client()?;
    
    for port in api_ports {
        // Все порты используют HTTPS
        let url = format!("https://{}:{}/api/client/config-by-key", server_ip, port);
        
        match client
            .post(&url)
            .json(&request_body)
            .send()
            .await
        {
            Ok(response) => {
                if response.status().is_success() {
                    if let Ok(json) = response.json::<serde_json::Value>().await {
                        return Ok(json);
                    }
                } else {
                    // Продолжаем пробовать другие порты
                    continue;
                }
            }
            Err(e) => {
                // Игнорируем ошибки от внешних сканеров и таймауты
                // TLS ошибки могут быть от порт-сканеров из интернета
                if !e.is_timeout() && !e.is_connect() {
                    eprintln!("[DEBUG] Config request error on port {}: {}", port, e);
                }
                continue; // Пробуем следующий порт
            }
        }
    }
    
    Err("API server not available or timeout".to_string())
}

fn main() {
    tauri::Builder::default()
        .plugin(tauri_plugin_shell::init())
        .manage(GoClientState::new())
        .invoke_handler(tauri::generate_handler![
            check_go_client_process,
            get_go_client_path,
            start_go_client,
            stop_go_client,
            get_server_public_key,
            get_server_traffic_stats,
            get_client_config_by_key,
            is_admin,
            set_autostart,
            get_autostart_status
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}



