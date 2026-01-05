use crate::http_utils::create_http_client;
use std::process::Command;

#[tauri::command]
pub async fn get_server_public_key(server_ip: String, insecure: bool) -> Result<serde_json::Value, String> {
    let client = create_http_client(insecure)?;
    for port in &[8081, 8443, 443] {
        let url = format!("https://{}:{}/api/system/info", server_ip, port);
        if let Ok(resp) = client.get(&url).send().await {
            if resp.status().is_success() {
                if let Ok(json) = resp.json::<serde_json::Value>().await {
                    if let Some(key) = json.get("server_pub").or_else(|| json.get("serverPublicKey")).and_then(|v| v.as_str()) {
                        return Ok(serde_json::json!({ "success": true, "key": key }));
                    }
                }
            }
        }
    }
    Err("Failed to get public key".to_string())
}

#[tauri::command]
pub async fn get_server_traffic_stats(server_ip: String, token: Option<String>) -> Result<serde_json::Value, String> {
    let client = create_http_client(false)?;
    for port in &[8081, 8443, 443] {
        let url = format!("https://{}:{}/api/stats/traffic", server_ip, port);
        let mut req = client.get(&url);
        if let Some(ref t) = token { req = req.header("Authorization", format!("Bearer {}", t)); }
        if let Ok(resp) = req.send().await {
            if resp.status().is_success() {
                if let Ok(json) = resp.json::<serde_json::Value>().await { return Ok(serde_json::json!({ "success": true, "data": json })); }
            }
        }
    }
    Err("Failed to get traffic stats".to_string())
}

#[tauri::command]
pub async fn get_client_config_by_key(server_ip: String, private_key: String) -> Result<serde_json::Value, String> {
    let client = create_http_client(false)?;
    let body = serde_json::json!({ "privateKey": private_key });
    for port in &[8081, 8443, 443] {
        let url = format!("https://{}:{}/api/client/config-by-key", server_ip, port);
        if let Ok(resp) = client.post(&url).json(&body).send().await {
            if resp.status().is_success() {
                if let Ok(json) = resp.json::<serde_json::Value>().await { return Ok(json); }
            }
        }
    }
    Err("Failed to get config".to_string())
}

/// Get active network connections (TCP/UDP) from the system
#[tauri::command]
pub async fn get_active_connections() -> Result<serde_json::Value, String> {
    #[cfg(windows)]
    {
        println!("[Rust] Executing netstat -n -o...");
        // Run netstat to get established connections
        let output = Command::new("netstat")
            .args(&["-n", "-o"])
            .output()
            .map_err(|e| {
                println!("[Rust] Failed to run netstat: {}", e);
                e.to_string()
            })?;
        
        if output.status.success() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            println!("[Rust] netstat raw output length: {}", stdout.len());
            let mut connections: Vec<serde_json::Value> = Vec::new();
            
            let mut debug_lines_printed = 0;
            for line in stdout.lines() {
                let parts: Vec<&str> = line.split_whitespace().collect();
                
                if debug_lines_printed < 10 {
                    println!("[Rust] Line: '{}', Parts: {}", line, parts.len());
                    debug_lines_printed += 1;
                }

                if parts.len() >= 4 {
                    let proto = parts[0].trim().to_uppercase(); // Normalize
                    
                    if debug_lines_printed <= 10 && (proto == "TCP" || proto == "UDP") {
                         println!("[Rust] Found Proto: {}, Addr: {}", proto, parts[1]);
                    }

                    if proto != "TCP" && proto != "UDP" { continue; }

                    let local_addr = parts[1];
                    let remote_addr = parts[2];
                    let state = if parts.len() > 3 { parts[3] } else { "" };
                    let pid = if parts.len() > 4 { parts[4] } else { "0" };
                    
                    // Extract host from remote address
                    let host = remote_addr.split(':').next().unwrap_or(remote_addr);
                    let port = remote_addr.split(':').last().unwrap_or("0");
                    
                    // Only include established or active connections
                    if state == "ESTABLISHED" || state == "TIME_WAIT" || state == "CLOSE_WAIT" || proto == "UDP" {
                        connections.push(serde_json::json!({
                            "protocol": proto,
                            "localAddress": local_addr,
                            "remoteAddress": remote_addr,
                            "host": host,
                            "port": port,
                            "state": state,
                            "pid": pid.parse::<u32>().unwrap_or(0),
                            "type": if remote_addr.contains("443") { "HTTPS" } 
                                   else if remote_addr.contains("80") { "HTTP" }
                                   else if remote_addr.contains("53") { "DNS" }
                                   else { "OTHER" }
                        }));
                    }
                }
            }
            
            println!("[Rust] Total parsed connections: {}", connections.len());
            
            return Ok(serde_json::json!({
                "success": true,
                "connections": connections,
                "total": connections.len()
            }));
        }
        
        Err("Failed to run netstat".to_string())
    }
    
    #[cfg(not(windows))]
    {
        // Linux: use ss or netstat
        let output = Command::new("ss")
            .args(&["-tunap"])
            .output()
            .or_else(|_| Command::new("netstat").args(&["-tunap"]).output())
            .map_err(|e| e.to_string())?;
        
        if output.status.success() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            let mut connections: Vec<serde_json::Value> = Vec::new();
            
            for line in stdout.lines().skip(1) {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 5 {
                    connections.push(serde_json::json!({
                        "protocol": parts[0],
                        "localAddress": parts.get(3).unwrap_or(&""),
                        "remoteAddress": parts.get(4).unwrap_or(&""),
                        "state": parts.get(1).unwrap_or(&""),
                        "host": parts.get(4).unwrap_or(&"").split(':').next().unwrap_or(""),
                        "type": "OTHER"
                    }));
                }
            }
            
            return Ok(serde_json::json!({
                "success": true,
                "connections": connections,
                "total": connections.len()
            }));
        }
        
        Err("Failed to get connections".to_string())
    }
}

