use std::process::Command;

#[tauri::command]
pub async fn is_admin() -> Result<bool, String> {
    #[cfg(windows)]
    {
        use winapi::um::winnt::TOKEN_QUERY;
        use winapi::um::processthreadsapi::{GetCurrentProcess, OpenProcessToken};
        use winapi::um::securitybaseapi::GetTokenInformation;
        use winapi::um::winnt::{TokenElevation, HANDLE};
        use winapi::um::handleapi::CloseHandle;
        use std::ptr;
        #[repr(C)] struct TOKEN_ELEVATION { token_is_elevated: u32 }
        unsafe {
            let mut token: HANDLE = ptr::null_mut();
            if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 { return Ok(false); }
            let mut elevation = TOKEN_ELEVATION { token_is_elevated: 0 };
            let mut size: u32 = 0;
            let result = GetTokenInformation(token, TokenElevation, &mut elevation as *mut _ as *mut _, std::mem::size_of::<TOKEN_ELEVATION>() as u32, &mut size);
            CloseHandle(token);
            Ok(result != 0 && elevation.token_is_elevated != 0)
        }
    }
    #[cfg(not(windows))]
    {
        let output = Command::new("id").arg("-u").output().map_err(|e| e.to_string())?;
        if output.status.success() {
            let uid = String::from_utf8_lossy(&output.stdout).trim().parse::<u32>().unwrap_or(1000);
            Ok(uid == 0)
        } else { Ok(false) }
    }
}

#[tauri::command]
pub async fn set_autostart(enabled: bool) -> Result<serde_json::Value, String> {
    #[cfg(windows)]
    {
        let exe_path = std::env::current_exe().map_err(|e| e.to_string())?;
        let exe_path_str = exe_path.to_string_lossy().replace('\\', "\\\\");
        let task_name = "WhisperaClientAutostart";
        if enabled {
            let xml_content = format!(r#"<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.4" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo><Description>Whispera Client Auto-start</Description><Author>Whispera</Author></RegistrationInfo>
  <Triggers><LogonTrigger><Enabled>true</Enabled><UserId>{}</UserId></LogonTrigger></Triggers>
  <Principals><Principal id="Author"><UserId>{}</UserId><LogonType>InteractiveToken</LogonType><RunLevel>HighestAvailable</RunLevel></Principal></Principals>
  <Settings><MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy><DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries><StopIfGoingOnBatteries>false</StopIfGoingOnBatteries><AllowHardTerminate>true</AllowHardTerminate><StartWhenAvailable>true</StartWhenAvailable><RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable><IdleSettings><StopOnIdleEnd>false</StopOnIdleEnd><RestartOnIdle>false</RestartOnIdle></IdleSettings><AllowStartOnDemand>true</AllowStartOnDemand><Enabled>true</Enabled><Hidden>false</Hidden><RunOnlyIfIdle>false</RunOnlyIfIdle><WakeToRun>false</WakeToRun><ExecutionTimeLimit>PT0S</ExecutionTimeLimit><Priority>7</Priority></Settings>
  <Actions Context="Author"><Exec><Command>{}</Command></Exec></Actions>
</Task>"#, whoami::username(), whoami::username(), exe_path_str);
            let xml_path = std::env::temp_dir().join("whispera_autostart.xml");
            std::fs::write(&xml_path, xml_content).map_err(|e| e.to_string())?;
            let output = Command::new("schtasks").args(&["/Create", "/TN", task_name, "/XML", &xml_path.to_string_lossy(), "/F"]).output().map_err(|e| e.to_string())?;
            let _ = std::fs::remove_file(&xml_path);
            if output.status.success() { Ok(serde_json::json!({"success": true})) } else { Err(String::from_utf8_lossy(&output.stderr).to_string()) }
        } else {
            let output = Command::new("schtasks").args(&["/Delete", "/TN", task_name, "/F"]).output().map_err(|e| e.to_string())?;
            Ok(serde_json::json!({"success": output.status.success()}))
        }
    }
    #[cfg(not(windows))]
    { Err("Autostart not implemented for this platform here".to_string()) }
}

#[tauri::command]
pub async fn get_autostart_status() -> Result<serde_json::Value, String> {
    #[cfg(windows)]
    {
        let output = Command::new("schtasks").args(&["/Query", "/TN", "WhisperaClientAutostart"]).output().ok();
        Ok(serde_json::json!({ "enabled": output.map(|o| o.status.success()).unwrap_or(false) }))
    }
    #[cfg(not(windows))]
    { Ok(serde_json::json!({ "enabled": false })) }
}

/// Get real system network statistics (bytes sent/received)
#[tauri::command]
pub async fn get_network_stats() -> Result<serde_json::Value, String> {
    #[cfg(windows)]
    {
        // Use PowerShell to get network interface statistics
        let output = Command::new("powershell")
            .args(&[
                "-NoProfile",
                "-Command",
                r#"Get-NetAdapterStatistics | Select-Object -First 1 | ForEach-Object { 
                    Write-Output "$($_.ReceivedBytes)|$($_.SentBytes)"
                }"#
            ])
            .output()
            .map_err(|e| e.to_string())?;
        
        if output.status.success() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            let parts: Vec<&str> = stdout.trim().split('|').collect();
            
            if parts.len() >= 2 {
                let bytes_in: u64 = parts[0].parse().unwrap_or(0);
                let bytes_out: u64 = parts[1].parse().unwrap_or(0);
                
                return Ok(serde_json::json!({
                    "success": true,
                    "bytes_received": bytes_in,
                    "bytes_sent": bytes_out
                }));
            }
        }
        
        // Fallback: try using Get-Counter
        let output2 = Command::new("powershell")
            .args(&[
                "-NoProfile",
                "-Command",
                r#"
                $counters = Get-Counter '\Network Interface(*)\Bytes Received/sec', '\Network Interface(*)\Bytes Sent/sec' -ErrorAction SilentlyContinue
                if ($counters) {
                    $recv = ($counters.CounterSamples | Where-Object { $_.Path -like '*Bytes Received*' } | Measure-Object -Property CookedValue -Sum).Sum
                    $sent = ($counters.CounterSamples | Where-Object { $_.Path -like '*Bytes Sent*' } | Measure-Object -Property CookedValue -Sum).Sum
                    Write-Output "$([math]::Round($recv))|$([math]::Round($sent))"
                }
                "#
            ])
            .output()
            .map_err(|e| e.to_string())?;
        
        if output2.status.success() {
            let stdout = String::from_utf8_lossy(&output2.stdout);
            let parts: Vec<&str> = stdout.trim().split('|').collect();
            
            if parts.len() >= 2 {
                let bytes_in: u64 = parts[0].parse().unwrap_or(0);
                let bytes_out: u64 = parts[1].parse().unwrap_or(0);
                
                return Ok(serde_json::json!({
                    "success": true,
                    "bytes_received": bytes_in,
                    "bytes_sent": bytes_out
                }));
            }
        }
        
        Ok(serde_json::json!({
            "success": false,
            "bytes_received": 0,
            "bytes_sent": 0
        }))
    }
    #[cfg(not(windows))]
    {
        // Linux: read from /proc/net/dev
        if let Ok(content) = std::fs::read_to_string("/proc/net/dev") {
            let mut total_recv: u64 = 0;
            let mut total_sent: u64 = 0;
            
            for line in content.lines().skip(2) {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 10 {
                    total_recv += parts[1].parse::<u64>().unwrap_or(0);
                    total_sent += parts[9].parse::<u64>().unwrap_or(0);
                }
            }
            
            Ok(serde_json::json!({
                "success": true,
                "bytes_received": total_recv,
                "bytes_sent": total_sent
            }))
        } else {
            Ok(serde_json::json!({
                "success": false,
                "bytes_received": 0,
                "bytes_sent": 0
            }))
        }
    }
}

/// Get process memory usage
#[tauri::command]
pub async fn get_memory_usage() -> Result<serde_json::Value, String> {
    #[cfg(windows)]
    {
        use std::mem;
        use winapi::um::psapi::{GetProcessMemoryInfo, PROCESS_MEMORY_COUNTERS};
        use winapi::um::processthreadsapi::GetCurrentProcess;
        
        unsafe {
            let mut pmc: PROCESS_MEMORY_COUNTERS = mem::zeroed();
            pmc.cb = mem::size_of::<PROCESS_MEMORY_COUNTERS>() as u32;
            
            if GetProcessMemoryInfo(GetCurrentProcess(), &mut pmc, pmc.cb) != 0 {
                let memory_mb = pmc.WorkingSetSize as f64 / (1024.0 * 1024.0);
                return Ok(serde_json::json!({
                    "success": true,
                    "memory_mb": memory_mb
                }));
            }
        }
        
        Ok(serde_json::json!({
            "success": false,
            "memory_mb": 0.0
        }))
    }
    #[cfg(not(windows))]
    {
        // Linux: read from /proc/self/statm
        if let Ok(content) = std::fs::read_to_string("/proc/self/statm") {
            let parts: Vec<&str> = content.split_whitespace().collect();
            if parts.len() >= 2 {
                let pages: u64 = parts[1].parse().unwrap_or(0);
                let memory_mb = (pages * 4096) as f64 / (1024.0 * 1024.0);
                return Ok(serde_json::json!({
                    "success": true,
                    "memory_mb": memory_mb
                }));
            }
        }
        
        Ok(serde_json::json!({
            "success": false,
            "memory_mb": 0.0
        }))
    }
}

