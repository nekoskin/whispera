pub mod args;
pub mod supervisor;

use std::process::Command;

pub fn stop_process(pid: u32) {
    #[cfg(windows)]
    {
        let _ = Command::new("taskkill").args(&["/PID", &pid.to_string()]).output();
        std::thread::sleep(std::time::Duration::from_millis(1000));
        let _ = Command::new("taskkill").args(&["/F", "/PID", &pid.to_string()]).output();
    }
    #[cfg(not(windows))]
    {
        let _ = Command::new("kill").args(&["-15", &pid.to_string()]).output();
        std::thread::sleep(std::time::Duration::from_millis(1000));
        let _ = Command::new("kill").args(&["-9", &pid.to_string()]).output();
    }
}

pub fn is_process_running(pid: u32) -> bool {
    #[cfg(windows)]
    {
        let output = Command::new("tasklist").args(&["/FI", &format!("PID eq {}", pid)]).output().ok();
        if let Some(output) = output {
            let s = String::from_utf8_lossy(&output.stdout);
            return s.contains(&pid.to_string());
        }
    }
    #[cfg(not(windows))]
    {
        let output = Command::new("ps").args(&["-p", &pid.to_string()]).output().ok();
        if let Some(output) = output {
            return !output.stdout.is_empty();
        }
    }
    false
}
