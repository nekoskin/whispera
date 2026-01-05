use serde::{Deserialize, Serialize};
use std::sync::{Arc, Mutex};
use std::sync::atomic::AtomicBool;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectionConfig {
    pub server_ip: String,
    pub server_port: u16,
    pub server_public_key: Option<String>,
    pub server_tcp_port: Option<u16>,
    pub server_ws_port: Option<u16>,
    pub server_ws2_port: Option<u16>,
    pub server_grpc_port: Option<u16>,      
    pub server_quic_port: Option<u16>,      
    pub server_http2_port: Option<u16>,     
    pub front_domain: Option<String>,       
    pub backend_domain: Option<String>,     
    #[serde(default)]
    pub use_tap: bool,                      
    #[serde(default)]
    pub cert_pinning: bool,                 
    pub cert_pinning_file: Option<String>,  
    pub client_private_key: Option<String>,
    #[serde(default)]
    pub proxy_mode: bool,                   
    #[serde(default)]
    pub auto_profile: bool,                 
    #[serde(default)]
    pub monitoring: bool,                   
    pub app_profile: Option<String>,
    pub stun_server: Option<String>, 
    pub outbound_tag: Option<String>, 
    pub xhttp_public_key: Option<String>,  
    pub xhttp_short_id: Option<String>,     
    pub xhttp_server_name: Option<String>,  
    pub xhttp_fingerprint: Option<String>,  
    pub xhttp_mode: Option<String>,            
    pub xhttp_max_concurrency: Option<u32>,    
    pub xhttp_alpn: Option<String>,            
    #[serde(default)]
    pub insecure: bool,                       
    #[serde(default)]
    pub auto_restart: bool,                   
}

pub struct GoClientState {
    pub process: Arc<Mutex<Option<u32>>>, 
    pub stopping: Arc<AtomicBool>, 
}

impl GoClientState {
    pub fn new() -> Self {
        Self {
            process: Arc::new(Mutex::new(None)),
            stopping: Arc::new(AtomicBool::new(false)),
        }
    }
}
