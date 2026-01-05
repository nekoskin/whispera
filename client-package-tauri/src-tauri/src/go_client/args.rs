use crate::types::ConnectionConfig;

pub fn build_args(config: &ConnectionConfig) -> Vec<String> {
    let mut args = vec![];

    if config.xhttp_public_key.is_some() && config.xhttp_short_id.is_some() && config.xhttp_server_name.is_some() {
        add_xhttp_args(config, &mut args);
    } else if let Some(ref pub_key) = config.server_public_key {
        args.push("-server-pub".to_string());
        args.push(pub_key.trim().to_string());
    }

    add_domain_fronting_args(config, &mut args);
    add_transport_args(config, &mut args);
    add_mode_args(config, &mut args);
    add_misc_args(config, &mut args);

    args.push("-verbose-packets".to_string());
    args
}

fn add_xhttp_args(config: &ConnectionConfig, args: &mut Vec<String>) {
    if let Some(ref k) = config.xhttp_public_key { args.push("-xhttp-public-key".to_string()); args.push(k.trim().to_string()); }
    if let Some(ref s) = config.xhttp_short_id { args.push("-xhttp-short-id".to_string()); args.push(s.trim().to_string()); }
    if let Some(ref n) = config.xhttp_server_name { args.push("-xhttp-server-name".to_string()); args.push(n.trim().to_string()); }
    if let Some(ref f) = config.xhttp_fingerprint { args.push("-xhttp-fingerprint".to_string()); args.push(f.trim().to_string()); }
    if let Some(ref m) = config.xhttp_mode { args.push("-xhttp-mode".to_string()); args.push(m.trim().to_string()); }
    if let Some(c) = config.xhttp_max_concurrency { args.push("-xhttp-max-concurrency".to_string()); args.push(c.to_string()); }
    if let Some(ref a) = config.xhttp_alpn { args.push("-xhttp-alpn".to_string()); args.push(a.trim().to_string()); }
    args.push("-core-enable".to_string());
}

fn add_domain_fronting_args(config: &ConnectionConfig, args: &mut Vec<String>) {
    if let Some(ref f) = config.front_domain { args.push("-front-domain".to_string()); args.push(f.trim().to_string()); }
    if let Some(ref b) = config.backend_domain { args.push("-backend-domain".to_string()); args.push(b.trim().to_string()); }
}

fn add_transport_args(config: &ConnectionConfig, args: &mut Vec<String>) {
    if let Some(p) = config.server_grpc_port { args.push("-server-grpc".to_string()); args.push(format!("{}:{}", config.server_ip, p)); }
    else if let Some(p) = config.server_quic_port { args.push("-server-quic".to_string()); args.push(format!("{}:{}", config.server_ip, p)); }
    else if let Some(p) = config.server_http2_port { args.push("-server-http2".to_string()); args.push(format!("https://{}:{}", config.server_ip, p)); }
    else {
        let tcp_port = config.server_tcp_port.unwrap_or(4443);
        if config.xhttp_public_key.is_some() && tcp_port == 4443 {
            args.push("-server-tcp".to_string());
            args.push(format!("{}:{}", config.server_ip, tcp_port));
        } else {
            args.push("-server".to_string());
            args.push(format!("{}:{}", config.server_ip, config.server_port));
            args.push("-server-tcp".to_string());
            args.push(format!("{}:{}", config.server_ip, tcp_port));
            args.push("-dual-mode".to_string());
            if tcp_port == 4443 { args.push("-tls".to_string()); args.push("-tls-skip-verify".to_string()); }
        }
    }
    args.push("-mtu".to_string()); args.push("1400".to_string());
}

fn add_mode_args(config: &ConnectionConfig, args: &mut Vec<String>) {
    if config.proxy_mode { args.push("-proxy-mode".to_string()); }
    if config.auto_profile { args.push("-auto-profile".to_string()); }
    if config.monitoring { args.push("-monitoring".to_string()); }
}

fn add_misc_args(config: &ConnectionConfig, args: &mut Vec<String>) {
    if let Some(ref p) = config.app_profile { args.push("-app-profile".to_string()); args.push(p.clone()); }
    if config.use_tap { args.push("-use-tap".to_string()); }
    if config.cert_pinning {
        args.push("-cert-pinning".to_string());
        if let Some(ref f) = config.cert_pinning_file { args.push("-cert-pinning-file".to_string()); args.push(f.trim().to_string()); }
    }
    if let Some(ref s) = config.stun_server { args.push("-stun".to_string()); args.push(s.clone()); }
    if let Some(ref t) = config.outbound_tag { args.push("-outbound-tag".to_string()); args.push(t.trim().to_string()); }
}
