package config

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

type ClientConfig struct {
	Server           string `yaml:"server" json:"server"`
	ServerTCP        string `yaml:"server_tcp" json:"server_tcp"`
	ServerWS         string `yaml:"server_ws" json:"server_ws"`
	WhisperaAddr     string `yaml:"whispera_addr" json:"whispera_addr"`
	WhisperaSNI      string `yaml:"whispera_sni" json:"whispera_sni"`
	DropECH          bool   `yaml:"drop_ech" json:"drop_ech"`
	WhisperaCertPin  string `yaml:"whispera_cert_pin" json:"whispera_cert_pin"`
	WhisperaIDPub    string `yaml:"whispera_idpub" json:"whispera_idpub"`
	WhisperaSelPub   string `yaml:"whispera_selpub" json:"whispera_selpub"`
	WhisperaQUICAddr string `yaml:"whispera_quic_addr" json:"whispera_quic_addr"`
	WhisperaIPv6     string `yaml:"whispera_ipv6" json:"whispera_ipv6"`
	GRPCAddr         string `yaml:"grpc_addr" json:"grpc_addr"`
	GRPCServerName   string `yaml:"grpc_server_name" json:"grpc_server_name"`
	GRPCUseTLS       bool   `yaml:"grpc_use_tls" json:"grpc_use_tls"`
	YaDiskOAuthToken string `yaml:"yadisk_oauth_token" json:"yadisk_oauth_token"`
	YaDiskSessionID  string `yaml:"yadisk_session_id" json:"yadisk_session_id"`
	ServerPub        string `yaml:"server_pub" json:"server_pub"`
	PSK              string `yaml:"psk" json:"psk"`

	SplitTunnel      bool   `yaml:"split_tunnel" json:"split_tunnel"`
	SplitTunnelRules string `yaml:"split_tunnel_rules" json:"split_tunnel_rules"`
	SplitTunnelMode  string `yaml:"split_tunnel_mode" json:"split_tunnel_mode"`

	MTU int `yaml:"mtu" json:"mtu"`
	//ChaffSec      int    `yaml:"chaff" json:"chaff"`
	ObfsPreset string `yaml:"obfs_preset" json:"obfs_preset"`
	UDPOnly    bool   `yaml:"udp_only" json:"udp_only"`
	// ChaffDist     string  `yaml:"chaff_dist" json:"chaff_dist"`
	// ChaffAlpha    float64 `yaml:"chaff_alpha" json:"chaff_alpha"`
	// ChaffXm       float64 `yaml:"chaff_xm" json:"chaff_xm"`
	// ChaffSizeMin  int     `yaml:"chaff_size_min" json:"chaff_size_min"`
	// ChaffSizeMax  int     `yaml:"chaff_size_max" json:"chaff_size_max"`
	// ShapeMeanMs   int     `yaml:"shape_mean_ms" json:"shape_mean_ms"`
	// ShapeTarget   int     `yaml:"shape_target" json:"shape_target"`

	UseTLS bool `yaml:"use_tls" json:"use_tls"`

	Routing *ClientRoutingConfig `yaml:"routing,omitempty" json:"routing,omitempty"`

	KillSwitch *ClientKillSwitchConfig `yaml:"kill_switch,omitempty" json:"kill_switch,omitempty"`

	ASNBypass *ClientASNBypassConfig `yaml:"asn_bypass,omitempty" json:"asn_bypass,omitempty"`

	Transport string `yaml:"transport,omitempty" json:"transport,omitempty"`

	TransportWhitelist []string `yaml:"transport_whitelist,omitempty" json:"transport_whitelist,omitempty"`
	TransportBlacklist []string `yaml:"transport_blacklist,omitempty" json:"transport_blacklist,omitempty"`

	RussianService string `yaml:"russian_service,omitempty" json:"russian_service,omitempty"`

	TransportConfig map[string]interface{} `yaml:"transport_config,omitempty" json:"transport_config,omitempty"`

	SubscriptionURL string `yaml:"subscription_url,omitempty" json:"subscription_url,omitempty"`

	ForceSNI string `yaml:"force_sni,omitempty" json:"force_sni,omitempty"`

	DialTraceMB int `yaml:"dial_trace_mb,omitempty" json:"dial_trace_mb,omitempty"`

	// Shape, when set, is the traffic-shape profile the client applies on start.
	// It lets a new shape ship as config from the server instead of a new build.
	Shape *ClientShapeProfile `yaml:"shape,omitempty" json:"shape,omitempty"`
}

// ClientShapeProfile is one named set of the shaping knobs. Empty fields mean
// "leave at zero", so an operator sets only what a given shape needs.
type ClientShapeProfile struct {
	Name           string `yaml:"name,omitempty" json:"name,omitempty"`
	PadRecords     int    `yaml:"pad_records" json:"pad_records"`
	PadMin         int    `yaml:"pad_min" json:"pad_min"`
	PadMax         int    `yaml:"pad_max" json:"pad_max"`
	FillerIdleMs   int    `yaml:"filler_idle_ms" json:"filler_idle_ms"`
	FillerEveryMs  int    `yaml:"filler_interval_ms" json:"filler_interval_ms"`
	FillerMin      int    `yaml:"filler_min" json:"filler_min"`
	FillerMax      int    `yaml:"filler_max" json:"filler_max"`
	ChunkMin       int    `yaml:"chunk_min" json:"chunk_min"`
	ChunkMax       int    `yaml:"chunk_max" json:"chunk_max"`
	ChunkShaped    bool   `yaml:"chunk_shaped" json:"chunk_shaped"`
	OpeningFillMs  int    `yaml:"opening_fill_ms" json:"opening_fill_ms"`
	OpeningEveryMs int    `yaml:"opening_every_ms" json:"opening_every_ms"`
}

type ClientRoutingConfig struct {
	Rules []ClientRoutingRule `yaml:"rules" json:"rules"`
}

type ClientRoutingRule struct {
	Type     string   `yaml:"type" json:"type"`
	Domain   []string `yaml:"domain,omitempty" json:"domain,omitempty"`
	IP       []string `yaml:"ip,omitempty" json:"ip,omitempty"`
	Port     string   `yaml:"port,omitempty" json:"port,omitempty"`
	Network  string   `yaml:"network,omitempty" json:"network,omitempty"`
	Enabled  bool     `yaml:"enabled" json:"enabled"`
	Priority int      `yaml:"priority" json:"priority"`
}

type ClientDNSConfig struct {
	Upstream string `yaml:"upstream" json:"upstream"`
}

type ClientAdBlockConfig struct {
	Enabled bool `yaml:"enabled" json:"enabled"`
	// MLEnabled     bool          `yaml:"ml_enabled" json:"ml_enabled"`
}

type AdBlockRule struct {
	Domain string `yaml:"domain,omitempty" json:"domain,omitempty"`
	URL    string `yaml:"url,omitempty" json:"url,omitempty"`
	Type   string `yaml:"type" json:"type"`
}

type ClientKillSwitchConfig struct {
	Enabled      bool     `yaml:"enabled" json:"enabled"`
	AllowLAN     bool     `yaml:"allow_lan" json:"allow_lan"`
	AllowDNS     bool     `yaml:"allow_dns" json:"allow_dns"`
	PersistRules bool     `yaml:"persist_rules" json:"persist_rules"`
	AllowedIPs   []string `yaml:"allowed_ips,omitempty" json:"allowed_ips,omitempty"`
}

type ClientFailoverConfig struct {
	Enabled bool `yaml:"enabled" json:"enabled"`
	Timeout int  `yaml:"timeout" json:"timeout"`
}

type ClientASNBypassConfig struct {
	Enabled         bool   `yaml:"enabled" json:"enabled"`
	TLSFingerprint  string `yaml:"tls_fingerprint" json:"tls_fingerprint"`
	DomainFrontHost string `yaml:"front_host" json:"front_host"`
}

func LoadClient(path string) (*ClientConfig, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cfg ClientConfig
	switch ext := filepath.Ext(path); ext {
	case ".yaml", ".yml":
		if err := yaml.Unmarshal(b, &cfg); err != nil {
			return nil, err
		}
	case ".json":
		if err := json.Unmarshal(b, &cfg); err != nil {
			return nil, err
		}
	default:
		return nil, errors.New("unsupported config format")
	}
	return &cfg, nil
}
