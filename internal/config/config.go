package config

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"

	yaml "gopkg.in/yaml.v3"
)

// ServerConfig holds optional server settings. Zero values mean "unspecified".
type ServerConfig struct {
	Listen    string `yaml:"listen" json:"listen"`
	ListenTCP string `yaml:"listen_tcp" json:"listen_tcp"`
	// Optional additional listeners (mirrors CLI flags)
	ListenWS     string `yaml:"listen_ws" json:"listen_ws"`
	ListenWS2    string `yaml:"listen_ws2" json:"listen_ws2"`
	ListenGRPC   string `yaml:"listen_grpc" json:"listen_grpc"`
	ListenQUIC   string `yaml:"listen_quic" json:"listen_quic"`
	ListenHTTP2  string `yaml:"listen_http2" json:"listen_http2"`
	API          string `yaml:"api" json:"api"`
	Health       string `yaml:"health" json:"health"`
	Metrics      string `yaml:"metrics" json:"metrics"`
	DNSUpstream  string `yaml:"dns_upstream" json:"dns_upstream"`
	TUN          string `yaml:"tun" json:"tun"`
	StaticKey    string `yaml:"static_key" json:"static_key"`
	PSK          string `yaml:"psk" json:"psk"`
	KeepaliveSec int    `yaml:"keepalive" json:"keepalive"`
	MTU          int    `yaml:"mtu" json:"mtu"`

	// Obfuscation / chaff / padding
	PadMin       int     `yaml:"pad_min" json:"pad_min"`
	PadMax       int     `yaml:"pad_max" json:"pad_max"`
	ChaffSec     int     `yaml:"chaff" json:"chaff"`
	ObfsPreset   string  `yaml:"obfs_preset" json:"obfs_preset"`
	ObfsStrict   bool    `yaml:"obfs_strict" json:"obfs_strict"`
	ChaffDist    string  `yaml:"chaff_dist" json:"chaff_dist"`
	ChaffAlpha   float64 `yaml:"chaff_alpha" json:"chaff_alpha"`
	ChaffXm      float64 `yaml:"chaff_xm" json:"chaff_xm"`
	ChaffSizeMin int     `yaml:"chaff_size_min" json:"chaff_size_min"`
	ChaffSizeMax int     `yaml:"chaff_size_max" json:"chaff_size_max"`
	ChaffDutyOn  int     `yaml:"chaff_duty_on" json:"chaff_duty_on"`
	ChaffDutyOff int     `yaml:"chaff_duty_off" json:"chaff_duty_off"`

	// Handshake / anti-amplification
	HSRate     float64 `yaml:"hs_rate" json:"hs_rate"`
	HSBurst    int     `yaml:"hs_burst" json:"hs_burst"`
	HSAmpRatio float64 `yaml:"hs_amp_ratio" json:"hs_amp_ratio"`
	HSAmpBytes int     `yaml:"hs_amp_bytes" json:"hs_amp_bytes"`

	// Rekey
	ServerRekeyMin   int   `yaml:"server_rekey_min" json:"server_rekey_min"`
	ServerRekeyBytes int64 `yaml:"server_rekey_bytes" json:"server_rekey_bytes"`
	ServerRekeyPkts  int64 `yaml:"server_rekey_pkts" json:"server_rekey_pkts"`

	// Misc
	Audit *bool  `yaml:"audit" json:"audit"`
	PProf string `yaml:"pprof" json:"pprof"`

	// Protocol-level options
	UseV2 *bool `yaml:"use_v2" json:"use_v2"`

	// TLS settings for HTTPS/DTLS
	TLSCert string `yaml:"tls_cert" json:"tls_cert"`
	TLSKey  string `yaml:"tls_key" json:"tls_key"`
	// Directory containing additional certificate/key pairs (PEM files) to serve via SNI.
	TLSCertDir string `yaml:"tls_cert_dir" json:"tls_cert_dir"`
	ACMEDomain string `yaml:"acme_domain" json:"acme_domain"`
	ACMEEmail  string `yaml:"acme_email" json:"acme_email"`

	// XHTTP transport (mirrors server flags)
	XHTTPTarget         string `yaml:"xhttp_target" json:"xhttp_target"`
	XHTTPServerNames    string `yaml:"xhttp_server_names" json:"xhttp_server_names"`
	XHTTPPrivateKey     string `yaml:"xhttp_private_key" json:"xhttp_private_key"`
	XHTTPShortID        string `yaml:"xhttp_short_id" json:"xhttp_short_id"`
	XHTTPMode           string `yaml:"xhttp_mode" json:"xhttp_mode"`
	XHTTPMaxConcurrency int    `yaml:"xhttp_max_concurrency" json:"xhttp_max_concurrency"`
	XHTTPConfigPath     string `yaml:"xhttp_config" json:"xhttp_config"`
}

// ClientConfig holds optional client settings. Zero values mean "unspecified".
type ClientConfig struct {
	Server        string  `yaml:"server" json:"server"`
	ServerTCP     string  `yaml:"server_tcp" json:"server_tcp"`
	TUN           string  `yaml:"tun" json:"tun"`
	Metrics       string  `yaml:"metrics" json:"metrics"`
	ServerPub     string  `yaml:"server_pub" json:"server_pub"`
	PSK           string  `yaml:"psk" json:"psk"`
	KeepaliveSec  int     `yaml:"keepalive" json:"keepalive"`
	RekeyMin      int     `yaml:"rekey" json:"rekey"`
	MTU           int     `yaml:"mtu" json:"mtu"`
	PadMin        int     `yaml:"pad_min" json:"pad_min"`
	PadMax        int     `yaml:"pad_max" json:"pad_max"`
	ChaffSec      int     `yaml:"chaff" json:"chaff"`
	ObfsPreset    string  `yaml:"obfs_preset" json:"obfs_preset"`
	ObfsStrict    bool    `yaml:"obfs_strict" json:"obfs_strict"`
	HSReadTimeout int     `yaml:"handshake_timeout" json:"handshake_timeout"`
	Watchdog      int     `yaml:"watchdog" json:"watchdog"`
	RekeyBytes    int64   `yaml:"rekey_bytes" json:"rekey_bytes"`
	RekeyPkts     int64   `yaml:"rekey_pkts" json:"rekey_pkts"`
	AutoSwitch    *bool   `yaml:"auto_switch" json:"auto_switch"`
	UDPUpgradeSec int     `yaml:"udp_upgrade_sec" json:"udp_upgrade_sec"`
	ChaffDist     string  `yaml:"chaff_dist" json:"chaff_dist"`
	ChaffAlpha    float64 `yaml:"chaff_alpha" json:"chaff_alpha"`
	ChaffXm       float64 `yaml:"chaff_xm" json:"chaff_xm"`
	ChaffSizeMin  int     `yaml:"chaff_size_min" json:"chaff_size_min"`
	ChaffSizeMax  int     `yaml:"chaff_size_max" json:"chaff_size_max"`
	ShapeMeanMs   int     `yaml:"shape_mean_ms" json:"shape_mean_ms"`
	ShapeTarget   int     `yaml:"shape_target" json:"shape_target"`
	PProf         string  `yaml:"pprof" json:"pprof"`
}

func LoadServer(path string) (*ServerConfig, error) {
	b, err := os.ReadFile(path) //nolint:gosec // Path is validated by caller
	if err != nil {
		return nil, err
	}
	var cfg ServerConfig
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

func LoadClient(path string) (*ClientConfig, error) {
	b, err := os.ReadFile(path) //nolint:gosec // Path is validated by caller
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
