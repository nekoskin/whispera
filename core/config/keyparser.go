package config

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"time"
)

type ConnectionKey struct {
	Version    int    `json:"v"`
	Name       string `json:"name,omitempty"`
	KeyID      string `json:"kid,omitempty"`
	ExpiresAt  int64  `json:"exp,omitempty"`
	Server     string `json:"server"`
	ServerTCP  string `json:"server_tcp,omitempty"`
	ServerWS   string `json:"server_ws,omitempty"`
	PSK        string `json:"psk"`
	ServerPub  string `json:"pub"`
	ObfsPreset string `json:"obfs"`
	Transport  string `json:"transport"`

	ObfsProfile string `json:"obfs_profile,omitempty"`

	EnableASNBypass bool   `json:"asn_bypass"`
	TLSFingerprint  string `json:"tls_fingerprint,omitempty"`
	DomainFrontHost string `json:"front_host,omitempty"`

	RussianService string `json:"russian_service,omitempty"`

	WhisperaAddr     string `json:"whispera_addr,omitempty"`
	WhisperaSNI      string `json:"whispera_sni,omitempty"`
	WhisperaQUICAddr string `json:"whispera_quic_addr,omitempty"`
	WhisperaCertPin  string `json:"whispera_pin,omitempty"`
	WhisperaIDPub    string `json:"whispera_idpub,omitempty"`
	WhisperaSelPub   string `json:"whispera_selpub,omitempty"`
	WhisperaFPRaw    string `json:"tls_fp_raw,omitempty"`

	ChameleonAddr string `json:"chameleon_addr,omitempty"`

	GRPCAddr       string `json:"grpc_addr,omitempty"`
	GRPCServerName string `json:"grpc_server_name,omitempty"`
	GRPCUseTLS     bool   `json:"grpc_use_tls,omitempty"`

	YaDiskOAuthToken string `json:"yadisk_oauth_token,omitempty"`
	YaDiskSessionID  string `json:"yadisk_session_id,omitempty"`

	TransportConfig map[string]interface{} `json:"transport_config,omitempty"`

	SubscriptionURL string `json:"sub_url,omitempty"`
}

type transportTraits struct {
	udpOnly       bool
	primaryServer func(ck *ConnectionKey) string
}

func (ck *ConnectionKey) IsExpired() bool {
	return ck.ExpiresAt > 0 && time.Now().Unix() > ck.ExpiresAt
}

var foreignSchemes = []string{"vless://", "vmess://", "trojan://", "ss://", "ssr://", "hysteria2://", "tuic://"}

func isForeignScheme(key string) bool {
	for _, p := range foreignSchemes {
		if strings.HasPrefix(key, p) {
			return true
		}
	}
	return false
}

func schemeOf(key string) string {
	if i := strings.Index(key, "://"); i > 0 {
		return key[:i]
	}
	return "unknown"
}

func ParseConnectionKey(key string) (*ConnectionKey, error) {
	key = strings.TrimSpace(key)

	if isForeignScheme(key) {
		return nil, fmt.Errorf("key: %s is another proxy's format, not a whispera key", schemeOf(key))
	}

	if strings.HasPrefix(key, "whispera://") && strings.Contains(key, "?") {
		u, err := url.Parse(key)
		if err != nil {
			return nil, fmt.Errorf("invalid URL key format: %w", err)
		}
		return parseWhisperaURLKey(u)
	}

	key = strings.TrimPrefix(key, "whispera://")
	key = strings.TrimPrefix(key, "wpn://")
	return parseBase64ConnKey(key)
}

func applyConnKeyDefaults(ck *ConnectionKey) {
	if ck.Transport == "" {
		ck.Transport = "auto"
	}
	if ck.ObfsPreset == "" {
		ck.ObfsPreset = "default"
	}
	if ck.Version == 0 {
		ck.Version = 1
	}
}

func hasServerAddr(ck *ConnectionKey) bool {
	return ck.Server != "" || ck.ServerTCP != ""
}

func parseWhisperaURLKey(u *url.URL) (*ConnectionKey, error) {
	if ck := decodeJSONHostKey(u.Host); ck != nil {
		if ck.IsExpired() {
			return nil, fmt.Errorf("connection key expired")
		}
		applyConnKeyDefaults(ck)
		if !hasServerAddr(ck) {
			return nil, fmt.Errorf("key must contain at least one server address (server or server_tcp)")
		}
		return ck, nil
	}
	return parseWhisperaQueryKey(u)
}

func decodeJSONHostKey(host string) *ConnectionKey {
	if host == "" {
		return nil
	}
	decoded, err := base64.StdEncoding.DecodeString(host)
	if err != nil || !json.Valid(decoded) {
		return nil
	}
	var ck ConnectionKey
	if json.Unmarshal(decoded, &ck) != nil {
		return nil
	}
	return &ck
}

func parseWhisperaQueryKey(u *url.URL) (*ConnectionKey, error) {
	ck := &ConnectionKey{
		Version:     1,
		Server:      u.Host,
		Transport:   "auto",
		ObfsPreset:  "default",
		ObfsProfile: "vk",
	}

	q := u.Query()
	ck.PSK = q.Get("psk")
	if ck.PSK == "" {
		ck.PSK = q.Get("key")
	}
	ck.ServerPub = q.Get("pub")

	if val := q.Get("obfs"); val != "" {
		ck.ObfsPreset = val
	}
	if val := q.Get("transport"); val != "" {
		ck.Transport = val
	}
	if val := q.Get("name"); val != "" {
		ck.Name = val
	}
	if val := q.Get("profile"); val != "" {
		ck.ObfsProfile = val
	}
	if q.Get("asn") == "1" || q.Get("asn_bypass") == "1" {
		ck.EnableASNBypass = true
	}
	if val := q.Get("tls"); val != "" {
		ck.TLSFingerprint = val
	}
	if val := q.Get("pin"); val != "" {
		ck.WhisperaCertPin = val
	}
	if val := q.Get("front"); val != "" {
		ck.DomainFrontHost = val
	}
	if val := q.Get("russian"); val != "" {
		ck.RussianService = val
	} else if val := q.Get("rs"); val != "" {
		ck.RussianService = val
	}
	if val := q.Get("kid"); val != "" {
		ck.KeyID = val
	}
	if val := q.Get("exp"); val != "" {
		var exp int64
		fmt.Sscanf(val, "%d", &exp)
		ck.ExpiresAt = exp
	}

	if ck.IsExpired() {
		return nil, fmt.Errorf("connection key expired")
	}

	if val := q.Get("cfg"); val != "" {
		decoded, err := base64.RawURLEncoding.DecodeString(val)
		if err == nil {
			var tc map[string]interface{}
			if json.Unmarshal(decoded, &tc) == nil {
				ck.TransportConfig = tc
			}
		}
	}

	if !hasServerAddr(ck) {
		return nil, fmt.Errorf("key must contain at least one server address (server or server_tcp)")
	}
	return ck, nil
}

func parseBase64ConnKey(key string) (*ConnectionKey, error) {
	data, err := base64.StdEncoding.DecodeString(key)
	if err != nil {
		data, err = base64.URLEncoding.DecodeString(key)
	}
	if err != nil {
		data, err = base64.RawURLEncoding.DecodeString(key)
	}
	if err != nil {
		return nil, fmt.Errorf("invalid key encoding: %w", err)
	}

	var ck ConnectionKey
	if err := json.Unmarshal(data, &ck); err != nil {
		return nil, fmt.Errorf("invalid key format: %w", err)
	}

	if ck.IsExpired() {
		return nil, fmt.Errorf("connection key expired")
	}
	if !hasServerAddr(&ck) {
		return nil, fmt.Errorf("key must contain at least one server address (server or server_tcp)")
	}

	applyConnKeyDefaults(&ck)
	return &ck, nil
}

func (ck *ConnectionKey) ToClientConfig() *ClientConfig {
	whisperaAddr := ck.WhisperaAddr
	if whisperaAddr == "" {
		whisperaAddr = ck.ChameleonAddr
	}

	cfg := &ClientConfig{
		Server:           ck.Server,
		ServerTCP:        ck.ServerTCP,
		ServerWS:         ck.ServerWS,
		PSK:              ck.PSK,
		ServerPub:        ck.ServerPub,
		ObfsPreset:       ck.ObfsPreset,
		RussianService:   ck.RussianService,
		TransportConfig:  ck.TransportConfig,
		Transport:        ck.Transport,
		WhisperaAddr:     whisperaAddr,
		WhisperaSNI:      ck.WhisperaSNI,
		WhisperaQUICAddr: ck.WhisperaQUICAddr,
		WhisperaCertPin:  ck.WhisperaCertPin,
		WhisperaIDPub:    ck.WhisperaIDPub,
		WhisperaSelPub:   ck.WhisperaSelPub,
		WhisperaFPRaw:    ck.WhisperaFPRaw,
		GRPCAddr:         ck.GRPCAddr,
		GRPCServerName:   ck.GRPCServerName,
		GRPCUseTLS:       ck.GRPCUseTLS,
		YaDiskOAuthToken: ck.YaDiskOAuthToken,
		YaDiskSessionID:  ck.YaDiskSessionID,
	}

	if traits, ok := transportRegistry[ck.Transport]; ok {
		cfg.UDPOnly = traits.udpOnly
	}

	if ck.EnableASNBypass {
		cfg.ASNBypass = &ClientASNBypassConfig{
			Enabled:         true,
			TLSFingerprint:  ck.TLSFingerprint,
			DomainFrontHost: ck.DomainFrontHost,
		}
	}

	return cfg
}

func (ck *ConnectionKey) GetPrimaryServer() string {
	if traits, ok := transportRegistry[ck.Transport]; ok && traits.primaryServer != nil {
		return traits.primaryServer(ck)
	}
	if ck.Server != "" {
		return ck.Server
	}
	return ck.ServerTCP
}

var transportRegistry = map[string]transportTraits{
	"tcp": {
		udpOnly: false,
		primaryServer: func(ck *ConnectionKey) string {
			if ck.ServerTCP != "" {
				return ck.ServerTCP
			}
			return ck.Server
		},
	},
	"udp": {
		udpOnly: true,
		primaryServer: func(ck *ConnectionKey) string {
			return ck.Server
		},
	},
	"ws": {
		primaryServer: func(ck *ConnectionKey) string {
			if ck.ServerWS != "" {
				return ck.ServerWS
			}
			return ck.ServerTCP
		},
	},
}

func FetchSubscription(rawURL string) ([]*ConnectionKey, error) {
	resp, err := subscriptionHTTPGet(rawURL)
	if err != nil {
		return nil, fmt.Errorf("subscription fetch: %w", err)
	}
	body := strings.TrimSpace(resp)

	var arr []string
	if json.Unmarshal([]byte(body), &arr) == nil {
		return parseKeyList(arr)
	}

	if decoded, err := base64.StdEncoding.DecodeString(body); err == nil {
		body = strings.TrimSpace(string(decoded))
	} else if decoded, err := base64.URLEncoding.DecodeString(body); err == nil {
		body = strings.TrimSpace(string(decoded))
	}

	lines := strings.Split(body, "\n")
	return parseKeyList(lines)
}

func parseKeyList(lines []string) ([]*ConnectionKey, error) {
	var out []*ConnectionKey
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		ck, err := ParseConnectionKey(line)
		if err != nil {
			continue
		}
		if ck.IsExpired() {
			continue
		}
		out = append(out, ck)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("subscription: no valid keys found")
	}
	return out, nil
}
