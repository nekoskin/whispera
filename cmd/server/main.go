package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/pprof"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	apipkg "whispera/internal/api"
	cfgpkg "whispera/internal/config"
	aeadpkg "whispera/internal/crypto"
	metr "whispera/internal/metrics"
	"whispera/internal/obfuscation"
	"whispera/internal/proto"
	proxypkg "whispera/internal/proxy"
	routingpkg "whispera/internal/routing"
	srvpkg "whispera/internal/server"
	sniffingpkg "whispera/internal/sniffing"
	tlspkg "whispera/internal/tls"
	tunpkg "whispera/internal/tun"
	"whispera/internal/tunneling"
	"whispera/internal/tunstack"
	"whispera/internal/util"
	vlesspkg "whispera/internal/vless"
	xhttppkg "whispera/internal/xhttp"

	// P2P optional
	p2p "whispera/internal/p2p"

	"nhooyr.io/websocket"
)

var (
	sessionMgr     *srvpkg.SessionManager
	routingEngine  *routingpkg.Engine
	metadataRouter *xhttppkg.MetadataRouter
	serverRuntime  *srvpkg.ServerRuntime
)

// tlsErrorLogger filters out common TLS handshake errors from standard Go logger
// These errors are expected when using self-signed certificates
func main() {
	listen := flag.String("listen", getEnvOrDefault("WHISPERA_LISTEN", ":51820"), "UDP listen address (DTLS if -tls is set)")
	listenTCP := flag.String("listen-tcp", "", "optional TCP listen address for fallback (TLS if -tls is set)")
	listenWS := flag.String("listen-ws", "", "optional WebSocket listen address (e.g. :8080) for fallback")
	listenWS2 := flag.String("listen-ws2", "", "optional HTTP/2 WebSocket listen address (e.g. :8443) for TLS mimicry")
	listenGRPC := flag.String("listen-grpc", "", "optional gRPC listen address (e.g. :50051) for transport")
	listenQUIC := flag.String("listen-quic", "", "optional QUIC listen address (e.g. :443) for transport")
	listenHTTP2 := flag.String("listen-http2", "", "optional HTTP/2 listen address (e.g. :8443) for transport")
	_ = flag.String("tls-cert-dir", "", "directory with additional TLS certificate/key PEM pairs for SNI")
	_ = flag.String("acme-domain", "", "primary domain for automatic Let's Encrypt (ACME)")
	_ = flag.String("acme-email", "", "contact email used for ACME registration")
	tlsCertPath := flag.String("tls-cert", "", "path to TLS certificate for HTTP/2 WS, API, and main protocol")
	tlsKeyPath := flag.String("tls-key", "", "path to TLS private key for HTTP/2 WS, API, and main protocol")
	_ = flag.Bool("tls", false, "use TLS/DTLS for main protocol (requires -tls-cert and -tls-key)")
	_ = flag.String("tls-mode", "auto", "TLS mode: auto (DTLS for UDP, TLS for TCP), dtls (UDP only), tls (TCP only)")
	apiAddr := flag.String("api", getEnvOrDefault("WHISPERA_API", ":8081"), "API server listen address (e.g. :8081)")
	apiTLS := flag.Bool("api-tls", false, "enable HTTPS for API server (requires -tls-cert and -tls-key)")
	metricsAddr := flag.String("metrics", "", "optional Prometheus metrics listen address (e.g. :9101)")
	metricsTLS := flag.Bool("metrics-tls", false, "enable HTTPS for metrics endpoint (requires -tls-cert and -tls-key)")
	healthAddr := flag.String(
		"health", getEnvOrDefault("WHISPERA_HEALTH", ":8082"),
		"health endpoint listen address (e.g. :8082, default changed from :8080 to avoid conflict with WebSocket)",
	)
	healthTLS := flag.Bool("health-tls", false, "enable HTTPS for health endpoint (requires -tls-cert and -tls-key)")
	token := flag.String("token", "", "single allowed client token (UUID)")
	tokenFile := flag.String("token-file", "", "path to file with allowed tokens (one per line)")
	tunName := flag.String("tun", "", "TUN interface name (optional)")
	pskHex := flag.String("psk", "", "hex-encoded 32-byte PSK (fallback if no -static-key)")
	staticKeyHex := flag.String("static-key", "", "server static X25519 private key (hex32) - deprecated, use -xhttp instead")
	xhttpTarget := flag.String("xhttp-target", "", "XHTTP target (e.g. example.com:443)")
	xhttpServerNames := flag.String("xhttp-server-names", "", "XHTTP server names (comma-separated, e.g. example.com,www.example.com)")
	xhttpPrivateKey := flag.String("xhttp-private-key", "", "XHTTP private key (ed25519, hex64)")
	xhttpShortID := flag.String("xhttp-short-id", "", "XHTTP short ID (hex16)")
	xhttpMode := flag.String("xhttp-mode", "stream-up", "XHTTP mode: packet-up|stream-up|stream-one")
	xhttpMaxConcurrency := flag.Int("xhttp-max-concurrency", 8, "XHTTP max concurrent streams per session (XMUX-like)")
	xhttpConfigPath := flag.String("xhttp-config", "", "optional XHTTP JSON config file (applies defaults for XHTTP server)")
	configPath := flag.String("config", "", "optional YAML/JSON config file to load defaults")
	pprofAddr := flag.String("pprof", "", "optional pprof listen address (e.g. :6060)")
	kaSec := flag.Int("keepalive", 25, "keepalive interval seconds (Noise mode)")
	padMin := flag.Int("pad-min", 0, "minimum random padding bytes")
	padMax := flag.Int("pad-max", 0, "maximum random padding bytes")
	chaffSec := flag.Int("chaff", 0, "send chaff keepalives every N seconds (0=off)")
	// Obfuscation presets and cover-traffic profiles
	obfsPreset := flag.String("obfs-preset", "", "obfuscation preset: quic|quic-strict|https")
	obfsStrict := flag.Bool("obfs-strict", false, "enable strict obfuscation (timing/length shaping)")
	// fteProfile и marionetteProfile теперь интегрированы в IntegratedDPIEvasion
	// fteProfile := flag.String("fte-profile", "", "FTE protocol profile: http2|websocket|quic|tls")
	// marionetteProfile := flag.String("marionette-profile", "", "Marionette traffic profile: http2|websocket|quic")
	russianService := flag.String("russian-service", "", "Russian service for tunneling: vk|yandex|mailru|rutube|ozon")
	useServiceTunnel := flag.Bool("use-service-tunnel", false, "Enable tunneling through Russian services instead of direct UDP")
	cdnEndpoint := flag.String("cdn-endpoint", "", "CDN endpoint for tunneling (e.g., cdn.example.com:443). If set, tunnel will route through CDN instead of direct service")
	appProfile := flag.String(
		"app-profile", "",
		"профиль приложения для мимикрии: vk|messenger_max|yandex|mailru|rutube|ozon",
	)
	chaffDist := flag.String("chaff-dist", "const", "chaff distribution: const|exp|pareto")
	chaffAlpha := flag.Float64("chaff-alpha", 1.5, "pareto shape alpha (when chaff-dist=pareto)")
	chaffXm := flag.Float64("chaff-xm", 1.0, "pareto scale xm seconds (when chaff-dist=pareto)")
	chaffSizeMin := flag.Int("chaff-size-min", 256, "min target total packet size for chaff (bytes)")
	chaffSizeMax := flag.Int("chaff-size-max", 1200, "max target total packet size for chaff (bytes)")
	chaffDutyOn := flag.Int("chaff-duty-on", 0, "duty-cycle on window seconds for chaff (0=always on)")
	chaffDutyOff := flag.Int("chaff-duty-off", 0, "duty-cycle off window seconds for chaff (0=never off)")
	mtu := flag.Int("mtu", 1200, "maximum UDP packet size (bytes) including headers and AEAD")
	hsRate := flag.Float64("hs-rate", 50, "max handshake packets per second (global)")
	hsBurst := flag.Int("hs-burst", 100, "handshake burst capacity (global)")
	// Anti-amplification guard
	ampMaxRatio := flag.Float64("hs-amp-ratio", 3.0, "max amplification ratio during handshake (bytes out / bytes in)")
	ampMaxBytes := flag.Int("hs-amp-bytes", 2048, "max total bytes the server will send before validation")
	// Server rekey thresholds
	rkSrvMin := flag.Int("server-rekey-min", 30, "server rekey interval minutes (0=off)")
	rkSrvBytes := flag.Int64(
		"server-rekey-bytes", 0,
		"server triggers rekey after sending this many ciphertext bytes (0=off)",
	)
	rkSrvPkts := flag.Int64("server-rekey-pkts", 0, "server triggers rekey after sending this many packets (0=off)")
	audit := flag.Bool("audit", true, "enable audit logging of key events (no secrets)")
	dnsUpstream := flag.String("dns-upstream", "8.8.8.8:53", "upstream DNS server for proxied requests")

	// Proxy flags
	socks5Addr := flag.String("socks5", "", "SOCKS5 proxy listen address (e.g., :1080)")
	httpProxyAddr := flag.String("http-proxy", "", "HTTP proxy listen address (e.g., :8080)")

	auditFlag = audit // Сохраняем в глобальную переменную

	// IP-роутер: таймаут неактивности серверных TCP-флоу (forwardTCPPacket).
	// По умолчанию включен клинап с таймаутом 10 минут; 0 = клинап выключен.
	iprouteTCPIdleTimeout := flag.Duration(
		"iproute-tcp-idle-timeout",
		10*time.Minute,
		"idle timeout for server-side TCP flows in IP router (default 10m, 0=disabled, e.g. 5m, 30m)",
	)
	iprouteUDPIdleTimeout := flag.Duration(
		"iproute-udp-idle-timeout",
		5*time.Minute,
		"idle timeout for server-side UDP flows (QUIC/HTTP3) in IP router (default 5m, 0=disabled)",
	)

	// Experimental: режим byte-stream TCP поверх STREAM‑слоя (без IP‑обёртки).
	// Если включён, выбранные TCP‑потоки (по порту) обрабатываются как чистые байты:
	// STREAM_DATA payload трактуется как TCP‑payload, а не как IP‑пакет.
	netstackTCPPortsFlag := flag.String("netstack-tcp-ports", "", "comma-separated list of destination TCP ports to treat as raw byte streams instead of IP packets (e.g. 80,443)")

	// Feature flag: Marionette core in datapath (default off)
	coreEnable := flag.Bool(
		"core-enable", os.Getenv("WHISPERA_CORE_ENABLE") == "1",
		"enable Marionette core processing in datapath (default off)",
	)
	// V2 Protocol: улучшенный протокол с меньшим overhead и мультиплексированием
	useV2 := flag.Bool("use-v2", getEnvBool("WHISPERA_USE_V2", true), "use V2 protocol (compact header, batch encryption, multiplexing)")

	// P2P flags
	p2pEnabled := flag.Bool("p2p", false, "enable decentralized P2P sidecar")
	_ = flag.Bool("proxy-mode", false, "run as proxy server without TUN interface (server doesn't use TUN)")
	p2pBootstrapCSV := flag.String(
		"p2p-bootstrap", "",
		"comma-separated bootstrap peers host:port for P2P discovery (udp)",
	)
	p2pListen := flag.String("p2p-listen", ":51821", "P2P discovery UDP listen address (default :51821)")

	// Dummy references to optional flags to avoid unused variable errors when optional
	// listeners and IP router cleanup are disabled in this build.
	_ = listenWS2
	_ = listenGRPC
	_ = listenQUIC
	_ = listenHTTP2
	_ = iprouteTCPIdleTimeout
	_ = iprouteUDPIdleTimeout

	// Split tunneling flags
	splitTunnel := flag.Bool("split-tunnel", false, "enable split tunneling")
	splitTunnelRules := flag.String("split-rules", "", "split tunneling rules file (JSON format)")
	splitTunnelMode := flag.String("split-mode", "exclude", "split tunnel mode: exclude (default) or include")

	// CLI utility flags
	validateConfig := flag.Bool("validate-config", false, "validate server config file and exit")
	printConfig := flag.Bool("print-config", false, "print effective server config (JSON) and exit")

	flag.Parse()

	// Log split tunneling configuration
	if *splitTunnel {
		log.Printf("Split tunneling enabled: mode=%s, rules=%s", *splitTunnelMode, *splitTunnelRules)
	}
	dnsUpstreamAddr = dnsUpstream

	// Парсим список портов для byte-stream TCP режима (UseNetstackTCP).
	netstackTCPPorts := make(map[uint16]struct{})
	if *netstackTCPPortsFlag != "" {
		for _, part := range strings.Split(*netstackTCPPortsFlag, ",") {
			part = strings.TrimSpace(part)
			if part == "" {
				continue
			}
			if p, err := strconv.Atoi(part); err == nil && p > 0 && p <= 65535 {
				netstackTCPPorts[uint16(p)] = struct{}{}
			}
		}
		if len(netstackTCPPorts) > 0 && *audit {
			log.Printf("[STREAM] UseNetstackTCP enabled for destination ports: %v", *netstackTCPPortsFlag)
		}
	}

	// Filter TLS handshake errors from standard Go logger (net/http package)
	// These errors are expected when using self-signed certificates
	originalWriter := log.Writer()
	log.SetOutput(&tlsErrorLogger{original: originalWriter})

	// Allow default app profile from env when flag not provided
	if *appProfile == "" {
		if v := os.Getenv("WHISPERA_APP_PROFILE"); v != "" {
			*appProfile = v
		}
	}

	// Запускаем фоновую зачистку серверных TCP/UDP-флоу IP-роутера при включённом таймауте.
	// ВРЕМЕННО ОТКЛЮЧЕНО: startIPConnectionsCleanup / startUDPFlowsCleanup не реализованы в текущей версии.
	// Логика IP-роутера останется без фоновой зачистки, что допустимо для текущего XHTTP+TUN сценария.

	// Load tokens allowlist
	allowedTokens := map[string]struct{}{}
	if *token != "" {
		allowedTokens[*token] = struct{}{}
	}
	if *tokenFile != "" {
		if b, err := os.ReadFile(*tokenFile); err == nil {
			for _, line := range strings.Split(string(b), "\n") {
				t := strings.TrimSpace(line)
				if t != "" && !strings.HasPrefix(t, "#") {
					allowedTokens[t] = struct{}{}
				}
			}
		} else {
			log.Printf("token-file read error: %v", err)
		}
	}
	// Start pprof if requested
	if *pprofAddr != "" {
		go func() {
			mux := http.NewServeMux()
			mux.HandleFunc("/debug/pprof/", pprof.Index)
			mux.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
			mux.HandleFunc("/debug/pprof/profile", pprof.Profile)
			mux.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
			mux.HandleFunc("/debug/pprof/trace", pprof.Trace)
			_ = (&http.Server{ //nolint:gosec // pprof endpoint, low security risk
				Addr:              *pprofAddr,
				Handler:           mux,
				ReadHeaderTimeout: 5 * time.Second,
			}).ListenAndServe()
		}()
	}

	// Health endpoint (independent of WS) - можно запустить с TLS
	if *healthAddr != "" {
		go func(addr string) {
			mux := http.NewServeMux()
			mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodGet && r.Method != http.MethodHead {
					w.WriteHeader(http.StatusMethodNotAllowed)
					w.Header().Set("Allow", "GET, HEAD")
					return
				}
				w.Header().Set("Content-Type", "text/plain; charset=utf-8")
				w.WriteHeader(http.StatusOK)
				if r.Method == http.MethodGet {
					_, _ = w.Write([]byte("ok"))
				}
			})

			srv := &http.Server{
				Addr:              addr,
				Handler:           mux,
				ReadHeaderTimeout: 5 * time.Second,
				ReadTimeout:       10 * time.Second,
				WriteTimeout:      10 * time.Second,
				IdleTimeout:       30 * time.Second,
			}

			if *healthTLS && *tlsCertPath != "" && *tlsKeyPath != "" {
				// SECURITY: Используем браузероподобный TLS fingerprint для обхода DPI
				cert, err := tls.LoadX509KeyPair(*tlsCertPath, *tlsKeyPath)
				if err == nil {
					srv.TLSConfig = tlspkg.GetBrowserLikeServerTLSConfig(
						tlspkg.GetDefaultBrowserFingerprint(),
						[]tls.Certificate{cert},
					)
				} else {
					// Fallback на базовую конфигурацию если не удалось загрузить сертификат
					srv.TLSConfig = &tls.Config{
						MinVersion: tls.VersionTLS12,
						MaxVersion: tls.VersionTLS13,
					}
				}
				log.Printf("Health endpoint (HTTPS) starting on %s", addr)
				if err := srv.ListenAndServeTLS(*tlsCertPath, *tlsKeyPath); err != nil && err != http.ErrServerClosed {
					log.Printf("health server (HTTPS) error: %v", err)
				}
			} else {
				log.Printf("Health endpoint (HTTP) starting on %s", addr)
				if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
					log.Printf("health server (HTTP) error: %v", err)
				}
			}
		}(*healthAddr)
	}

	// Load config file if provided (values act as defaults where flags not set)
	if *configPath != "" {
		if sc, err := cfgpkg.LoadServer(*configPath); err == nil {
			if *listen == ":51820" && sc.Listen != "" {
				*listen = sc.Listen
			}
			if *listenTCP == "" && sc.ListenTCP != "" {
				*listenTCP = sc.ListenTCP
			}
			if *metricsAddr == "" && sc.Metrics != "" {
				*metricsAddr = sc.Metrics
			}
			if *tunName == "" && sc.TUN != "" {
				*tunName = sc.TUN
			}
			if *staticKeyHex == "" && sc.StaticKey != "" {
				*staticKeyHex = sc.StaticKey
			}
			if *pskHex == "" && sc.PSK != "" {
				*pskHex = sc.PSK
			}
			if *kaSec == 25 && sc.KeepaliveSec > 0 {
				*kaSec = sc.KeepaliveSec
			}
			if *mtu == 1200 && sc.MTU > 0 {
				*mtu = sc.MTU
			}
			if *padMin == 0 && sc.PadMin > 0 {
				*padMin = sc.PadMin
			}
			if *padMax == 0 && sc.PadMax > 0 {
				*padMax = sc.PadMax
			}
			if *chaffSec == 0 && sc.ChaffSec > 0 {
				*chaffSec = sc.ChaffSec
			}
			if *obfsPreset == "" && sc.ObfsPreset != "" {
				*obfsPreset = sc.ObfsPreset
			}
			if !*obfsStrict && sc.ObfsStrict {
				*obfsStrict = true
			}
			if *chaffDist == "const" && sc.ChaffDist != "" {
				*chaffDist = sc.ChaffDist
			}
			if *chaffAlpha == 1.5 && sc.ChaffAlpha != 0 {
				*chaffAlpha = sc.ChaffAlpha
			}
			if *chaffXm == 1.0 && sc.ChaffXm != 0 {
				*chaffXm = sc.ChaffXm
			}
			if *chaffSizeMin == 256 && sc.ChaffSizeMin > 0 {
				*chaffSizeMin = sc.ChaffSizeMin
			}
			if *chaffSizeMax == 1200 && sc.ChaffSizeMax > 0 {
				*chaffSizeMax = sc.ChaffSizeMax
			}
			if *chaffDutyOn == 0 && sc.ChaffDutyOn > 0 {
				*chaffDutyOn = sc.ChaffDutyOn
			}
			if *chaffDutyOff == 0 && sc.ChaffDutyOff > 0 {
				*chaffDutyOff = sc.ChaffDutyOff
			}
			if *hsRate == 50 && sc.HSRate > 0 {
				*hsRate = sc.HSRate
			}
			if *hsBurst == 100 && sc.HSBurst > 0 {
				*hsBurst = sc.HSBurst
			}
			if *ampMaxRatio == 3.0 && sc.HSAmpRatio > 0 {
				*ampMaxRatio = sc.HSAmpRatio
			}
			if *ampMaxBytes == 2048 && sc.HSAmpBytes > 0 {
				*ampMaxBytes = sc.HSAmpBytes
			}
			if *rkSrvMin == 30 && sc.ServerRekeyMin > 0 {
				*rkSrvMin = sc.ServerRekeyMin
			}
			if *rkSrvBytes == 0 && sc.ServerRekeyBytes > 0 {
				*rkSrvBytes = sc.ServerRekeyBytes
			}
			if *rkSrvPkts == 0 && sc.ServerRekeyPkts > 0 {
				*rkSrvPkts = sc.ServerRekeyPkts
			}
			if *audit && sc.Audit != nil {
				*audit = *sc.Audit
			}
			if *pprofAddr == "" && sc.PProf != "" {
				*pprofAddr = sc.PProf
			}
			if *tlsCertPath == "" && sc.TLSCert != "" {
				*tlsCertPath = sc.TLSCert
			}
			if *tlsKeyPath == "" && sc.TLSKey != "" {
				*tlsKeyPath = sc.TLSKey
			}
			// API / health / DNS / extra listeners
			if *apiAddr == ":8081" && sc.API != "" {
				*apiAddr = sc.API
			}
			if *healthAddr == ":8082" && sc.Health != "" {
				*healthAddr = sc.Health
			}
			if *metricsAddr == "" && sc.Metrics != "" {
				*metricsAddr = sc.Metrics
			}
			if *dnsUpstream == "8.8.8.8:53" && sc.DNSUpstream != "" {
				*dnsUpstream = sc.DNSUpstream
			}
			if *listenWS == "" && sc.ListenWS != "" {
				*listenWS = sc.ListenWS
			}
			if *listenWS2 == "" && sc.ListenWS2 != "" {
				*listenWS2 = sc.ListenWS2
			}
			if *listenGRPC == "" && sc.ListenGRPC != "" {
				*listenGRPC = sc.ListenGRPC
			}
			if *listenQUIC == "" && sc.ListenQUIC != "" {
				*listenQUIC = sc.ListenQUIC
			}
			if *listenHTTP2 == "" && sc.ListenHTTP2 != "" {
				*listenHTTP2 = sc.ListenHTTP2
			}
			// XHTTP block
			if *xhttpTarget == "" && sc.XHTTPTarget != "" {
				*xhttpTarget = sc.XHTTPTarget
			}
			if *xhttpServerNames == "" && sc.XHTTPServerNames != "" {
				*xhttpServerNames = sc.XHTTPServerNames
			}
			if *xhttpPrivateKey == "" && sc.XHTTPPrivateKey != "" {
				*xhttpPrivateKey = sc.XHTTPPrivateKey
			}
			if *xhttpShortID == "" && sc.XHTTPShortID != "" {
				*xhttpShortID = sc.XHTTPShortID
			}
			if *xhttpMode == "stream-up" && sc.XHTTPMode != "" {
				*xhttpMode = sc.XHTTPMode
			}
			if *xhttpMaxConcurrency == 8 && sc.XHTTPMaxConcurrency > 0 {
				*xhttpMaxConcurrency = sc.XHTTPMaxConcurrency
			}
			if *xhttpConfigPath == "" && sc.XHTTPConfigPath != "" {
				*xhttpConfigPath = sc.XHTTPConfigPath
			}
			// Protocol-level flags
			if sc.UseV2 != nil {
				*useV2 = *sc.UseV2
			}
		}
	} else if *validateConfig {
		// В режиме валидации наличие -config обязательно
		log.Printf("Error: -config is required when using -validate-config")
		os.Exit(1)
	}

	// Режим только проверки конфига: если мы сюда дошли и LoadServer не упал — конфиг синтаксически валиден.
	if *validateConfig {
		log.Printf("Config %s is valid", *configPath)
		os.Exit(0)
	}

	// Режим печати effective-конфига (после merge config-файла и флагов).
	if *printConfig {
		// Собираем ServerConfig из текущих значений флагов.
		out := cfgpkg.ServerConfig{
			Listen:    *listen,
			ListenTCP: *listenTCP,
			ListenWS:  *listenWS,
			// listenWS2/listenGRPC/listenQUIC/listenHTTP2 пока помечены как unused,
			// но если позже включишь - просто разкомментируешь и уберешь "_" выше.
			API:         *apiAddr,
			Health:      *healthAddr,
			Metrics:     *metricsAddr,
			DNSUpstream: *dnsUpstream,
			TUN:         *tunName,
			StaticKey:   *staticKeyHex,
			PSK:         *pskHex,
			KeepaliveSec: *kaSec,
			MTU:          *mtu,

			PadMin:       *padMin,
			PadMax:       *padMax,
			ChaffSec:     *chaffSec,
			ObfsPreset:   *obfsPreset,
			ObfsStrict:   *obfsStrict,
			ChaffDist:    *chaffDist,
			ChaffAlpha:   *chaffAlpha,
			ChaffXm:      *chaffXm,
			ChaffSizeMin: *chaffSizeMin,
			ChaffSizeMax: *chaffSizeMax,
			ChaffDutyOn:  *chaffDutyOn,
			ChaffDutyOff: *chaffDutyOff,

			HSRate:     *hsRate,
			HSBurst:    *hsBurst,
			HSAmpRatio: *ampMaxRatio,
			HSAmpBytes: *ampMaxBytes,

			ServerRekeyMin:   *rkSrvMin,
			ServerRekeyBytes: *rkSrvBytes,
			ServerRekeyPkts:  *rkSrvPkts,

			Audit: audit,
			PProf: *pprofAddr,

			TLSCert: *tlsCertPath,
			TLSKey:  *tlsKeyPath,
		}

		// UseV2 — pointer в конфиге, приводим из bool-флага.
		useV2Val := *useV2
		out.UseV2 = &useV2Val

		// XHTTP блок
		out.XHTTPTarget = *xhttpTarget
		out.XHTTPServerNames = *xhttpServerNames
		out.XHTTPPrivateKey = *xhttpPrivateKey
		out.XHTTPShortID = *xhttpShortID
		out.XHTTPMode = *xhttpMode
		out.XHTTPMaxConcurrency = *xhttpMaxConcurrency
		out.XHTTPConfigPath = *xhttpConfigPath

		enc, err := json.MarshalIndent(out, "", "  ")
		if err != nil {
			log.Printf("Failed to marshal effective config: %v", err)
			os.Exit(1)
		}
		fmt.Println(string(enc))
		os.Exit(0)
	}

	// Создаем ServerRuntime на основе текущих значений флагов (effective config).
	// Это нужно до дальнейшей инициализации, чтобы runtime знал актуальный cfg.
	{
		effective := cfgpkg.ServerConfig{
			Listen:    *listen,
			ListenTCP: *listenTCP,
			ListenWS:  *listenWS,
			API:         *apiAddr,
			Health:      *healthAddr,
			Metrics:     *metricsAddr,
			DNSUpstream: *dnsUpstream,
			TUN:         *tunName,
			StaticKey:   *staticKeyHex,
			PSK:         *pskHex,
			KeepaliveSec: *kaSec,
			MTU:          *mtu,

			PadMin:       *padMin,
			PadMax:       *padMax,
			ChaffSec:     *chaffSec,
			ObfsPreset:   *obfsPreset,
			ObfsStrict:   *obfsStrict,
			ChaffDist:    *chaffDist,
			ChaffAlpha:   *chaffAlpha,
			ChaffXm:      *chaffXm,
			ChaffSizeMin: *chaffSizeMin,
			ChaffSizeMax: *chaffSizeMax,
			ChaffDutyOn:  *chaffDutyOn,
			ChaffDutyOff: *chaffDutyOff,

			HSRate:     *hsRate,
			HSBurst:    *hsBurst,
			HSAmpRatio: *ampMaxRatio,
			HSAmpBytes: *ampMaxBytes,

			ServerRekeyMin:   *rkSrvMin,
			ServerRekeyBytes: *rkSrvBytes,
			ServerRekeyPkts:  *rkSrvPkts,

			Audit: audit,
			PProf: *pprofAddr,

			TLSCert: *tlsCertPath,
			TLSKey:  *tlsKeyPath,

			XHTTPTarget:         *xhttpTarget,
			XHTTPServerNames:    *xhttpServerNames,
			XHTTPPrivateKey:     *xhttpPrivateKey,
			XHTTPShortID:        *xhttpShortID,
			XHTTPMode:           *xhttpMode,
			XHTTPMaxConcurrency: *xhttpMaxConcurrency,
			XHTTPConfigPath:     *xhttpConfigPath,
		}
		useV2Val := *useV2
		effective.UseV2 = &useV2Val

		serverRuntime = srvpkg.NewServerRuntime(&effective)
		// Связываем runtime с глобальным состоянием сервера (dnsUpstream, xhttpTarget, MTU, hs‑лимиты, chaff)
		serverRuntime.SetDNSUpstreamCallback(func(oldVal, newVal string) {
			if dnsUpstreamAddr != nil {
				*dnsUpstreamAddr = newVal
			}
			log.Printf("[Runtime] Applied DNS upstream change to global state: %s -> %s", oldVal, newVal)
		})
		serverRuntime.SetXHTTPTargetCallback(func(oldVal, newVal string) {
			// Обновляем флаг xhttp-target для новых соединений
			*xhttpTarget = newVal
			log.Printf("[Runtime] Applied XHTTP target change to global state: %s -> %s", oldVal, newVal)
		})
		// MTU → maxUDPPacket для server UDP I/O (при старте и при reload)
		serverRuntime.SetMTUCallback(func(newMTU int) {
			setMaxUDPPacket(newMTU)
			// Обновляем глобальный флаг для совместимости с кодом, который читает *mtu
			if mtu != nil {
				*mtu = newMTU
			}
			log.Printf("[Runtime] Applied MTU change: %d (maxUDPPacket updated)", newMTU)
		})
		setMaxUDPPacket(*mtu)

		// XHTTP max concurrency → обновляет глобальный флаг и mux (если зарегистрирован)
		serverRuntime.SetXHTTPMaxConcurrencyCallback(func(newMaxConcurrency int) {
			// Обновляем глобальный флаг для новых XHTTP соединений
			if xhttpMaxConcurrency != nil {
				*xhttpMaxConcurrency = newMaxConcurrency
			}
			// Обновляем maxConcurrency в зарегистрированном mux (если есть)
			if mux := serverRuntime.GetMux(); mux != nil {
				mux.SetMaxConcurrency(newMaxConcurrency)
				log.Printf("[Runtime] Updated mux maxConcurrency to %d", newMaxConcurrency)
			}
			log.Printf("[Runtime] Applied XHTTP max concurrency change: %d", newMaxConcurrency)
		})

		// Chaff runtime config (server-originated keepalive chaff)
		// Инициализируем runtime-конфиг текущими значениями флагов
		setChaffRuntimeConfig(*chaffSec, *chaffDist, *chaffAlpha, *chaffXm, *chaffSizeMin, *chaffSizeMax, *chaffDutyOn, *chaffDutyOff)
		serverRuntime.SetChaffCallback(func(sec int, dist string, alpha, xm float64, sizeMin, sizeMax, dutyOn, dutyOff int) {
			if chaffSec != nil {
				*chaffSec = sec
			}
			if chaffDist != nil {
				*chaffDist = dist
			}
			if chaffAlpha != nil {
				*chaffAlpha = alpha
			}
			if chaffXm != nil {
				*chaffXm = xm
			}
			if chaffSizeMin != nil {
				*chaffSizeMin = sizeMin
			}
			if chaffSizeMax != nil {
				*chaffSizeMax = sizeMax
			}
			if chaffDutyOn != nil {
				*chaffDutyOn = dutyOn
			}
			if chaffDutyOff != nil {
				*chaffDutyOff = dutyOff
			}
			setChaffRuntimeConfig(sec, dist, alpha, xm, sizeMin, sizeMax, dutyOn, dutyOff)
			log.Printf("[Runtime] Applied chaff config change: sec=%d dist=%s alpha=%.2f xm=%.2f size=[%d-%d] duty_on=%d duty_off=%d",
				sec, dist, alpha, xm, sizeMin, sizeMax, dutyOn, dutyOff)
		})

		// Anti-amplification runtime config
		setAmpRuntimeConfig(*ampMaxRatio, *ampMaxBytes)
		serverRuntime.SetAmpCallback(func(maxRatio float64, maxBytes int) {
			if ampMaxRatio != nil {
				*ampMaxRatio = maxRatio
			}
			if ampMaxBytes != nil {
				*ampMaxBytes = maxBytes
			}
			setAmpRuntimeConfig(maxRatio, maxBytes)
			log.Printf("[Runtime] Applied anti-amplification limits change: ratio=%.2f bytes=%d", maxRatio, maxBytes)
		})

		sessionMgr = serverRuntime.GetSessionManager()
		routingEngine = serverRuntime.GetRoutingEngine()
		metadataRouter = serverRuntime.GetMetadataRouter()
	}
	// Apply obfuscation preset overrides (only where user didn't set explicit values)
	switch *obfsPreset {
	case "quic":
		if *padMin == 0 && *padMax == 0 {
			*padMin = 96
			*padMax = 384
		}
		if *chaffSec == 0 {
			*chaffSec = 1
		}
		if *chaffDist == "const" {
			*chaffDist = "pareto"
		}
		if *chaffAlpha == 1.5 {
			*chaffAlpha = 1.7
		}
		if *chaffXm == 1.0 {
			*chaffXm = 0.6
		}
		if *chaffSizeMin == 256 {
			*chaffSizeMin = 600
		}
		if *chaffSizeMax == 1200 {
			*chaffSizeMax = 1300
		}
	case "quic-strict":
		if !*obfsStrict {
			*obfsStrict = true
		}
		if *chaffSec > 0 {
			*chaffSec = 0 // client shapes chaff
		}
		if *padMin == 0 && *padMax == 0 {
			*padMin = 64
			*padMax = 256
		}
	case "https":
		if !*obfsStrict {
			*obfsStrict = true
		}
		if *chaffSec > 0 {
			*chaffSec = 0
		}
		if *padMin == 0 && *padMax == 0 {
			*padMin = 48
			*padMax = 192
		}
	}

	// Either -static-key (deprecated) or -psk must be provided; validated below
	var psk []byte
	var err error
	if *pskHex != "" {
		psk, err = util.DecodeHexKey(*pskHex, 32)
		if err != nil {
			log.Printf("Error: invalid PSK: %v", err)
			return
		}
	}

	// Server should not create TUN interface - only clients need TUN
	// Server accepts connections and routes traffic directly to internet
	var tun *tunpkg.Interface = nil
	// Optional core integration manager (safe-by-default)
	var coreIM *obfuscation.IntegrationManager

	// Optional XHTTP config loaded from JSON
	var loadedXHTTPConfig *xhttppkg.XHTTPConfig

	log.Printf("Server mode: accepting client connections (no TUN interface on server)")

	if *coreEnable {
		coreIM = obfuscation.NewIntegrationManager()
		log.Printf("Core obfuscation enabled in datapath (IntegrationManager with ML + FTE)")
		if coreIM.GetMLSystem() != nil {
			log.Printf("✅ ML system initialized in IntegrationManager")
		}
		if coreIM.GetFTE() != nil {
			log.Printf("✅ FTE initialized in IntegrationManager")
		}
	}

	// Load XHTTP config file if provided
	if *xhttpConfigPath != "" {
		if b, err := os.ReadFile(*xhttpConfigPath); err == nil {
			if xc, err := xhttppkg.LoadXHTTPConfigFromJSON(b); err == nil {
				loadedXHTTPConfig = xc
				log.Printf("Loaded XHTTP config from %s", *xhttpConfigPath)
			} else {
				log.Printf("Failed to parse XHTTP config %s: %v", *xhttpConfigPath, err)
			}
		} else {
			log.Printf("Failed to read XHTTP config %s: %v", *xhttpConfigPath, err)
		}
	}

	// Optional P2P network boot
	if *p2pEnabled {
		var boots []string
		if *p2pBootstrapCSV != "" {
			s := *p2pBootstrapCSV
			start := 0
			for i := 0; i <= len(s); i++ {
				if i == len(s) || s[i] == ',' {
					if seg := s[start:i]; seg != "" {
						boots = append(boots, seg)
					}
					start = i + 1
				}
			}
		}
		netw := p2p.NewP2PNetwork(boots)
		if *p2pListen != "" {
			netw.DiscoveryListen = *p2pListen
		}
		go func() {
			if err := netw.Start(context.Background()); err != nil {
				log.Printf("P2P network error: %v", err)
			}
		}()
		log.Printf("P2P sidecar enabled, listen=%s, bootstrap=%v", *p2pListen, boots)
	}

	// Initialize integrated DPI evasion system (now integrated into UnifiedMLSystem)
	var russianTunneler *tunneling.RussianTunneler

	// Интегрированная система обхода DPI для российских сервисов
	// service := "vk"
	// if *russianService != "" {
	//	service = *russianService
	// }
	log.Printf("Интегрированная система обхода DPI интегрирована в объединенную ML систему")

	// Initialize Russian service tunneling for whitelist bypass
	var serviceTunnel *tunneling.ServiceTunnel
	// Создаем контекст с возможностью отмены для graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	// defer cancel() вызывается в конце main после graceful shutdown
	if *russianService != "" {
		russianTunneler = tunneling.NewRussianTunneler()
		if err := russianTunneler.SetActiveService(*russianService); err != nil {
			log.Printf("Russian service error: %v", err)
		} else {
			log.Printf("Russian service active: %s", *russianService)
			// Show available services
			services := russianTunneler.GetAvailableServices()
			log.Printf("Available Russian services: %v", services)

			// Create service tunnel if service tunneling is enabled
			if *useServiceTunnel {
				var err error
				serviceTunnel, err = russianTunneler.CreateTunnel(ctx, *cdnEndpoint)
				if err != nil {
					log.Printf("Failed to create service tunnel: %v", err)
				} else {
					if *cdnEndpoint != "" {
						log.Printf("Service tunnel created for %s via CDN endpoint: %s", *russianService, *cdnEndpoint)
					} else {
						log.Printf("Service tunnel created for %s (direct)", *russianService)
					}
				}
			}
		}
	}

	// Initialize BehavioralMimicry for application traffic profiling
	var behavioralMimicry *obfuscation.BehavioralMimicry
	if *appProfile != "" {
		behavioralMimicry = obfuscation.NewBehavioralMimicry()
		if err := behavioralMimicry.SetApplicationProfile(*appProfile); err != nil {
			log.Printf("Ошибка установки профиля приложения %s: %v", *appProfile, err)
		} else {
			log.Printf("Поведенческая мимикрия включена для профиля: %s", *appProfile)
		}
	}

	// Инициализация реальных методов обхода DPI (теперь интегрирована в IntegratedDPIEvasion)
	log.Printf("Реальные методы обхода DPI интегрированы в систему")

	// Используем "udp4" для явного указания IPv4, чтобы избежать проблем с dual-stack
	addr, err := net.ResolveUDPAddr("udp4", *listen)
	if err != nil {
		log.Printf("Error: failed to resolve listen address: %v", err)
		return
	}
	// ВАЖНО: Проверяем, что адрес резолвится правильно
	if addr.IP == nil {
		// Если IP не указан (например ":51820"), слушаем на всех интерфейсах IPv4
		addr.IP = net.IPv4zero // 0.0.0.0 - слушать на всех интерфейсах IPv4
		log.Printf("No IP specified, listening on all IPv4 interfaces (0.0.0.0:%d)", addr.Port)
	} else {
		log.Printf("Resolved listen address: %s (IP: %s, Port: %d)", *listen, addr.IP, addr.Port)
	}

	// Используем "udp4" для явного IPv4 слушателя
	conn, err := net.ListenUDP("udp4", addr)
	if err != nil {
		log.Printf("Error: failed to listen on UDP %s: %v", addr, err)
		return
	}
	defer func() {
		if err := conn.Close(); err != nil {
			log.Printf("error closing UDP connection: %v", err)
		}
	}()

	// Проверяем реальный адрес, на котором слушаем
	localAddr := conn.LocalAddr()
	log.Printf("UDP server listening on %s (actual: %s)", *listen, localAddr)
	log.Printf("Server ready to accept connections from clients")

	// Настраиваем автоматическое обновление геобаз
	geoUpdateEnabled := getEnvBool("WHISPERA_GEO_UPDATE_ENABLED", true)
	geoUpdateDir := getEnvOrDefault("WHISPERA_GEO_UPDATE_DIR", "")
	geoUpdateInterval := getEnvDuration("WHISPERA_GEO_UPDATE_INTERVAL", 24*time.Hour)

	geoIPFile := getEnvOrDefault("WHISPERA_GEOIP_FILE", "")
	geoSiteFile := getEnvOrDefault("WHISPERA_GEOSITE_FILE", "")

	// Создаем geo updater если автообновление включено
	var geoUpdater *routingpkg.GeoUpdater
	if geoUpdateEnabled {
		updaterConfig := routingpkg.GeoUpdateConfig{
			UpdateDir:   geoUpdateDir,
			Interval:    geoUpdateInterval,
			Enabled:     true,
			GeoIPPath:   geoIPFile,   // Если указан явный путь, используем его
			GeoSitePath: geoSiteFile, // Если указан явный путь, используем его
		}
		geoUpdater = routingpkg.NewGeoUpdater(updaterConfig)
		if serverRuntime != nil {
			serverRuntime.SetGeoUpdater(geoUpdater)
		} else if routingEngine != nil {
			routingEngine.SetGeoUpdater(geoUpdater)
		}
		log.Printf("Geo updater initialized (update interval: %v)", geoUpdateInterval)

		// Запускаем автообновление
		if err := geoUpdater.Start(ctx); err != nil {
			log.Printf("Failed to start geo updater: %v (continuing without auto-update)", err)
		} else {
			log.Printf("Geo updater started - databases will be updated automatically")
		}

		// Загружаем базы после первого обновления
		geoIPPath := geoUpdater.GetGeoIPPath()
		geoSitePath := geoUpdater.GetGeoSitePath()

		if geoIPPath != "" {
			if err := routingEngine.LoadGeoIP(geoIPPath); err != nil {
				log.Printf("Failed to load GeoIP database: %v (continuing without GeoIP)", err)
			} else {
				log.Printf("GeoIP database loaded from %s", geoIPPath)
			}
		}

		if geoSitePath != "" {
			if err := routingEngine.LoadGeoSite(geoSitePath); err != nil {
				log.Printf("Failed to load GeoSite database: %v (continuing without GeoSite)", err)
			} else {
				log.Printf("GeoSite database loaded from %s", geoSitePath)
			}
		}

		// Периодически перезагружаем базы после обновления
		go func() {
			ticker := time.NewTicker(1 * time.Hour) // Проверяем каждый час
			defer ticker.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
					if geoUpdater != nil {
						needsUpdate, _ := geoUpdater.CheckUpdate()
						if needsUpdate {
							log.Printf("[GEO] Checking for geo database updates...")
							if err := geoUpdater.Update(); err != nil {
								log.Printf("[GEO] Failed to update databases: %v", err)
							} else {
								log.Printf("[GEO] Databases updated, reloading...")
								if err := routingEngine.ReloadGeoBases(); err != nil {
									log.Printf("[GEO] Failed to reload databases: %v", err)
								} else {
									log.Printf("[GEO] Databases reloaded successfully")
								}
							}
						}
					}
				}
			}
		}()
	} else {
		// Если автообновление выключено, загружаем из указанных файлов
		if geoIPFile != "" {
			if err := routingEngine.LoadGeoIP(geoIPFile); err != nil {
				log.Printf("Failed to load GeoIP database: %v (continuing without GeoIP)", err)
			} else {
				log.Printf("GeoIP database loaded from %s", geoIPFile)
			}
		}
		if geoSiteFile != "" {
			if err := routingEngine.LoadGeoSite(geoSiteFile); err != nil {
				log.Printf("Failed to load GeoSite database: %v (continuing without GeoSite)", err)
			} else {
				log.Printf("GeoSite database loaded from %s", geoSiteFile)
			}
		}
	}

	// Запускаем Prometheus метрики сервер (HTTP или HTTPS)
	if *metricsAddr != "" {
		go func() {
			if *metricsTLS {
				if *tlsCertPath == "" || *tlsKeyPath == "" {
					log.Printf("Metrics TLS disabled: missing -tls-cert/-tls-key")
					if err := metr.Serve(*metricsAddr); err != nil {
						log.Printf("metrics serve (HTTP): %v", err)
					}
				} else {
					log.Printf("Metrics server (HTTPS) starting on %s", *metricsAddr)
					if err := metr.ServeTLS(*metricsAddr, *tlsCertPath, *tlsKeyPath); err != nil {
						log.Printf("metrics serve (HTTPS): %v", err)
					}
				}
			} else {
				log.Printf("Metrics server (HTTP) starting on %s", *metricsAddr)
				if err := metr.Serve(*metricsAddr); err != nil {
					log.Printf("metrics serve: %v", err)
				}
			}
		}()
	}

	// Запускаем API сервер для управления (HTTP или HTTPS)
	var apiServer *apipkg.APIServer
	// ОПТИМИЗАЦИЯ: Используем RWMutex для чтения apiServer
	var apiServerMu sync.RWMutex
	if *apiAddr != "" {
		go func() {
			// Используем MarionetteAdapter из IntegrationManager
			var marionette *obfuscation.MarionetteAdapter
			if coreIM != nil {
				marionette = coreIM.GetMarionetteAdapter()
			} else {
				// Fallback: создаем новый адаптер если IntegrationManager не доступен
				marionette = obfuscation.NewMarionetteAdapter()
			}

			var cfg *cfgpkg.ServerConfig
			if *configPath != "" {
				var err error
				cfg, err = cfgpkg.LoadServer(*configPath)
				if err != nil {
					log.Printf("Failed to load config for API: %v", err)
					cfg = &cfgpkg.ServerConfig{}
				}
			} else {
				cfg = &cfgpkg.ServerConfig{}
			}

			var err error
			// По умолчанию используем HTTPS, если есть сертификаты
			useAPITLS := *apiTLS || (*tlsCertPath != "" && *tlsKeyPath != "")

			if useAPITLS {
				if *tlsCertPath == "" || *tlsKeyPath == "" {
					log.Printf("API server requires TLS certificates but -tls-cert/-tls-key not provided. API server disabled.")
					return
				}
				apiServerMu.Lock()
				apiServer, err = apipkg.NewAPIServerTLSWithKey(*apiAddr, *configPath, cfg, marionette, *tlsCertPath, *tlsKeyPath, *staticKeyHex)
				if apiServer != nil && serverRuntime != nil {
					apiServer.SetRuntime(serverRuntime)
				}
				apiServerMu.Unlock()
				if err != nil {
					log.Printf("Failed to create API server with TLS: %v", err)
					return
				}
				log.Printf("API server (HTTPS) starting on %s", *apiAddr)
				if err := apiServer.Start(); err != nil {
					log.Printf("API server (HTTPS) start error: %v", err)
				}
			} else {
				log.Printf("WARNING: API server starting in HTTP mode (not recommended for production). Use -api-tls or provide -tls-cert/-tls-key for HTTPS.")
				apiServerMu.Lock()
				apiServer = apipkg.NewAPIServer(*apiAddr, *configPath, cfg, marionette)
				if apiServer != nil && serverRuntime != nil {
					apiServer.SetRuntime(serverRuntime)
				}
				apiServerMu.Unlock()
				log.Printf("API server (HTTP) starting on %s", *apiAddr)
				if err := apiServer.Start(); err != nil {
					log.Printf("API server start error: %v", err)
				}
			}

			// Загружаем routing rules из API после запуска сервера
			if routingEngine != nil && apiServer != nil {
				// Устанавливаем routing engine в ManagementAPI для доступа к subscription manager
				managementAPI := apiServer.GetManagementAPI()
				if managementAPI != nil {
					managementAPI.SetRoutingEngine(routingEngine)
					// Устанавливаем глобальный managementAPI для доступа из других частей сервера
					setGlobalManagementAPI(managementAPI)
				}

				// Запускаем автоматическое обновление подписок
				routingEngine.StartSubscriptions()

				// Небольшая задержка для инициализации API сервера
				time.Sleep(500 * time.Millisecond)
				loadRoutingRulesFromAPI(apiServer)

				// Периодически обновляем правила из API (каждые 30 секунд)
				go func() {
					ticker := time.NewTicker(30 * time.Second)
					defer ticker.Stop()
					for {
						select {
						case <-ctx.Done():
							return
						case <-ticker.C:
							// ОПТИМИЗАЦИЯ: Используем RLock для чтения
							apiServerMu.RLock()
							api := apiServer
							apiServerMu.RUnlock()
							if api != nil {
								loadRoutingRulesFromAPI(api)
							}
						}
					}
				}()
			}
		}()
	}

	// Optional TCP listener (accepts multiple connections).
	// Если listenWS совпадает с listenTCP, объединяем их на одном порту (unified режим).
	unifiedTCPWS := *listenTCP != "" && *listenWS != "" && *listenTCP == *listenWS && *staticKeyHex != ""

	// Пока хелпер startSeparateTCPListener/tcpListenerConfig не выделен в отдельный файл,
	// оставляем существующую inline‑реализацию TCP‑листенера ниже. Здесь только считаем unifiedTCPWS.

	// Универсальный TCP/WebSocket listener на одном порту (inline реализация пока остаётся).
	if unifiedTCPWS {
		// В unified режиме используем существующий inline‑код ниже (TCP+WS на одном порту).
	} else {
		log.Printf("[Unified] Starting unified TCP/WebSocket server on %s (TCP and WS on same port)", *listenTCP)
		go func() {
			if *staticKeyHex == "" {
				log.Printf("[Unified] Unified TCP/WS listener disabled: -static-key required")
				return
			}

			priv, err := hex.DecodeString(*staticKeyHex)
			if err != nil || len(priv) != 32 {
				log.Printf("unified tcp/ws invalid static key: %v", err)
				return
			}

			// Создаем HTTP сервер для WebSocket
			mux := http.NewServeMux()
			mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/" {
					w.Header().Set("Content-Type", "text/html")
					// Определяем протокол (wss:// для HTTPS, ws:// для HTTP)
					wsProtocol := "ws://"
					if r.TLS != nil {
						wsProtocol = "wss://"
					}
					if _, err := w.Write([]byte(fmt.Sprintf(`
<!DOCTYPE html>
<html>
<head><title>Secure Chat</title></head>
<body>
<h1>Secure Chat Service</h1>
<p>WebSocket chat service is running.</p>
<script>
const ws = new WebSocket('%s' + location.host + '/ws');
ws.onopen = () => console.log('Connected');
ws.onmessage = (e) => console.log('Message:', e.data);
</script>
</body>
</html>`, wsProtocol))); err != nil {
						log.Printf("error writing response: %v", err)
					}
				} else {
					http.NotFound(w, r)
				}
			})

			// WebSocket handler
			mux.HandleFunc("/ws", func(w http.ResponseWriter, r *http.Request) {

				log.Printf("[WS] WebSocket connection attempt from %s, path: %s", r.RemoteAddr, r.URL.Path)

				ua := r.Header.Get("User-Agent")
				if ua == "" || len(ua) < 10 {
					log.Printf("[WS] Rejected: missing or invalid User-Agent")
					http.Error(w, "Bad Request", http.StatusBadRequest)
					return
				}

				log.Printf("[WS] User-Agent: %s", ua)

				suspiciousUA := []string{"curl", "wget", "python", "go-http", "Java"}
				for _, sus := range suspiciousUA {
					if ua != "" && len(ua) >= len(sus) && ua[:len(sus)] == sus {
						log.Printf("[WS] Detected suspicious UA: %s, returning probe response", sus)
						w.Header().Set("Content-Type", "text/plain")
						w.WriteHeader(http.StatusOK)
						if _, err := w.Write([]byte("Chat service available")); err != nil {
							log.Printf("error writing probe response: %v", err)
						}
						return
					}
				}

				token := r.Header.Get("X-Auth-Token")
				// SECURITY: Не логируем токены - это утечка секретов
				if token != "" && token != "whispera-v1" {
					log.Printf("[WS] Rejected: invalid token")
					http.Error(w, "Service Unavailable", http.StatusServiceUnavailable)
					return
				}

				w.Header().Set("Server", "nginx/1.20.1")
				w.Header().Set("X-Content-Type-Options", "nosniff")
				w.Header().Set("X-Frame-Options", "DENY")

				c, err := websocket.Accept(w, r, &websocket.AcceptOptions{
					Subprotocols:   []string{"chat", "superchat"},
					OriginPatterns: []string{"*"}, // Разрешаем все Origin для обхода DPI
				})
				if err != nil {
					log.Printf("[WS] WebSocket accept failed in unified mode: %v", err)
					return
				}
				log.Printf("[WS] WebSocket connection accepted in unified mode from %s", r.RemoteAddr)
				// Note: defer removed - connection will be closed only when data plane goroutines exit

				// Noise IK removed - use XHTTP instead
				log.Printf("[WS] Noise IK removed, use XHTTP protocol instead")
				c.Close(websocket.StatusPolicyViolation, "Noise IK removed, use XHTTP")
				return
			})

			lc := net.ListenConfig{}
			ctx := context.Background()
			ln, err := lc.Listen(ctx, "tcp4", *listenTCP)
			if err != nil {
				log.Printf("unified tcp/ws listen error: %v", err)
				return
			}
			log.Printf("[Unified] Unified TCP/WebSocket server listening on %s (XHTTP recommended)", *listenTCP)
			defer func() {
				if err := ln.Close(); err != nil {
					log.Printf("error closing unified listener: %v", err)
				}
			}()

			httpServer := &http.Server{
				Handler:           mux,
				ReadTimeout:       0, // No timeout for WebSocket - keep connection alive
				WriteTimeout:      0, // No timeout for WebSocket - keep connection alive
				IdleTimeout:       0, // No idle timeout for WebSocket - keep connection alive
				ReadHeaderTimeout: 5 * time.Second,
			}

			// Если есть TLS сертификаты, настраиваем TLS для unified сервера
			if *tlsCertPath != "" && *tlsKeyPath != "" {
				// Для unified сервера с TLS нужно использовать TLS listener
				// Но так как мы используем обычный TCP listener для различения HTTP и Noise IK,
				// мы не можем напрямую использовать TLS listener
				// Вместо этого, если TLS включен, используем только TLS соединения
				log.Printf("[Unified] TLS enabled for unified TCP/WebSocket server - TLS connections only")
				// Load TLS certificate
				cert, err := tls.LoadX509KeyPair(*tlsCertPath, *tlsKeyPath)
				if err != nil {
					log.Printf("[Unified] Failed to load TLS certificate: %v", err)
					return
				}
				// SECURITY: Используем браузероподобный TLS fingerprint для обхода DPI
				httpServer.TLSConfig = tlspkg.GetBrowserLikeServerTLSConfig(
					tlspkg.GetDefaultBrowserFingerprint(),
					[]tls.Certificate{cert},
				)
				httpServer.ErrorLog = log.New(&tlsErrorFilter{original: os.Stderr}, "", log.LstdFlags)
			}

			for {
				conn, err := ln.Accept()
				if err != nil {
					log.Printf("unified accept error: %v", err)
					continue
				}

				go func(c net.Conn) {
					defer func() {
						if err := c.Close(); err != nil {
							// Игнорируем ошибки закрытия уже закрытого соединения - это нормально
							if !strings.Contains(err.Error(), "use of closed network connection") &&
								!strings.Contains(err.Error(), "closed network connection") {
								log.Printf("error closing connection: %v", err)
							}
						}
					}()

					// Читаем первые байты для определения типа соединения
					// Устанавливаем таймаут для чтения
					if err := c.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
						log.Printf("failed to set read deadline: %v", err)
						return
					}

					// Читаем больше байтов для sniffing (SNI или HTTP Host)
					peekBytes := make([]byte, 512)
					n, err := c.Read(peekBytes)
					if err != nil && err != io.EOF {
						log.Printf("read error: %v", err)
						_ = c.SetReadDeadline(time.Time{})
						return
					}

					// Сбрасываем deadline
					_ = c.SetReadDeadline(time.Time{})

					// Если прочитали меньше байтов, обрезаем
					if n < len(peekBytes) {
						peekBytes = peekBytes[:n]
					}

					// Пытаемся извлечь домен через sniffing (SNI или HTTP Host)
					var domain string
					if sniffingpkg.IsTLSClientHello(peekBytes) {
						// Это TLS соединение - пытаемся извлечь SNI
						sni, err := sniffingpkg.PeekSNI(peekBytes)
						if err == nil && sni != "" {
							domain = sni
							log.Printf("[SNI] Detected SNI: %s from %s", domain, c.RemoteAddr())
							// Сохраняем домен в кэш routing engine для использования в routing rules
							if routingEngine != nil {
								// Получаем IP адрес из соединения для кэширования
								if remoteAddr := c.RemoteAddr(); remoteAddr != nil {
									if tcpAddr, ok := remoteAddr.(*net.TCPAddr); ok {
										routingEngine.CacheDomain(domain, tcpAddr.IP)
										// Синхронизируем Fake-IP маппинг, если IP является Fake-IP
										routingEngine.SyncFakeIPMapping(tcpAddr.IP, domain)
									}
								}
							}
						}
					} else if sniffingpkg.IsHTTPRequest(peekBytes) {
						// Это HTTP запрос - пытаемся извлечь Host header
						host, err := sniffingpkg.PeekHTTPHost(peekBytes)
						if err == nil && host != "" {
							domain = host
							log.Printf("[HTTP] Detected Host: %s from %s", domain, c.RemoteAddr())
							// Сохраняем домен в кэш routing engine для использования в routing rules
							if routingEngine != nil {
								// Получаем IP адрес из соединения для кэширования
								if remoteAddr := c.RemoteAddr(); remoteAddr != nil {
									if tcpAddr, ok := remoteAddr.(*net.TCPAddr); ok {
										routingEngine.CacheDomain(domain, tcpAddr.IP)
										// Синхронизируем Fake-IP маппинг, если IP является Fake-IP
										routingEngine.SyncFakeIPMapping(tcpAddr.IP, domain)
									}
								}
							}
						}
					}

					// Создаем reader, который включает прочитанные байты
					br := bufio.NewReader(io.MultiReader(bytes.NewReader(peekBytes), c))

					// Проверяем, является ли это HTTP запросом
					// HTTP методы: GET, POST, HEAD, PUT, DELETE, OPTIONS, PATCH
					isHTTP := false
					httpMethods := [][]byte{
						[]byte("GET "), []byte("POST"), []byte("HEAD"),
						[]byte("PUT "), []byte("DELE"), []byte("OPTI"),
						[]byte("PATC"),
					}
					for _, method := range httpMethods {
						if bytes.HasPrefix(peekBytes, method) {
							isHTTP = true
							break
						}
					}

					if isHTTP {
						// Это HTTP/WebSocket соединение
						// Создаем соединение, которое читает из буфера
						bufConn := &bufferedConn{
							Conn:   c,
							Reader: br,
						}
						// Используем ServeHTTP напрямую через http.ServeConn
						// Но так как ServeConn не существует, создаем временный HTTP connection
						// Используем http.Serve с кастомным listener
						go func() {
							// Создаем временный HTTP connection handler
							connChan := make(chan net.Conn, 1)
							connChan <- bufConn
							close(connChan)

							// Используем ServeHTTP через http.Serve
							// Но это требует listener, поэтому используем другой подход
							// Создаем временный listener для одного соединения
							tempListener := &singleConnListener{
								conn: bufConn,
								done: make(chan struct{}, 1),
							}
							_ = httpServer.Serve(tempListener)
						}()
					} else if sniffingpkg.IsTLSClientHello(peekBytes) && *xhttpTarget != "" {
						// Это XHTTP TLS соединение с Marionette обфускацией
						var xhttpConfig *xhttppkg.ServerConfig
						var err error

						if *xhttpPrivateKey != "" && *xhttpShortID != "" {
							privKeyBytes, err := hex.DecodeString(*xhttpPrivateKey)
							if err != nil || len(privKeyBytes) != 64 {
								log.Printf("xhttp private key error: %v", err)
								return
							}
							privKey := ed25519.PrivateKey(privKeyBytes)

							shortIDBytes, err := hex.DecodeString(*xhttpShortID)
							if err != nil || len(shortIDBytes) != 8 {
								log.Printf("xhttp short ID error: %v", err)
								return
							}

							xhttpConfig, err = xhttppkg.NewServerConfigWithKeys(
								strings.Split(*xhttpServerNames, ","),
								privKey,
								[][]byte{shortIDBytes},
								coreIM, // Pass Marionette IntegrationManager
							)
						} else {
							xhttpConfig, err = xhttppkg.NewServerConfig(strings.Split(*xhttpServerNames, ","), coreIM)
						}

						if err != nil {
							log.Printf("xhttp config error: %v", err)
							return
						}

						// Apply loaded XHTTP JSON config defaults if provided
						if loadedXHTTPConfig != nil {
							loadedXHTTPConfig.ApplyToServerConfig(xhttpConfig)
						}

						xhttpConn, err := xhttpConfig.HandleConn(context.Background(), c)
						if err != nil {
							log.Printf("xhttp handshake error: %v", err)
							c.Close()
							return
						}

						vlessHdr, err := vlesspkg.ReadRequestHeader(xhttpConn)
						if err != nil {
							// Handle EOF gracefully - client may have closed connection during handshake
							if err == io.EOF || strings.Contains(err.Error(), "EOF") {
								log.Printf("[XHTTP] Client closed connection during VLESS header read (EOF)")
							} else {
								log.Printf("[XHTTP] VLESS header error: %v", err)
							}
							xhttpConn.Close()
							return
						}

						sid := binary.BigEndian.Uint32(vlessHdr.UUID[:4])

						log.Printf("[XHTTP] ✅ XHTTP+VLESS connection established with Marionette obfuscation, sessionID=%d", sid)

						ipAddr := getIPFromAddr(c.RemoteAddr())
						userID := resolveUserID(ipAddr, "")

						if !checkPolicyConnection(userID, ipAddr) {
							log.Printf("[POLICY] ⚠️ XHTTP connection blocked for %s (userID=%s): connection limit exceeded", ipAddr, userID)
							xhttpConn.Close()
							return
						}

						if !checkPolicyTimeBased(userID, util.GetGlobalTimeCache().Now()) {
							log.Printf("[POLICY] ⚠️ XHTTP connection blocked for %s (userID=%s): time-based policy restriction", ipAddr, userID)
							xhttpConn.Close()
							return
						}

						// Все проверки пройдены - легитимный клиент
						log.Printf("[POLICY] ✅ XHTTP policy checks passed for %s (userID=%s, sessionID=%d)", ipAddr, userID, sid)

						// Создаем сессию для XHTTP
						// Преобразуем RemoteAddr в *net.UDPAddr
						var udpAddr *net.UDPAddr
						if addr, ok := c.RemoteAddr().(*net.UDPAddr); ok {
							udpAddr = addr
						} else {
							// Fallback: создаем UDPAddr из строки
							if addr, err := net.ResolveUDPAddr("udp", c.RemoteAddr().String()); err == nil {
								udpAddr = addr
							}
						}
						if udpAddr != nil {
							sessionMgr.UpdateSession(sid, udpAddr, nil, nil)
						}
						if userID != "" {
							sessionMgr.SetUserID(sid, userID)
						}

						// Регистрируем connection в connection enforcer
						api := getGlobalManagementAPI()
						if api != nil {
							api.GetConnectionEnforcer().AddConnection(userID, ipAddr)
						}

						log.Printf("[XHTTP] Starting XHTTP data plane for sessionID=%d", sid)
						// Запускаем data plane в горутине с cleanup при завершении
						go func() {
							defer func() {
								xhttpConn.Close()
								if sessionMgr != nil {
									sessionMgr.RemoveSession(sid)
								}
								if api != nil {
									api.GetConnectionEnforcer().RemoveConnection(userID, ipAddr)
								}
							}()
							runXHTTPDataPlane(xhttpConn, sid, tun, *kaSec, coreIM, *xhttpMode, *xhttpMaxConcurrency)
						}()
						log.Printf("[XHTTP] ✅ XHTTP data plane started for sessionID=%d", sid)
					} else {
						// Legacy TCP connections are no longer supported
						// Use XHTTP instead
						log.Printf("[TCP] Legacy TCP connection rejected. Use XHTTP protocol instead.")
						c.Close()
						return
					}
				}(conn)
			}
		}()
	}

	// Optional WS listener with advanced mimicry (только если не используется unified режим)
	if *listenWS != "" && *staticKeyHex != "" && !unifiedTCPWS {
		// Пока helper startSeparateWebSocketServer не вынесен полностью,
		// используем существующую inline‑реализацию ниже.
	} else {
		// Legacy inline implementation (to be removed)
		log.Printf("[WS] Starting separate WebSocket server on %s (unifiedTCPWS=%v)", *listenWS, unifiedTCPWS)
		go func() {
			// Create separate ServeMux for WS server to avoid conflicts
			mux := http.NewServeMux()

			// Serve static website for legitimacy
			mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/" {
					// Simple chat-like landing page
					w.Header().Set("Content-Type", "text/html")
					// Определяем протокол (wss:// для HTTPS, ws:// для HTTP)
					wsProtocol := "ws://"
					if r.TLS != nil {
						wsProtocol = "wss://"
					}
					if _, err := w.Write([]byte(fmt.Sprintf(`
<!DOCTYPE html>
<html>
<head><title>Secure Chat</title></head>
<body>
<h1>Secure Chat Service</h1>
<p>WebSocket chat service is running.</p>
<script>
const ws = new WebSocket('%s' + location.host + '/ws');
ws.onopen = () => console.log('Connected');
ws.onmessage = (e) => console.log('Message:', e.data);
</script>
</body>
</html>`, wsProtocol))); err != nil {
						log.Printf("error writing response: %v", err)
					}
				} else {
					http.NotFound(w, r)
				}
			})

			mux.HandleFunc("/ws", func(w http.ResponseWriter, r *http.Request) {
				log.Printf("[WS] WebSocket connection attempt from %s, path: %s (separate server)", r.RemoteAddr, r.URL.Path)

				// Advanced probe detection
				ua := r.Header.Get("User-Agent")
				if ua == "" || len(ua) < 10 {
					log.Printf("[WS] Rejected: missing or invalid User-Agent (separate server)")
					http.Error(w, "Bad Request", http.StatusBadRequest)
					return
				}

				log.Printf("[WS] User-Agent: %s (separate server)", ua)

				// Detect common DPI probe patterns
				suspiciousUA := []string{"curl", "wget", "python", "go-http", "Java"}
				for _, sus := range suspiciousUA {
					if ua != "" && len(ua) >= len(sus) && ua[:len(sus)] == sus {
						log.Printf("[WS] Detected suspicious UA: %s, returning probe response (separate server)", sus)
						// Respond like a normal chat server to probes
						w.Header().Set("Content-Type", "text/plain")
						w.WriteHeader(http.StatusOK)
						if _, err := w.Write([]byte("Chat service available")); err != nil {
							log.Printf("error writing probe response: %v", err)
						}
						return
					}
				}

				// Token authentication with probe resistance
				token := r.Header.Get("X-Auth-Token")
				// SECURITY: Не логируем токены - это утечка секретов
				if token != "" && token != "whispera-v1" {
					log.Printf("[WS] Rejected: invalid token (separate server)")
					// Don't reveal auth failure to probes
					http.Error(w, "Service Unavailable", http.StatusServiceUnavailable)
					return
				}

				// ML-evasion: randomize response timing

				// Set realistic response headers
				w.Header().Set("Server", "nginx/1.20.1")
				w.Header().Set("X-Content-Type-Options", "nosniff")
				w.Header().Set("X-Frame-Options", "DENY")

				c, err := websocket.Accept(w, r, &websocket.AcceptOptions{
					Subprotocols:   []string{"chat", "superchat"},
					OriginPatterns: []string{"*"}, // Разрешаем все Origin для обхода DPI
				})
				if err != nil {
					log.Printf("[WS] WebSocket accept failed (separate server): %v", err)
					return
				}
				log.Printf("[WS] ✅ WebSocket connection accepted from %s (separate server)", r.RemoteAddr)
				log.Printf("[WS] Connection details: TLS=%v, Protocol=%s (separate server)", r.TLS != nil, r.Proto)

				// Проверяем, что соединение действительно установлено
				// Не закрываем соединение сразу, даем время на handshake
				// Note: defer removed - connection will be закрыто только при завершении горутин data plane

				priv, err := hex.DecodeString(*staticKeyHex)
				if err != nil || len(priv) != 32 {
					log.Printf("[WS] Bad static key (separate server)")
					return
				}
				// Noise IK removed - use XHTTP instead
				log.Printf("[WS] Noise IK removed, use XHTTP protocol instead")
				c.Close(websocket.StatusPolicyViolation, "Noise IK removed, use XHTTP")
				return
			})
			// Нормализуем адрес для IPv4
			normalizedWSAddr := normalizeListenAddr(*listenWS)
			log.Printf("[WS] WebSocket server starting on %s (normalized: %s)", *listenWS, normalizedWSAddr)

			// Явно используем IPv4 для слушателя
			lc := net.ListenConfig{}
			ln, err := lc.Listen(context.Background(), "tcp4", normalizedWSAddr)
			if err != nil {
				log.Printf("[WS] Failed to listen on %s: %v", normalizedWSAddr, err)
				return
			}

			srv := &http.Server{
				Handler:           mux,
				ReadTimeout:       0, // No timeout for WebSocket - keep connection alive
				WriteTimeout:      0, // No timeout for WebSocket - keep connection alive
				IdleTimeout:       0, // No idle timeout for WebSocket - keep connection alive
				ReadHeaderTimeout: 5 * time.Second,
			}

			// Если есть TLS сертификаты, используем HTTPS (wss://)
			if *tlsCertPath != "" && *tlsKeyPath != "" {
				// Load TLS certificate
				cert, err := tls.LoadX509KeyPair(*tlsCertPath, *tlsKeyPath)
				if err != nil {
					log.Printf("[WS] Failed to load TLS certificate: %v", err)
					return
				}
				// SECURITY: Используем браузероподобный TLS fingerprint для обхода DPI
				srv.TLSConfig = tlspkg.GetBrowserLikeServerTLSConfig(
					tlspkg.GetDefaultBrowserFingerprint(),
					[]tls.Certificate{cert},
				)
				// Wrap error log to filter TLS errors
				srv.ErrorLog = log.New(&tlsErrorFilter{original: os.Stderr}, "", log.LstdFlags)
				log.Printf("[WS] WebSocket server (WSS/HTTPS) starting on %s", normalizedWSAddr)
				tlsListener := tls.NewListener(ln, srv.TLSConfig)
				if err := srv.Serve(tlsListener); err != nil && err != http.ErrServerClosed {
					log.Printf("[WS] WebSocket server error on %s: %v", normalizedWSAddr, err)
				}
			} else {
				log.Printf("[WS] WARNING: WebSocket server starting in HTTP mode (ws://). Use -tls-cert/-tls-key for HTTPS (wss://).")
				if err := srv.Serve(ln); err != nil && err != http.ErrServerClosed {
					log.Printf("[WS] WebSocket server error on %s: %v", normalizedWSAddr, err)
				}
			}
		}()
	}

	// Optional HTTP/2 WebSocket / gRPC / QUIC / HTTP/2 servers
	// ВРЕМЕННО ОТКЛЮЧЕНО: вспомогательные функции startHTTP2WebSocketServer/startGRPCServer/
	// startQUICServer/startHTTP2Server отсутствуют в текущей сборке. Основной XHTTP+TUN сценарий
	// продолжает работать через основной UDP/TCP/WS слушатели.

	// Start SOCKS5 proxy server
	if *socks5Addr != "" {
		go func() {
			socks5Server := proxypkg.NewSOCKS5Server(*socks5Addr, func(clientConn net.Conn, targetAddr string, targetPort uint16) error {
				// Проксируем соединение к целевому серверу
				targetConn, err := net.DialTimeout("tcp", net.JoinHostPort(targetAddr, strconv.Itoa(int(targetPort))), 10*time.Second)
				if err != nil {
					return err
				}
				defer targetConn.Close()

				// Проксируем данные в обе стороны
				errChan := make(chan error, 2)
				go func() {
					_, err := io.Copy(targetConn, clientConn)
					errChan <- err
				}()
				go func() {
					_, err := io.Copy(clientConn, targetConn)
					errChan <- err
				}()

				// Ждем завершения одной из сторон
				<-errChan
				return nil
			})
			if err := socks5Server.ListenAndServe(); err != nil {
				log.Printf("[SOCKS5] Proxy server error: %v", err)
			}
		}()
		log.Printf("[SOCKS5] Proxy server starting on %s", *socks5Addr)
	}

	// Start HTTP proxy server
	if *httpProxyAddr != "" {
		go func() {
			httpProxy := proxypkg.NewHTTPServer(*httpProxyAddr, proxypkg.SimpleHTTPProxyHandler())
			if err := httpProxy.ListenAndServe(); err != nil {
				log.Printf("[HTTP-PROXY] Proxy server error: %v", err)
			}
		}()
		log.Printf("[HTTP-PROXY] Proxy server starting on %s", *httpProxyAddr)
	}

	// Handshake теперь обрабатывается в основном UDP loop, а не блокирующе
	// Инициализируем staticPriv для handshake
	staticPriv, err := initStaticPrivateKey(*staticKeyHex, psk)
	if err != nil {
		log.Printf("ERROR: %v", err)
		return
	}
	if staticPriv == nil {
		// PSK mode - обрабатывается позже в data plane
	}

	// Reassembly buffer for fragmented payloads (per-session reassembly будет добавлен позже)
	reasm := proto.NewReassembler(15*time.Second, 512)

	// Keepalive ticker для всех активных сессий
	if *staticKeyHex != "" && *kaSec > 0 {
		go func() {
			kaTicker := time.NewTicker(time.Duration(*kaSec) * time.Second)
			defer kaTicker.Stop()
			for range kaTicker.C {
				// Получаем все активные сессии
				allSessions := sessionMgr.GetAllSessions()
				for _, session := range allSessions {
					session.Mu.RLock()
					clientAddr := session.ClientAddr
					aeadState := session.AEADState
					seqSend := session.SeqSend
					sessionID := session.SessionID
					session.Mu.RUnlock()

					if clientAddr == nil || aeadState == nil {
						continue
					}
					var hdr proto.PacketHeader
					hdr.Version = proto.Version
					hdr.Flags = proto.FlagControl
					hdr.SessionID = sessionID
					hdr.Seq = seqSend
					hdr.PayloadLen = uint16(1 + 16)
					aad := hdr.MarshalBinary()
					ciphertext, err := aeadState.Encrypt(hdr.Seq, aad, []byte{proto.CtrlKeepAlive})
					if err != nil {
						log.Printf("keepalive encrypt error for session %d: %v", sessionID, err)
						continue
					}
					pktOut := util.Concat(aad, ciphertext)
					_, _ = conn.WriteToUDP(pktOut, clientAddr)
					metr.KeepaliveSent.Inc()

					// Обновляем sequence number и активность сессии
					sessionMgr.IncrementSeqSend(sessionID)
				}
			}
		}()
	}

	// Server-initiated periodic rekey (optional) - обновлен для работы с множественными сессиями
	if *staticKeyHex != "" && *rkSrvMin > 0 {
		go func() {
			t := time.NewTicker(time.Duration(*rkSrvMin) * time.Minute)
			defer t.Stop()
			for range t.C {
				// Получаем все активные сессии и делаем rekey для каждой
				allSessions := sessionMgr.GetAllSessions()
				for i := range allSessions {
					session := allSessions[i]
					session.Mu.RLock()
					clientAddr := session.ClientAddr
					aeadState := session.AEADState
					sessionID := session.SessionID
					seqSend := session.SeqSend
					seed := session.Seed
					session.Mu.RUnlock()

					if clientAddr == nil || aeadState == nil || len(seed) == 0 {
						continue
					}

					salt := make([]byte, 32)
					if _, err := rand.Read(salt); err != nil {
						continue
					}
					var hdr proto.PacketHeader
					hdr.Version = proto.Version
					hdr.Flags = proto.FlagControl
					hdr.SessionID = sessionID
					hdr.Seq = seqSend
					hdr.PayloadLen = uint16(1 + 32 + 16)
					aad := hdr.MarshalBinary()
					payload := util.Concat([]byte{proto.CtrlRekey}, salt)
					if ct, err := aeadState.Encrypt(hdr.Seq, aad, payload); err == nil {
						pktOut := util.Concat(aad, ct)
						if _, err := conn.WriteToUDP(pktOut, clientAddr); err == nil {
							if sendK, recvK, err := aeadpkg.DeriveRekey(seed, salt, false); err == nil {
								if st, err2 := aeadpkg.NewAEADState(sendK, recvK); err2 == nil {
									sessionMgr.UpdateSessionAEAD(sessionID, st)
									metr.RekeyCount.Inc()
									metr.RekeyTriggerTime.Inc()
								}
							}
							sessionMgr.SetSeqSend(sessionID, 1)
							sessionMgr.IncrementSeqSend(sessionID)
						}
					}
				}
			}
		}()
	}

	// Optional chaff traffic (server-originated). Disabled when strict shaping is enabled.
	// Переведено на runtime-конфиг, чтобы можно было менять параметры без рестарта.
	if !*obfsStrict {
		go func() {
			// Базовый тикер 100ms для более точного контроля распределения интервалов.
			chaffTicker := time.NewTicker(100 * time.Millisecond)
			defer chaffTicker.Stop()

			var nextSend time.Time
			on := true
			nextSwitch := time.Now()

			for range chaffTicker.C {
				cfg := getChaffRuntimeConfig()
				// Если chaff выключен, просто продолжаем.
				if cfg.Sec <= 0 {
					nextSend = time.Time{}
					continue
				}

				// Вычисляем следующий интервал на основе распределения (const/exp/pareto).
				now := time.Now()
				if nextSend.IsZero() || now.After(nextSend) {
					// Генерируем следующий интервал на основе распределения.
					interval := calculateChaffInterval(cfg)
					nextSend = now.Add(interval)
				} else {
					// Еще не время отправлять.
					continue
				}

				// duty cycle switching (используем runtime-конфиг)
				if cfg.DutyOn > 0 || cfg.DutyOff > 0 {
					if time.Now().After(nextSwitch) {
						on = !on
						if on {
							nextSwitch = time.Now().Add(time.Duration(cfg.DutyOn) * time.Second)
						} else {
							nextSwitch = time.Now().Add(time.Duration(cfg.DutyOff) * time.Second)
						}
					}
				}
				if !on {
					continue
				}

				// Получаем все активные сессии и отправляем chaff для каждой
				allSessions := sessionMgr.GetAllSessions()
				for i := range allSessions {
					session := allSessions[i]
					session.Mu.RLock()
					clientAddr := session.ClientAddr
					aeadState := session.AEADState
					sessionID := session.SessionID
					seqSend := session.SeqSend
					session.Mu.RUnlock()

					if clientAddr == nil || aeadState == nil {
						continue
					}

					var hdr proto.PacketHeader
					hdr.Version = proto.Version
					hdr.Flags = proto.FlagControl
					hdr.SessionID = sessionID
					hdr.Seq = seqSend
					// base control payload
					plain := []byte{proto.CtrlKeepAlive}
					payload := plain
					// Optional size shaping to a random total target
					if cfg.SizeMax > 0 && cfg.SizeMax >= cfg.SizeMin && cfg.SizeMin > 0 {
						span := cfg.SizeMax - cfg.SizeMin + 1
						// Use crypto/rand for secure randomness
						n, err := rand.Int(rand.Reader, big.NewInt(int64(span)))
						if err != nil {
							return
						}
						totalTarget := cfg.SizeMin + int(n.Int64())
						need := totalTarget - (int(proto.HeaderLen) + 16)
						if need < (2 + len(plain)) {
							need = 2 + len(plain)
						}
						pad := need - (2 + len(plain))
						framed := make([]byte, 2+len(plain)+pad)
						framed[0] = byte(len(plain) >> 8)
						framed[1] = byte(len(plain))
						copy(framed[2:], plain)
						payload = framed
						hdr.Flags |= proto.FlagObfsPad
					}
					// set payload length for header
					cipherLen := len(payload) + 16
					if cipherLen > 0xFFFF {
						continue
					}
					hdr.PayloadLen = uint16(cipherLen) //nolint:gosec // Bounds checked: cipherLen <= 0xFFFF
					aad := hdr.MarshalBinary()
					ct, err := aeadState.Encrypt(hdr.Seq, aad, payload)
					if err != nil {
						log.Printf("chaff encrypt error for session %d: %v", sessionID, err)
						continue
					}
					pkt := util.Concat(aad, ct)
					_, _ = conn.WriteToUDP(pkt, clientAddr)
					metr.KeepaliveSent.Inc()
					metr.ChaffSent.Inc()
					sessionMgr.IncrementSeqSend(sessionID)
				}
			}
		}()
	}

	// Rate limiter для handshake (глобальный, с поддержкой live‑reload через runtime callbacks)
	handshakeLimiter := newHandshakeLimiter(*hsRate, *hsBurst)
	if serverRuntime != nil {
		serverRuntime.SetHandshakeLimiterCallback(func(rate float64, burst int) {
			if handshakeLimiter != nil {
				handshakeLimiter.Set(rate, burst)
				log.Printf("[Runtime] Applied handshake limits change: rate=%.2f, burst=%d", rate, burst)
			}
		})
	}

	// UDP -> TUN handler с поддержкой множественных клиентов
	go func() {
		defer func() {
			if r := recover(); r != nil {
				log.Printf("UDP reader goroutine panic recovered: %v", r)
			}
		}()
		buf := make([]byte, maxUDPPacket)
		packetCount := 0
		lastClosedErrTime := time.Time{}
		for {
			n, raddr, err := conn.ReadFromUDP(buf)
			if err != nil {
				var nerr net.Error
				if errors.As(err, &nerr) && nerr.Timeout() {
					continue
				}
				// Проверяем, закрыто ли соединение - игнорируем эту ошибку, но не выходим
				// Это может происходить временно, соединение может быть восстановлено
				if strings.Contains(err.Error(), "use of closed network connection") ||
					strings.Contains(err.Error(), "closed network connection") {
					// Логируем только раз в минуту, чтобы не спамить
					now := time.Now()
					if now.Sub(lastClosedErrTime) > time.Minute {
						log.Printf("UDP read: connection temporarily closed, continuing...")
						lastClosedErrTime = now
					}
					// ОПТИМИЗАЦИЯ: Убираем sleep для производительности, используем runtime.Gosched()
					runtime.Gosched()
					continue
				}
				// Для других ошибок логируем, но продолжаем работу
				log.Printf("udp read error: %v", err)
				continue
			}
			packetCount++
			if packetCount%100 == 0 || *audit {
				log.Printf("UDP: Received packet #%d from %s (%d bytes)", packetCount, raddr, n)
			}
			metr.PacketsRx.Inc()
			metr.BytesRx.Add(float64(n))

			// Логируем первые байты пакетов для диагностики (только для подозрительных размеров)
			if n == 152 || n == 48 {
				log.Printf("[UDP] Packet #%d from %s: size=%d, first 8 bytes: %02x %02x %02x %02x %02x %02x %02x %02x",
					packetCount, raddr, n, buf[0], buf[1], buf[2], buf[3], buf[4], buf[5], buf[6], buf[7])
			}

			// Сначала пытаемся распарсить как data packet (с заголовком протокола)
			// Data пакеты имеют заголовок proto.PacketHeader (12 байт) или CompactHeaderV2 (6 байт)
			// Handshake пакеты (legacy) не имеют такого заголовка
			version, headerSize, err := proto.ParsePacketHeader(buf[:n])
			isDataPacket := err == nil && headerSize <= n

			// Логируем результат парсинга для пакетов 152 байта
			if auditFlag != nil && *auditFlag && n == 152 {
				// Детальный анализ первых байт
				versionBits := (buf[0] >> 5) & 0x07
				firstByte := buf[0]
				if err != nil {
					log.Printf("[PARSE] ⚠️ Packet #%d from %s: size=152 bytes, header parse failed: %v",
						packetCount, raddr, err)
					log.Printf("[PARSE] 🔍 First byte analysis: 0x%02x (decimal %d), version bits (>>5&0x07)=%d, first 16 bytes: %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x",
						firstByte, firstByte, versionBits,
						buf[0], buf[1], buf[2], buf[3], buf[4], buf[5], buf[6], buf[7],
						buf[8], buf[9], buf[10], buf[11], buf[12], buf[13], buf[14], buf[15])
				} else {
					log.Printf("[PARSE] ✅ Packet #%d from %s: size=152 bytes, parsed as data packet (version=%d, headerSize=%d)",
						packetCount, raddr, version, headerSize)
				}
			}

			// Дополнительная проверка: если парсинг успешен, но пакет размером 48 байт (характерный для handshake)
			// и нет активной сессии для этого адреса, это может быть handshake, который случайно начался с похожего байта
			if isDataPacket && n == 48 && *staticKeyHex != "" {
				// Проверяем, есть ли активная сессия для этого адреса
				// Если сессии нет, это скорее всего handshake, а не data packet
				hasSession := false
				if version == proto.Version {
					// V1 протокол - проверяем SessionID
					if n >= proto.HeaderLen {
						var h proto.PacketHeader
						if err := h.UnmarshalBinary(buf[:proto.HeaderLen]); err == nil {
							sess := sessionMgr.GetSession(h.SessionID)
							hasSession = (sess != nil)
						}
					}
				}
				// Также проверяем по адресу клиента (для V2 и как дополнительная проверка для V1)
				if !hasSession {
					sess := sessionMgr.GetSessionByClientAddr(raddr)
					hasSession = (sess != nil)
				}

				if !hasSession {
					// Нет активной сессии - это скорее всего handshake
					log.Printf("[UDP] Packet from %s parsed as data packet but size 48 bytes and no active session, treating as handshake", raddr)
					isDataPacket = false
				}
			}

			if !isDataPacket {
				// Получаем актуальные anti-amplification лимиты из runtime-конфига.
				ampCfg := getAmpRuntimeConfig()
				if processNonDataPacket(
					buf[:n],
					n,
					err,
					raddr,
					conn,
					packetCount,
					audit,
					handshakeLimiter,
					ampCfg.MaxRatio,
					ampCfg.MaxBytes,
					staticPriv,
					*staticKeyHex != "",
					coreIM,
				) {
					continue
				}
			}

			var seq uint32
			var payloadLen uint16
			var flags byte
			var sessionID uint32
			var aad []byte
			var streamID uint16

			if version == proto.Version2 {
				// V2 протокол
				var h2 proto.CompactHeaderV2
				if err := h2.UnmarshalBinary(buf[:proto.CompactHeaderLenV2]); err != nil {
					metr.Drops.Inc()
					continue
				}
				seq = h2.Seq
				flags = h2.Flags
				streamID = h2.StreamID
				// Извлекаем PayloadLen
				offset := proto.CompactHeaderLenV2
				if len(buf) > offset {
					if buf[offset] == 0xFF && len(buf) > offset+2 {
						payloadLen = uint16(buf[offset+1])<<8 | uint16(buf[offset+2])
						headerSize = proto.CompactHeaderLenV2 + 3
					} else {
						payloadLen = uint16(buf[offset])
						headerSize = proto.CompactHeaderLenV2 + 1
					}
				}
				aad = buf[:headerSize]
				// В V2 SessionID не входит в компактный заголовок, поэтому
				// определяем его по адресу клиента. Это сохраняет semantics
				// "одна Noise‑сессия на клиента", а StreamID остаётся для mux-а.
				if sess := sessionMgr.GetSessionByClientAddr(raddr); sess != nil {
					sessionID = sess.SessionID
				} else {
					metr.Drops.Inc()
					continue
				}
			} else {
				// V1 протокол (fallback)
				var h proto.PacketHeader
				if err := h.UnmarshalBinary(buf[:proto.HeaderLen]); err != nil {
					metr.Drops.Inc()
					continue
				}
				seq = h.Seq
				payloadLen = h.PayloadLen
				flags = h.Flags
				sessionID = h.SessionID
				aad = buf[:proto.HeaderLen]
				headerSize = proto.HeaderLen
			}

			if int(payloadLen)+headerSize != n {
				if *audit {
					log.Printf("[UDP] Packet size mismatch from %s: expected %d (header %d + payload %d), got %d",
						raddr, int(payloadLen)+headerSize, headerSize, payloadLen, n)
				}
				metr.Drops.Inc()
				continue
			}

			// Получаем сессию
			session := sessionMgr.GetSession(sessionID)
			if session == nil {
				// Сессия не найдена - возможно это handshake или старая сессия.
				// Если пакет в диапазоне размеров, характерных для Noise‑handshake,
				// просто логируем подсказку, но не пытаемся переразобрать его здесь.
				if *staticKeyHex != "" && n >= 32 && n <= 96 {
					log.Printf("[UDP] Packet from %s parsed as data packet (sessionID=%d) but session not found, size %d bytes - may be handshake",
						raddr, sessionID, n)
				} else {
					if auditFlag != nil && *auditFlag && n == 152 {
						log.Printf("[DECRYPT] ⚠️ Packet #%d from %s: size=152 bytes, but session %d not found",
							packetCount, raddr, sessionID)
					} else if *audit {
						log.Printf("Packet from unknown session %d from %s (size: %d bytes)", sessionID, raddr, n)
					}
				}
				metr.Drops.Inc()
				continue
			}

			// ОПТИМИЗАЦИЯ: Объединяем чтение из сессии в один RLock
			session.Mu.RLock()
			recvWin := session.RecvWin
			aeadState := session.AEADState
			session.Mu.RUnlock()

			if recvWin == nil {
				metr.Drops.Inc()
				continue
			}
			if !recvWin.CheckAndMark(seq) {
				if auditFlag != nil && *auditFlag && n == 152 {
					log.Printf("[DECRYPT] ⚠️ Packet #%d from %s: size=152 bytes, but failed anti-replay check (seq=%d, session %d)",
						packetCount, raddr, seq, sessionID)
				}
				metr.Drops.Inc()
				continue
			}

			// Обновляем активность сессии
			sessionMgr.UpdateActivity(sessionID)

			// ОПТИМИЗАЦИЯ: Асинхронная расшифровка через пул воркеров
			if aeadState == nil {
				metr.Drops.Inc()
				if auditFlag != nil && *auditFlag && n == 152 {
					log.Printf("[DECRYPT] ⚠️ Packet #%d from %s: size=152 bytes, but aeadState is nil (session %d)",
						packetCount, raddr, sessionID)
				}
				continue
			}

			// КРИТИЧЕСКАЯ ОПТИМИЗАЦИЯ: Синхронная расшифровка для максимальной производительности
			// Убираем overhead копирования и асинхронной расшифровки
			ciphertext := buf[headerSize:n]
			plaintext, err := aeadState.Decrypt(seq, aad, ciphertext)
			if err != nil {
				metr.DecryptFailures.Inc()
				if auditFlag != nil && *auditFlag && n == 152 {
					log.Printf("[DECRYPT] ❌ Packet #%d from %s: size=152 bytes, decrypt failed: %v (session %d, seq=%d)",
						packetCount, raddr, err, sessionID, seq)
				}
				continue
			}

			// Логируем расшифрованные пакеты для диагностики
			// Логируем все пакеты для понимания что приходит
			if auditFlag != nil && *auditFlag {
				firstBytes := ""
				if len(plaintext) >= 16 {
					firstBytes = fmt.Sprintf("%02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x",
						plaintext[0], plaintext[1], plaintext[2], plaintext[3],
						plaintext[4], plaintext[5], plaintext[6], plaintext[7],
						plaintext[8], plaintext[9], plaintext[10], plaintext[11],
						plaintext[12], plaintext[13], plaintext[14], plaintext[15])
				} else {
					firstBytes = fmt.Sprintf("%x", plaintext)
				}
				isIP := len(plaintext) >= 1 && (plaintext[0]>>4 == 4 || plaintext[0]>>4 == 6)
				ipInfo := ""
				if isIP && len(plaintext) >= 20 {
					protocol := plaintext[9]
					dstIP := net.IP(plaintext[16:20]).String()
					ipInfo = fmt.Sprintf(" [IP: protocol=%d, dst=%s]", protocol, dstIP)
				}
				// Логируем первые 10 пакетов и каждый 100-й для мониторинга
				if packetCount <= 10 || packetCount%100 == 0 {
					log.Printf("[DECRYPT] 📦 Packet #%d from %s: encrypted=%d bytes, decrypted=%d bytes, first bytes: %s%s",
						packetCount, raddr, n, len(plaintext), firstBytes, ipInfo)
				}
			}

			// Проверяем, не является ли это control пакетом (control пакеты не обрабатываем ML)
			controlFlag := (version == proto.Version2 && flags&proto.FlagControlV2 != 0) || (version == proto.Version && flags&proto.FlagControl != 0)

			// Для V2 stream‑пакетов: декодируем Stream кадры [Cmd][Payload].
			// На данном шаге поддерживаем StreamData и STREAM_OPEN для регистрации потоков, остальные команды логируем/игнорируем.
			if version == proto.Version2 && (flags&proto.FlagStreamV2) != 0 && !controlFlag {
				if len(plaintext) < 1 {
					metr.Drops.Inc()
					continue
				}
				cmd := proto.StreamCommand(plaintext[0])
				switch cmd {
				case proto.StreamData:
					plaintext = plaintext[1:]
				case proto.StreamOpen:
					// STREAM_OPEN payload: [Proto:1][SrcIP:4][SrcPort:2][DstIP:4][DstPort:2]
					if len(plaintext) < 1+4+2+4+2 {
						metr.Drops.Inc()
						continue
					}
					protoByte := plaintext[1]
					srcIP := net.IP(plaintext[2:6])
					srcPort := binary.BigEndian.Uint16(plaintext[6:8])
					dstIP := net.IP(plaintext[8:12])
					dstPort := binary.BigEndian.Uint16(plaintext[12:14])

					// Регистрируем поток в SessionManager для последующего mux-а.
					sessionMgr.RegisterStream(sessionID, streamID, protoByte, srcIP, srcPort, dstIP, dstPort)
					if *audit {
						log.Printf("[STREAM] Server STREAM_OPEN: session=%d StreamID=%d, proto=%d %s:%d → %s:%d",
							sessionID, streamID, protoByte, srcIP.String(), srcPort, dstIP.String(), dstPort)
					}
					// При необходимости включаем byte-stream TCP режим (UseNetstackTCP) для этого потока.
					if protoByte == 6 && len(netstackTCPPorts) > 0 {
						if _, ok := netstackTCPPorts[dstPort]; ok {
							if *audit {
								log.Printf("[STREAM] UseNetstackTCP requested for session=%d StreamID=%d → %s, but TCP bridge is disabled in this build",
									sessionID, streamID, net.JoinHostPort(dstIP.String(), strconv.Itoa(int(dstPort))))
							}
						}
					}
					// STREAM_OPEN не несёт IP‑payload, дальше нечего обрабатывать.
					continue
				case proto.StreamOpenDomain:
					// STREAM_OPEN_DOMAIN payload: [Proto:1][SrcIP:4][SrcPort:2][DomainLen:1][Domain:N][DstPort:2]
					if len(plaintext) < 1+4+2+1 {
						metr.Drops.Inc()
						continue
					}
					protoByte := plaintext[1]
					srcIP := net.IP(plaintext[2:6])
					srcPort := binary.BigEndian.Uint16(plaintext[6:8])
					domainLen := int(plaintext[8])
					if len(plaintext) < 9+domainLen+2 {
						metr.Drops.Inc()
						continue
					}
					domain := string(plaintext[9 : 9+domainLen])
					dstPort := binary.BigEndian.Uint16(plaintext[9+domainLen : 11+domainLen])

					// Resolve domain
					ips, err := net.LookupIP(domain)
					if err != nil || len(ips) == 0 {
						if *audit {
							log.Printf("[STREAM] Failed to resolve domain %s: %v", domain, err)
						}
						continue
					}
					dstIP := ips[0]
					if ip4 := dstIP.To4(); ip4 != nil {
						dstIP = ip4
					}

					sessionMgr.RegisterStream(sessionID, streamID, protoByte, srcIP, srcPort, dstIP, dstPort)
					if *audit {
						log.Printf("[STREAM] Server STREAM_OPEN_DOMAIN: session=%d StreamID=%d, domain=%s -> %s:%d",
							sessionID, streamID, domain, dstIP.String(), dstPort)
					}

					// Check for UseNetstackTCP (same logic as StreamOpen)
					if protoByte == 6 && len(netstackTCPPorts) > 0 {
						if _, ok := netstackTCPPorts[dstPort]; ok {
							if *audit {
								log.Printf("[STREAM] UseNetstackTCP requested for session=%d StreamID=%d → %s:%d, but TCP bridge is disabled in this build",
									sessionID, streamID, dstIP.String(), dstPort)
							}
						}
					}
					continue
				case proto.StreamClose:
					// STREAM_CLOSE не несёт payload. Помечаем поток как закрытый и закрываем TargetConn (если есть).
					if sess := sessionMgr.GetSession(sessionID); sess != nil {
						sess.Mu.Lock()
						if entry, ok := sess.Streams[streamID]; ok {
							if entry.TargetConn != nil {
								_ = entry.TargetConn.Close()
								entry.TargetConn = nil
							}
							entry.UseNetstackTCP = false
							entry.Closed = true
						}
						sess.Mu.Unlock()
					}
					sessionMgr.CloseStream(sessionID, streamID)
					if *audit {
						log.Printf("[STREAM] Server STREAM_CLOSE: session=%d StreamID=%d", sessionID, streamID)
					}
					continue
				default:
					if *audit {
						log.Printf("[STREAM] Server RX unsupported stream cmd=%d (StreamID=%d, len=%d), dropping",
							cmd, streamID, len(plaintext))
					}
					metr.Drops.Inc()
					continue
				}
			}

			// Для V2 stream‑data пакетов проверяем, что StreamID зарегистрирован в SessionManager.
			// Это первый шаг к реальному mux-слою: неизвестные потоки дропаем.
			if version == proto.Version2 && (flags&proto.FlagStreamV2) != 0 && !controlFlag {
				streamEntry := sessionMgr.GetStream(sessionID, streamID)
				if streamEntry == nil && streamID == proto.TunStreamID {
					// Для агрегированного TUN-потока регистрируем StreamID на лету, используя реальные IP-метаданные.
					var (
						streamProto uint8 = proto.StreamProtoTunAggregate
						srcIP       net.IP
						dstIP       net.IP
						srcPort     uint16
						dstPort     uint16
					)

					if len(plaintext) >= 20 {
						ipVersion := (plaintext[0] >> 4) & 0x0F
						switch ipVersion {
						case 4:
							ihl := int(plaintext[0]&0x0F) * 4
							if ihl >= 20 && len(plaintext) >= ihl {
								streamProto = plaintext[9]
								srcIP = append(net.IP(nil), plaintext[12:16]...)
								dstIP = append(net.IP(nil), plaintext[16:20]...)

								if isMulticastOrBroadcast(dstIP) {
									// Multicast/broadcast оставляем агрегированным без конкретного tuple.
									streamProto = proto.StreamProtoTunAggregate
									srcIP = nil
									dstIP = nil
								} else {
									switch streamProto {
									case 6, 17: // TCP или UDP
										if len(plaintext) >= ihl+4 {
											header := plaintext[ihl:]
											srcPort = binary.BigEndian.Uint16(header[0:2])
											dstPort = binary.BigEndian.Uint16(header[2:4])
										}
									default:
										srcPort = 0
										dstPort = 0
									}
								}
							}
						case 6:
							if len(plaintext) >= 40 {
								nextHeader := plaintext[6]
								headerLen := 40
								streamProto = nextHeader
								srcIP = append(net.IP(nil), plaintext[8:24]...)
								dstIP = append(net.IP(nil), plaintext[24:40]...)

								if isMulticastOrBroadcast(dstIP) {
									streamProto = proto.StreamProtoTunAggregate
									srcIP = nil
									dstIP = nil
								} else {
									switch nextHeader {
									case 6, 17:
										if len(plaintext) >= headerLen+4 {
											header := plaintext[headerLen:]
											srcPort = binary.BigEndian.Uint16(header[0:2])
											dstPort = binary.BigEndian.Uint16(header[2:4])
										}
									default:
										srcPort = 0
										dstPort = 0
									}
								}
							}
						default:
							streamProto = proto.StreamProtoTunAggregate
						}
					}

					sessionMgr.RegisterStream(sessionID, streamID, streamProto, srcIP, srcPort, dstIP, dstPort)
					streamEntry = sessionMgr.GetStream(sessionID, streamID)
					if streamEntry != nil && auditFlag != nil && *auditFlag {
						log.Printf("[STREAM] Auto-registered default TUN stream: session=%d StreamID=%d proto=%d %s:%d → %s:%d",
							sessionID, streamID, streamProto, srcIP, srcPort, dstIP, dstPort)
					}
				}
				if streamEntry == nil {
					metr.Drops.Inc()
					if auditFlag != nil && *auditFlag {
						log.Printf("[STREAM] Dropping packet for unknown stream: session=%d StreamID=%d len=%d",
							sessionID, streamID, len(plaintext))
					}
					continue
				}
			}

			// ML обработка для INBOUND трафика (Client -> Server) - только для data пакетов
			// Теперь интегрирована в coreIM
			if !controlFlag && coreIM != nil && len(plaintext) > 0 {
				if processed, _, err := coreIM.ProcessTrafficWithML(plaintext, "inbound", "udp"); err == nil && len(processed) > 0 {
					plaintext = processed
				}
			}

			// If obfs padding flag set, deframe [2B len][data][pad]
			if (version == proto.Version2 && flags&proto.FlagObfsPadV2 != 0) || (version == proto.Version && flags&proto.FlagObfsPad != 0) {
				if len(plaintext) < 2 {
					metr.Drops.Inc()
					continue
				}
				realLen := int(plaintext[0])<<8 | int(plaintext[1])
				if realLen < 0 || realLen > len(plaintext)-2 {
					metr.Drops.Inc()
					continue
				}
				plaintext = plaintext[2 : 2+realLen]
			}
			// controlFlag уже определен выше при проверке ML обработки
			if controlFlag {
				if len(plaintext) == 0 {
					continue
				}
				switch plaintext[0] {
				case proto.CtrlKeepAlive:
					// no-op
					continue
				case proto.CtrlPing:
					// echo back as Pong
					if len(plaintext) == 1+8 {
						bufPong := make([]byte, 9)
						bufPong[0] = proto.CtrlPong
						copy(bufPong[1:], plaintext[1:])
						bufLen := len(bufPong) + 16
						if bufLen > 65535 {
							bufLen = 65535
						}
						// Создаем заголовок с правильным PayloadLen
						var aad2 []byte
						if version == proto.Version2 {
							pb := &proto.PacketBuilder{UseV2: true, StreamID: uint16(sessionID)}
							aad2 = pb.BuildHeader(session.SeqSend, uint16(bufLen), proto.FlagControlV2)
						} else {
							var h proto.PacketHeader
							h.Version = proto.Version
							h.Flags = proto.FlagControl
							h.SessionID = sessionID
							h.Seq = session.SeqSend
							h.PayloadLen = uint16(bufLen) //nolint:gosec // Bounds checked: bufLen <= 65535
							aad2 = h.MarshalBinary()
						}
						session.Mu.RLock()
						aeadState := session.AEADState
						clientAddr := session.ClientAddr
						session.Mu.RUnlock()
						if aeadState == nil || clientAddr == nil {
							continue
						}
						ct2, err := aeadState.Encrypt(session.SeqSend, aad2, bufPong)
						if err != nil {
							log.Printf("ping response encrypt error: %v", err)
							continue
						}
						pkt2 := util.Concat(aad2, ct2)
						_, _ = conn.WriteToUDP(pkt2, clientAddr)
						sessionMgr.IncrementSeqSend(sessionID)
					}
					continue
				case proto.CtrlRekey:
					session.Mu.RLock()
					seed := session.Seed
					session.Mu.RUnlock()
					if len(plaintext) == 1+32 && len(seed) > 0 {
						salt := plaintext[1:]
						if sendK, recvK, err := aeadpkg.DeriveRekey(seed, salt, false); err == nil {
							if st, err2 := aeadpkg.NewAEADState(sendK, recvK); err2 == nil {
								// Обновляем AEAD state в сессии
								sessionMgr.UpdateSessionAEAD(sessionID, st)

								// acknowledge by sending keepalive under new keys
								var hdr proto.PacketHeader
								hdr.Version = proto.Version
								hdr.Flags = proto.FlagControl
								hdr.SessionID = sessionID
								hdr.Seq = 1 // После rekey начинаем с 1
								hdr.PayloadLen = uint16(1 + 16)
								aad := hdr.MarshalBinary()
								ciphertext, err := st.Encrypt(hdr.Seq, aad, []byte{proto.CtrlKeepAlive})
								if err != nil {
									log.Printf("rekey ack encrypt error: %v", err)
									continue
								}
								session.Mu.RLock()
								clientAddr := session.ClientAddr
								session.Mu.RUnlock()
								if clientAddr == nil {
									continue
								}
								pktOut := util.Concat(aad, ciphertext)
								_, _ = conn.WriteToUDP(pktOut, clientAddr)
								sessionMgr.IncrementSeqSend(sessionID)
								metr.RekeyCount.Inc()
								metr.KeepaliveSent.Inc()
							}
						}
					}
					continue
				case proto.CtrlAuth:
					if len(plaintext) > 1 {
						tok := string(plaintext[1:])
						if len(allowedTokens) > 0 {
							if _, ok := allowedTokens[tok]; !ok {
								if *audit {
									log.Printf("auth failed for %s", raddr)
								}
								continue
							}
						}
						if *audit {
							log.Printf("auth ok: %s", tok)
						}
					}
					continue
				case proto.CtrlFrag:
					// payload: [CtrlFrag|FragID(4)|FragIdx(2)|FragCnt(2)|chunk]
					if len(plaintext) < 1+4+2+2 {
						metr.Drops.Inc()
						continue
					}
					fragID := binary.BigEndian.Uint32(plaintext[1:5])
					fragIdx := int(binary.BigEndian.Uint16(plaintext[5:7]))
					fragCnt := int(binary.BigEndian.Uint16(plaintext[7:9]))
					chunk := plaintext[9:]
					complete, full, expired := reasm.Insert(fragID, fragIdx, fragCnt, chunk, time.Now())
					metr.FragmentsRx.Inc()
					for range expired {
						metr.FragmentsExpired.Inc()
					}
					if !complete {
						continue
					}
					metr.FragmentsReasm.Inc()

					// ML обработка для собранного фрагмента (INBOUND - Client -> Server)
					// Теперь интегрирована в coreIM
					finalData := full
					if coreIM != nil && len(full) > 0 {
						if processed, _, err := coreIM.ProcessTrafficWithML(full, "inbound", "udp"); err == nil && len(processed) > 0 {
							finalData = processed
						}
					}

					// deliver reassembled payload
					if tun != nil {
						if _, err := tun.Write(finalData); err != nil {
							log.Printf("tun write: %v", err)
						}
					}
					continue
				}
			}
			// Обновляем адрес клиента в сессии если изменился
			session.Mu.Lock()
			if session.ClientAddr == nil || session.ClientAddr.String() != raddr.String() {
				session.ClientAddr = raddr
			}
			session.Mu.Unlock()

			// V2 stream‑маршрутизация: если это STREAM_DATA для известного StreamID,
			// по умолчанию считаем payload TUN‑IP‑трафиком. В режиме UseNetstackTCP
			// для выбранных потоков payload трактуется как чистые TCP‑байты и
			// пишется в TargetConn.
			if version == proto.Version2 && (flags&proto.FlagStreamV2) != 0 && !controlFlag {
				if entry := sessionMgr.GetStream(sessionID, streamID); entry != nil {
					// Режим byte-stream TCP: payload — это чистый TCP‑payload.
					if entry.UseNetstackTCP && entry.TargetConn != nil {
						if len(plaintext) > 0 {
							if _, err := entry.TargetConn.Write(plaintext); err != nil {
								if auditFlag != nil && *auditFlag {
									log.Printf("[STREAM] UseNetstackTCP: write error for session=%d StreamID=%d: %v",
										sessionID, streamID, err)
								}
							}
						}
						// В режиме UseNetstackTCP этот payload не трактуем как IP‑пакет.
						continue
					}

					// Ожидаем, что внутри STREAM_DATA лежит IP‑пакет, пришедший от tun2socks.
					if len(plaintext) > 0 {
						firstByte := plaintext[0]
						ipVersion := (firstByte >> 4) & 0x0F
						isIPPacket := ipVersion == 4 || ipVersion == 6
						if !isIPPacket {
							if auditFlag != nil && *auditFlag {
								log.Printf("[STREAM] ⚠️ Non-IP payload in stream: session=%d StreamID=%d proto=%d len=%d firstByte=0x%02x",
									sessionID, streamID, entry.Proto, len(plaintext), firstByte)
							}
							metr.Drops.Inc()
							continue
						}

						if ipVersion != 4 {
							if auditFlag != nil && *auditFlag {
								log.Printf("[STREAM] ⚠️ IPv%d packet unsupported: session=%d StreamID=%d len=%d",
									ipVersion, sessionID, streamID, len(plaintext))
							}
							metr.Drops.Inc()
							continue
						}

						if len(plaintext) < 20 {
							metr.Drops.Inc()
							continue
						}

						ihl := int(plaintext[0]&0x0F) * 4
						if ihl < 20 || len(plaintext) < ihl {
							metr.Drops.Inc()
							continue
						}

						protocol := plaintext[9]
						srcIP := net.IP(plaintext[12:16])
						dstIP := net.IP(plaintext[16:20])

						if isMulticastOrBroadcast(dstIP) {
							if auditFlag != nil && *auditFlag {
								log.Printf("[STREAM] ⚠️ Dropping multicast/broadcast packet: session=%d StreamID=%d dst=%s proto=%d",
									sessionID, streamID, dstIP.String(), protocol)
							}
							metr.Drops.Inc()
							continue
						}

						var srcPort, dstPort uint16
						if protocol == 6 || protocol == 17 {
							if len(plaintext) >= ihl+4 {
								header := plaintext[ihl:]
								srcPort = binary.BigEndian.Uint16(header[0:2])
								dstPort = binary.BigEndian.Uint16(header[2:4])
							}
						}

						session.Mu.Lock()
						if entry.Proto == 0 {
							entry.Proto = protocol
						}
						entry.SrcIP = append(entry.SrcIP[:0], srcIP...)
						entry.DstIP = append(entry.DstIP[:0], dstIP...)
						if entry.SrcPort == 0 {
							entry.SrcPort = srcPort
						}
						if entry.DstPort == 0 {
							entry.DstPort = dstPort
						}
						entry.LastActive = time.Now()
						entry.Closed = false
						session.Mu.Unlock()

						if auditFlag != nil && *auditFlag {
							log.Printf("[STREAM] IP packet for stream: session=%d StreamID=%d proto=%d %s:%d → %s:%d (ipProto=%d dstIP=%s)",
								sessionID, streamID, entry.Proto, srcIP, srcPort, dstIP, dstPort, protocol, dstIP.String())
						}

						// Маршрутизация IP‑пакета из stream‑потока напрямую в интернет.
						if auditFlag != nil && *auditFlag {
							log.Printf("[IP-ROUTE] 📤 Stream IP packet (%d bytes) from %s (session %d, StreamID=%d) → IP router forwarding disabled (protocol=%d, dst=%s, IP version=%d)",
								len(plaintext), raddr, sessionID, streamID, protocol, dstIP.String(), ipVersion)
						}
						continue
					}
				}
			}

			// Legacy‑путь: payload рассматривается как либо прокси‑пакет, либо сырой
			// IP‑пакет. Этот путь используется для V1 и V2 без stream‑слоя.
			// Проверяем, это прокси‑пакет или TUN‑пакет.
			// Формат прокси‑пакета: [proxyID:4][cmd:1][data:N]
			if handleUDPProxyPacket(plaintext, session, sessionID, conn, raddr) {
				continue
			}

			// Server doesn't use TUN - route traffic directly to internet
			// Check what type of packet we received (legacy path, без stream‑слоя).
			if len(plaintext) > 0 {
				firstByte := plaintext[0]
				ipVersion := (firstByte >> 4) & 0x0F
				isIPPacket := ipVersion == 4 || ipVersion == 6

				if isIPPacket {
					if auditFlag != nil && *auditFlag {
						protocol := byte(0)
						if len(plaintext) >= 10 {
							protocol = plaintext[9]
						}
						dstIP := "unknown"
						if ipVersion == 4 && len(plaintext) >= 20 {
							dstIP = net.IP(plaintext[16:20]).String()
						}
						log.Printf("[IP-ROUTE] 📤 Received legacy IP packet (%d bytes) from %s (session %d) → IP router forwarding disabled (protocol=%d, dst=%s, IP version=%d)",
							len(plaintext), raddr, sessionID, protocol, dstIP, ipVersion)
					}
					// Legacy‑IP: без StreamID.
					continue
				} else {
					// Not an IP packet - might be keepalive, control data, or malformed proxy packet
					// Логируем только первые несколько раз, чтобы не засорять логи
					if auditFlag != nil && *auditFlag && (packetCount <= 5 || packetCount%100 == 0) {
						log.Printf("[IP-ROUTE] ⚠️ Received non-IP data (%d bytes) from %s (session %d) - first byte: 0x%02x (IP version bits: %d)",
							len(plaintext), raddr, sessionID, firstByte, ipVersion)
					}
				}
			} else {
				// Empty packet - should not happen after decryption
				if auditFlag != nil && *auditFlag {
					log.Printf("[IP-ROUTE] ⚠️ Received empty plaintext from %s (session %d)", raddr, sessionID)
				}
			}
		}
	}()

	// Service tunnel receiver goroutine (receive data from service tunnel and send via UDP)
	if *useServiceTunnel && serviceTunnel != nil {
		go func() {
			for {
				select {
				case <-ctx.Done():
					return
				default:
					// Receive data from service tunnel
					extracted, err := serviceTunnel.ReceiveData(5 * time.Second)
					if err != nil {
						if err.Error() != "timeout waiting for data" {
							log.Printf("Service tunnel receive error: %v", err)
						}
						continue
					}
					// Маршрутизация данных из service tunnel к конкретному клиенту
					allSessions := sessionMgr.GetAllSessions()
					if len(allSessions) == 0 {
						continue
					}

					// Логика маршрутизации:
					// 1. Если есть только один активный клиент - отправляем ему
					// 2. Если несколько клиентов - отправляем первому активному
					// 3. В будущем можно добавить более сложную логику (round-robin, по destination IP и т.д.)

					var targetSession *srvpkg.SessionState
					if len(allSessions) == 1 {
						// Только один клиент - отправляем ему
						targetSession = allSessions[0]
					} else {
						// Несколько клиентов - выбираем первого активного
						// В production можно добавить более сложную логику выбора
						for i := range allSessions {
							session := allSessions[i]
							session.Mu.RLock()
							if session.ClientAddr != nil {
								targetSession = session
								session.Mu.RUnlock()
								break
							}
							session.Mu.RUnlock()
						}
					}

					if targetSession != nil {
						targetSession.Mu.RLock()
						clientAddr := targetSession.ClientAddr
						targetSession.Mu.RUnlock()

						if clientAddr != nil {
							if _, err := conn.WriteToUDP(extracted, clientAddr); err != nil {
								var nerr net.Error
								if errors.As(err, &nerr) {
									continue
								}
								log.Printf("Failed to forward tunneled data to %s: %v", clientAddr, err)
							} else {
								metr.PacketsTx.Inc()
								metr.BytesTx.Add(float64(len(extracted)))
							}
						}
					}
				}
			}
		}()
		log.Printf("Service tunnel receiver goroutine started")
	}

	// TUN -> UDP with advanced obfuscation (only when TUN is available)
	// Маршрутизация пакетов к правильному клиенту на основе destination IP
	if tun != nil {
		// Запускаем цикл чтения TUN в отдельной горутине, чтобы main мог продолжить выполнение
		go func() {
			defer func() {
				if r := recover(); r != nil {
					log.Printf("TUN reader goroutine panic recovered: %v", r)
				}
			}()
			pkt := make([]byte, maxUDPPacket)

			// Потоковая карта: 5‑tuple потока → StreamID (для V2 stream‑мультиплексирования).
			flowToStream := make(map[tunstack.FlowKey]uint16)
			// Используем concurrent multiplexer для параллельной обработки потоков
			// Настраиваем padding для Mux потоков (если указаны параметры)
			var paddingConfig *proto.MuxPaddingConfig
			if *padMin > 0 || *padMax > 0 {
				paddingConfig = &proto.MuxPaddingConfig{
					Enabled: true,
					MinSize: *padMin,
					MaxSize: *padMax,
				}
			}
			concurrentMux := proto.NewConcurrentStreamMultiplexerWithPadding(100, paddingConfig) // Максимум 100 одновременных потоков
			// Регистрируем mux в ServerRuntime для возможности менять padding в рантайме через API
			if serverRuntime != nil {
				serverRuntime.SetMux(concurrentMux)
			}
			for {
				n, err := tun.Read(pkt)
				if err != nil {
					// TUN интерфейс закрыт или ошибка - логируем и выходим из цикла
					// Не используем log.Fatalf, чтобы systemd не перезапускал сервер
					// Не используем return из main - просто выходим из горутины
					log.Printf("TUN read error: %v (TUN interface may be closed, exiting TUN reader goroutine)", err)
					return
				}

				// Парсим IP заголовок для определения destination IP
				if n < 20 { // Минимальный размер IP заголовка
					continue
				}

				// Получаем destination IP из IP заголовка (offset 16-19 для IPv4)
				var destIP net.IP
				if pkt[0]>>4 == 4 { // IPv4
					destIP = net.IP(pkt[16:20])
				} else if pkt[0]>>4 == 6 { // IPv6
					if n < 40 {
						continue
					}
					destIP = net.IP(pkt[24:40])
				} else {
					continue
				}

				// Пропускаем multicast и broadcast адреса (это нормальный сетевой трафик)
				if isMulticastOrBroadcast(destIP) {
					continue
				}

				// Извлекаем информацию о пакете для routing engine
				var srcIP net.IP
				if pkt[0]>>4 == 4 { // IPv4
					srcIP = net.IP(pkt[12:16])
				} else if pkt[0]>>4 == 6 { // IPv6
					srcIP = net.IP(pkt[8:24])
				}
				packetInfo := extractPacketInfo(pkt[:n], srcIP, destIP)

				// Применяем routing rules для определения outbound (подход как в Clash Verge Rev)
				var selectedSession *srvpkg.SessionState
				if routingEngine != nil && packetInfo != nil {
					outboundTag, balancerTag, shouldRoute := applyRoutingRules(packetInfo)
					if !shouldRoute {
						// Правило говорит не маршрутизировать этот пакет (явное блокирование)
						if *audit {
							log.Printf("[ROUTING] Packet blocked by routing rule: %s → %s", srcIP, destIP)
						}
						continue
					}

					// Если указан outbound tag, ищем сессию по этому тегу
					if outboundTag != "" {
						if *audit {
							log.Printf("[ROUTING] Packet matched rule with outbound tag: %s, balancer: %s", outboundTag, balancerTag)
						}

						// Получаем session ID для outbound tag через routing engine
						if sessionID, found := routingEngine.GetSessionIDForOutbound(outboundTag); found {
							if session := sessionMgr.GetSession(sessionID); session != nil {
								selectedSession = session
								if *audit {
									log.Printf("[ROUTING] Selected session %d for outbound tag: %s", sessionID, outboundTag)
								}
							}
						} else {
							// Outbound tag не зарегистрирован - fallback на default (как в Clash/Mihomo)
							if *audit {
								log.Printf("[ROUTING] Warning: outbound tag '%s' not registered, falling back to default routing", outboundTag)
							}
						}
					}
					// Если outboundTag пустой, это означает "default" - ищем зарегистрированный default outbound
				}

				// Находим сессию для этого destination IP (логика как в Clash Verge Rev и Prizrak-Box)
				// Соответствует подходу Mihomo/Clash Meta - всегда есть default outbound
				// 1. Сначала пробуем selectedSession из routing rules
				// 2. Затем пробуем найти по destination IP
				// 3. Затем пробуем зарегистрированный "default" outbound (как в Clash/Mihomo)
				// 4. Fallback на первую активную сессию (если default outbound не зарегистрирован)
				session := selectedSession
				if session == nil {
					session = sessionMgr.FindSessionByDestinationIP(destIP, nil)
				}
				// КРИТИЧЕСКОЕ ИСПРАВЛЕНИЕ: Сначала ищем зарегистрированный "default" outbound
				// В Clash/Mihomo/Prizrak-Box "default" outbound - это явно зарегистрированная сессия,
				// а не просто "первая активная". Это обеспечивает стабильность и предсказуемость.
				if session == nil && routingEngine != nil {
					if defaultSessionID, found := routingEngine.GetSessionIDForOutbound("default"); found {
						if defaultSession := sessionMgr.GetSession(defaultSessionID); defaultSession != nil {
							// Проверяем, что сессия активна
							defaultSession.Mu.RLock()
							isActive := defaultSession.AEADState != nil && defaultSession.ClientAddr != nil
							defaultSession.Mu.RUnlock()
							if isActive {
								session = defaultSession
								if *audit {
									log.Printf("[ROUTING] Using registered default outbound (session %d) for IP %s (like Clash/Mihomo/Prizrak-Box)", session.SessionID, destIP)
								}
							}
						}
					}
				}
				// Fallback: если default outbound не зарегистрирован или неактивен, используем первую активную сессию
				// Это гарантирует, что трафик всегда будет маршрутизирован, если есть хотя бы одна активная сессия
				if session == nil {
					session = sessionMgr.GetFirstActiveSession()
					if session != nil && *audit {
						log.Printf("[ROUTING] Using fallback default routing (first active session %d) for IP %s (default outbound not registered)", session.SessionID, destIP)
					}
				}
				if session == nil {
					// Действительно нет активных сессий - это критическая ошибка
					if *audit {
						log.Printf("[ROUTING] ERROR: No active sessions available, dropping packet to %s", destIP)
					}
					continue
				}

				// Берем локальные копии для безопасного использования
				session.Mu.RLock()
				clientAddr := session.ClientAddr
				aeadState := session.AEADState
				sessionID := session.SessionID
				seqSend := session.SeqSend
				session.Mu.RUnlock()

				if clientAddr == nil || aeadState == nil {
					continue
				}
				base := pkt[:n]

				// Optional core processing (safe-by-default gated)
				// КРИТИЧЕСКАЯ ОПТИМИЗАЦИЯ: Полностью убираем блокирующие задержки для максимальной производительности
				if coreIM != nil {
					if processed, _, err := coreIM.ProcessTraffic(base, "outbound"); err == nil && len(processed) > 0 {
						base = processed
						// Задержки из обфускации критически замедляют передачу - пропускаем их полностью
					}
				}

				// ML обработка теперь интегрирована в coreIM.ProcessTraffic
				// Дополнительная обработка не требуется, так как уже выполнена в coreIM
				// Статистика доступна через coreIM.GetMLSystem().GetStats()
				if coreIM != nil && coreIM.GetMLSystem() != nil {
					stats := coreIM.GetMLSystem().GetStats()
					if stats != nil && stats.ProcessedPackets > 0 && stats.ProcessedPackets%100 == 0 {
						log.Printf("[ML] Server Stats: Packets=%d, Accuracy=%.2f%%, EvasionRate=%.2f%%",
							stats.ProcessedPackets, stats.Accuracy, stats.DPIEvasionRate)
					}
				}

				// Если используем V2 stream‑мультиплексирование, оборачиваем IP‑пакет
				// в StreamData кадр: [Cmd=StreamData][IP‑payload].
				if *useV2 {
					base = proto.EncodeStreamControlFrame(proto.StreamData, base)
				}

				// Дополнительная обработка через интегрированную систему обхода DPI
				// if integratedEvasion != nil {
				//	processed, delay, err := integratedEvasion.ProcessPacket(base, "outbound")
				//	if err != nil {
				//		log.Printf("Интегрированная система обхода DPI error: %v", err)
				//	} else {
				//		base = processed
				//		// Применяем задержку для реалистичного поведения
				//		if delay > 0 {
				//			// Production timing - use real network timing instead of sleep
				//			timer := time.NewTimer(delay)
				//			<-timer.C
				//		}
				//	}
				// }

				// Optional padding frame: [2B len][data][pad]
				payload := base
				appliedPad := 0
				if *padMax > 0 && *padMax >= *padMin {
					pad := 0
					if *padMax > *padMin {
						var b [1]byte
						if _, err := rand.Read(b[:]); err == nil {
							pad = *padMin + int(b[0])%(*padMax-*padMin+1)
						} else {
							pad = *padMin
						}
					} else {
						pad = *padMin
					}
					framed := make([]byte, 2+len(base)+pad)
					framed[0] = byte(len(base) >> 8)
					framed[1] = byte(len(base))
					copy(framed[2:], base)
					payload = framed
					appliedPad = pad
				}

				// На уровне V2‑протокола сервер также выделяет StreamID по 5‑tuple потока,
				// чтобы симметрично клиенту маркировать потоки для будущего mux‑слоя.
				streamID := proto.TunStreamID
				if *useV2 {
					if fkPtr, ok := tunstack.BuildFlowKey(base); ok && fkPtr != nil {
						fk := *fkPtr
						if id, exists := flowToStream[fk]; exists {
							streamID = id
						} else {
							// Используем concurrent multiplexer для выделения StreamID
							id, err := concurrentMux.AllocateStream()
							if err != nil {
								log.Printf("[STREAM] Failed to allocate stream ID: %v", err)
								streamID = proto.TunStreamID // Fallback к дефолтному потоку
							} else {
							flowToStream[fk] = id
							streamID = id
							}
							// Регистрируем процессор потока с нормальным приоритетом для параллельной обработки
							concurrentMux.RegisterStreamProcessor(id, proto.PriorityNormal, 100)
							if *audit {
								log.Printf("[STREAM] New server-side stream with concurrency: StreamID=%d, Flow=%s", streamID, fk.String())
							}
						}
					}
				}

				// Decide if fragmentation is needed based on mtu
				// Используем maxUDPPacket (динамически обновляется через runtime reload)
				maxLen := maxUDPPacket
				// Fast path: try single packet
				{
					cipherLen := len(payload) + 16
					// Оцениваем размер заголовка для V1/V2
					headerSize := int(proto.HeaderLen)
					if *useV2 {
						pb := &proto.PacketBuilder{UseV2: true, StreamID: streamID}
						headerSize = pb.GetHeaderSize(uint16(cipherLen))
					}
					totalLen := headerSize + cipherLen
					if cipherLen <= 0xFFFF && totalLen <= maxLen {
						if cipherLen > 65535 {
							cipherLen = 65535
						}
						var aad []byte
						if *useV2 {
							// Для V2 используем компактный заголовок с StreamID для TUN-потока.
							flags := byte(0)
							if appliedPad > 0 {
								flags |= proto.FlagObfsPadV2
							}
							// Маркируем как stream-пакет (TunStreamID).
							flags |= proto.FlagStreamV2
							pb := &proto.PacketBuilder{
								UseV2:    true,
								StreamID: streamID,
							}
							aad = pb.BuildHeader(seqSend, uint16(cipherLen), flags)
						} else {
							var hdr proto.PacketHeader
							hdr.Version = proto.Version
							hdr.Flags = 0
							if appliedPad > 0 {
								hdr.Flags |= proto.FlagObfsPad
							}
							hdr.SessionID = sessionID
							hdr.Seq = seqSend
							hdr.PayloadLen = uint16(cipherLen) //nolint:gosec // Bounds checked: cipherLen <= 65535
							aad = hdr.MarshalBinary()
						}
						ct, err := aeadState.Encrypt(seqSend, aad, payload)
						if err != nil {
							log.Printf("encrypt: %v", err)
							continue
						}
						pktOut := util.Concat(aad, ct)

						// Отправка через туннель сервиса или напрямую через UDP
						if *useServiceTunnel && serviceTunnel != nil {
							// Отправка через туннель сервиса (HTTPS к реальному сервису)
							if err := serviceTunnel.SendData(pktOut); err != nil {
								log.Printf("Service tunnel send error: %v, falling back to direct UDP", err)
								// Fallback на прямой UDP
								if _, err := conn.WriteToUDP(pktOut, clientAddr); err != nil {
									var nerr net.Error
									if errors.As(err, &nerr) {
										continue
									}
								}
							} else {
								// Успешная отправка через туннель
								metr.PacketsTx.Inc()
								metr.BytesTx.Add(float64(len(pktOut)))
								sessionMgr.IncrementSeqSend(sessionID)
								continue
							}
						} else {
							// Прямая отправка через UDP
							written, err := conn.WriteToUDP(pktOut, clientAddr)
							if err != nil {
								var nerr net.Error
								if errors.As(err, &nerr) {
									if *audit {
										log.Printf("UDP send error (network): %v (tried to send %d bytes to %s)", err, len(pktOut), clientAddr)
									}
									continue
								}
								log.Printf("UDP send error: %v (tried to send %d bytes to %s, written: %d)", err, len(pktOut), clientAddr, written)
								continue
							}
							if *audit {
								log.Printf("TUN->UDP: Sent %d bytes to client %s (session %d)", written, clientAddr, sessionID)
							}
						}
						metr.PacketsTx.Inc()
						metr.BytesTx.Add(float64(len(pktOut)))
						sessionMgr.IncrementSeqSend(sessionID)

						// Проверяем rekey по байтам/пакетам для этой сессии
						session.Mu.RLock()
						seed := session.Seed
						session.Mu.RUnlock()

						// Обновляем счетчики
						session.Mu.Lock()
						session.SentBytes += int64(len(pktOut))
						session.SentPkts++
						newSentBytes := session.SentBytes
						newSentPkts := session.SentPkts
						session.Mu.Unlock()

						if (*rkSrvBytes > 0 && newSentBytes >= *rkSrvBytes) || (*rkSrvPkts > 0 && newSentPkts >= *rkSrvPkts) {
							salt := make([]byte, 32)
							if _, err := rand.Read(salt); err == nil && len(seed) > 0 {
								// Получаем текущий seqSend
								currentSeq := sessionMgr.GetSeqSend(sessionID)
								var hdr2 proto.PacketHeader
								hdr2.Version = proto.Version
								hdr2.Flags = proto.FlagControl
								hdr2.SessionID = sessionID
								hdr2.Seq = currentSeq
								hdr2.PayloadLen = uint16(1 + 32 + 16)
								aad2 := hdr2.MarshalBinary()
								pl2 := util.Concat([]byte{proto.CtrlRekey}, salt)

								// Берем актуальный aeadState
								session.Mu.RLock()
								currentAeadState := session.AEADState
								session.Mu.RUnlock()

								if ct2, err := currentAeadState.Encrypt(hdr2.Seq, aad2, pl2); err == nil {
									pkt2 := util.Concat(aad2, ct2)
									sent := false
									if *useServiceTunnel && serviceTunnel != nil {
										if err := serviceTunnel.SendData(pkt2); err == nil {
											sent = true
										}
									}
									if !sent {
										if _, err := conn.WriteToUDP(pkt2, clientAddr); err == nil {
											sent = true
										}
									}
									if sent {
										if sendK, recvK, err := aeadpkg.DeriveRekey(seed, salt, false); err == nil {
											if st, err2 := aeadpkg.NewAEADState(sendK, recvK); err2 == nil {
												sessionMgr.UpdateSessionAEAD(sessionID, st)
											}
										}
										metr.RekeyCount.Inc()
										if *rkSrvBytes > 0 && newSentBytes >= *rkSrvBytes {
											metr.RekeyTriggerBytes.Inc()
										}
										if *rkSrvPkts > 0 && newSentPkts >= *rkSrvPkts {
											metr.RekeyTriggerPackets.Inc()
										}
										// Сбрасываем счетчики
										session.Mu.Lock()
										session.SentBytes = 0
										session.SentPkts = 0
										session.Mu.Unlock()
									}
									sessionMgr.IncrementSeqSend(sessionID)
								}
							}
						}
						if appliedPad > 0 {
							metr.PaddingBytesAdded.Add(float64(appliedPad))
						}
						continue
					}
				}
				// Fragmentation path: send control fragments without obfs padding
				// Compute max chunk per fragment
				overhead := int(proto.HeaderLen) + 16 + 1 + 4 + 2 + 2 // header + tag + ctrl byte + frag header
				maxChunk := maxLen - overhead
				if maxChunk <= 0 {
					log.Printf("mtu too small: %d", maxLen)
					continue
				}
				// Use a random fragID
				var idb [4]byte
				if _, err := rand.Read(idb[:]); err != nil {
					log.Printf("rand: %v", err)
					continue
				}
				fragID := binary.BigEndian.Uint32(idb[:])
				// IMPORTANT: fragment the base payload (no obfs pad), receiver reassembles base
				total := len(base)
				cnt := (total + maxChunk - 1) / maxChunk
				totalCipher := 0

				// Получаем актуальные значения из сессии для каждого фрагмента
				currentSeq := seqSend
				for i := 0; i < cnt; i++ {
					start := i * maxChunk
					end := start + maxChunk
					if end > total {
						end = total
					}
					chunk := base[start:end]
					// Build control fragment payload
					pl := make([]byte, 1+4+2+2+len(chunk))
					pl[0] = proto.CtrlFrag
					binary.BigEndian.PutUint32(pl[1:5], fragID)
					if i > 65535 {
						i = 65535
					}
					if cnt > 65535 {
						cnt = 65535
					}
					binary.BigEndian.PutUint16(pl[5:7], uint16(i))   //nolint:gosec // Bounds checked: i <= 65535
					binary.BigEndian.PutUint16(pl[7:9], uint16(cnt)) //nolint:gosec // Bounds checked: cnt <= 65535
					copy(pl[9:], chunk)

					// Получаем актуальный aeadState для этого фрагмента
					session.Mu.RLock()
					fragAeadState := session.AEADState
					fragClientAddr := session.ClientAddr
					session.Mu.RUnlock()

					if fragAeadState == nil || fragClientAddr == nil {
						log.Printf("Session state lost during fragmentation")
						break
					}

					var hdr proto.PacketHeader
					hdr.Version = proto.Version
					hdr.Flags = proto.FlagControl | proto.FlagFragment
					hdr.SessionID = sessionID
					hdr.Seq = currentSeq
					cipherLen := len(pl) + 16
					if cipherLen > 0xFFFF {
						log.Printf("fragment too large")
						break
					}
					hdr.PayloadLen = uint16(cipherLen) //nolint:gosec // Bounds checked: cipherLen <= 0xFFFF
					aad := hdr.MarshalBinary()
					ct, err := fragAeadState.Encrypt(hdr.Seq, aad, pl)
					if err != nil {
						log.Printf("encrypt: %v", err)
						break
					}
					pktOut := util.Concat(aad, ct)
					// Отправка через туннель или напрямую (фрагменты)
					if *useServiceTunnel && serviceTunnel != nil {
						if err := serviceTunnel.SendData(pktOut); err != nil {
							// Fallback на прямой UDP
							if _, err := conn.WriteToUDP(pktOut, fragClientAddr); err != nil {
								var nerr net.Error
								if errors.As(err, &nerr) {
									continue
								}
							}
						}
					} else {
						if _, err := conn.WriteToUDP(pktOut, fragClientAddr); err != nil {
							var nerr net.Error
							if errors.As(err, &nerr) {
								continue
							}
						}
					}
					metr.PacketsTx.Inc()
					metr.BytesTx.Add(float64(len(pktOut)))
					metr.FragmentsTx.Inc()
					totalCipher += len(pktOut)
					currentSeq++
					sessionMgr.IncrementSeqSend(sessionID)
				}

				// Обновляем счетчики rekey для этой сессии
				session.Mu.Lock()
				session.SentBytes += int64(totalCipher)
				session.SentPkts += int64(cnt)
				newSentBytes := session.SentBytes
				newSentPkts := session.SentPkts
				fragSeed := session.Seed
				session.Mu.Unlock()

				if (*rkSrvBytes > 0 && newSentBytes >= *rkSrvBytes) || (*rkSrvPkts > 0 && newSentPkts >= *rkSrvPkts) {
					salt := make([]byte, 32)
					if _, err := rand.Read(salt); err == nil && len(fragSeed) > 0 {
						currentSeq2 := sessionMgr.GetSeqSend(sessionID)
						var hdr2 proto.PacketHeader
						hdr2.Version = proto.Version
						hdr2.Flags = proto.FlagControl
						hdr2.SessionID = sessionID
						hdr2.Seq = currentSeq2
						hdr2.PayloadLen = uint16(1 + 32 + 16)
						aad2 := hdr2.MarshalBinary()
						pl2 := util.Concat([]byte{proto.CtrlRekey}, salt)

						session.Mu.RLock()
						fragAeadState2 := session.AEADState
						fragClientAddr2 := session.ClientAddr
						session.Mu.RUnlock()

						if ct2, err := fragAeadState2.Encrypt(hdr2.Seq, aad2, pl2); err == nil {
							pkt2 := util.Concat(aad2, ct2)
							sent := false
							if *useServiceTunnel && serviceTunnel != nil {
								if err := serviceTunnel.SendData(pkt2); err == nil {
									sent = true
								}
							}
							if !sent {
								if _, err := conn.WriteToUDP(pkt2, fragClientAddr2); err == nil {
									sent = true
								}
							}
							if sent {
								if sendK, recvK, err := aeadpkg.DeriveRekey(fragSeed, salt, false); err == nil {
									if st, err2 := aeadpkg.NewAEADState(sendK, recvK); err2 == nil {
										sessionMgr.UpdateSessionAEAD(sessionID, st)
									}
								}
								metr.RekeyCount.Inc()
								if *rkSrvBytes > 0 && newSentBytes >= *rkSrvBytes {
									metr.RekeyTriggerBytes.Inc()
								}
								if *rkSrvPkts > 0 && newSentPkts >= *rkSrvPkts {
									metr.RekeyTriggerPackets.Inc()
								}
								// Сбрасываем счетчики
								session.Mu.Lock()
								session.SentBytes = 0
								session.SentPkts = 0
								session.Mu.Unlock()
							}
							sessionMgr.IncrementSeqSend(sessionID)
						}
					}
				}
			}
		}() // Закрываем горутину чтения TUN
		log.Printf("TUN reader goroutine started")
	}
	// Graceful shutdown setup
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM, syscall.SIGHUP)

	// keep process alive in proxy mode (no TUN loops running)
	if tun == nil {
		// Ждем сигнала завершения в proxy mode
		sig := <-sigChan
		log.Printf("Received shutdown signal: %v, exiting...", sig)

		// Graceful shutdown API сервера перед выходом
		apiServerMu.Lock()
		as := apiServer
		apiServerMu.Unlock()
		if as != nil {
			shutdownCtx, _ := context.WithTimeout(context.Background(), 2*time.Second)
			_ = as.Stop(shutdownCtx)
		}
		return
	}

	// В обычном режиме ждем сигнала для graceful shutdown
	log.Println("Server running. Press Ctrl+C to stop.")
	sig := <-sigChan
	log.Printf("Received shutdown signal: %v (type: %T, value: %d), shutting down gracefully...", sig, sig, sig)
	log.Printf("Signal source: PID=%d, UID=%d, GID=%d", os.Getpid(), os.Getuid(), os.Getgid())

	// Log stack trace to see what goroutine received the signal
	buf := make([]byte, 4096)
	n := runtime.Stack(buf, false)
	log.Printf("Goroutine stack at signal reception:\n%s", buf[:n])

	// Отменяем контекст для всех горутин
	cancel()

	// Даем время на завершение (5 секунд)
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer shutdownCancel()

	// Graceful shutdown API сервера
	apiServerMu.Lock()
	as := apiServer
	apiServerMu.Unlock()
	if as != nil {
		if err := as.Stop(shutdownCtx); err != nil {
			log.Printf("Error stopping API server: %v", err)
		}
	}

	// Закрываем соединения
	if conn != nil {
		if err := conn.Close(); err != nil {
			// Игнорируем ошибки закрытия уже закрытого соединения
			errStr := err.Error()
			if !strings.Contains(errStr, "use of closed network connection") &&
				!strings.Contains(errStr, "closed network connection") {
				log.Printf("Error closing UDP connection: %v", err)
			}
		}
	}
	if tun != nil {
		if err := tun.Close(); err != nil {
			// Игнорируем ошибки закрытия уже закрытого интерфейса
			errStr := err.Error()
			if !strings.Contains(errStr, "use of closed network connection") &&
				!strings.Contains(errStr, "closed network connection") {
				log.Printf("Error closing TUN interface: %v", err)
			}
		}
	}

	// Ждем завершения или timeout
	<-shutdownCtx.Done()
	log.Println("Server shut down complete")

	// Вызываем cancel() для очистки
	cancel()
}

// configureTUNInterface автоматически настраивает TUN интерфейс (поднимает и назначает IP)
func configureTUNInterface(tunName string) error {
	// Поднять TUN интерфейс
	cmd := exec.Command("ip", "link", "set", tunName, "up")
	if err := cmd.Run(); err != nil {
		return err
	}

	// Назначить IP адрес (10.0.0.1/24 для сервера)
	cmd = exec.Command("ip", "addr", "add", "10.0.0.1/24", "dev", tunName)
	if err := cmd.Run(); err != nil {
		// Если адрес уже назначен, это не ошибка (игнорируем)
		// Команда может вернуть ошибку, но это нормально если адрес уже есть
		_ = err
	}

	// Установить MTU для оптимальной производительности
	cmd = exec.Command("ip", "link", "set", tunName, "mtu", "1420")
	_ = cmd.Run() // Игнорируем ошибку MTU

	return nil
}

// hasAnyCert returns true if at least one certificate source is configured
func hasAnyCert(c *tlspkg.TLSServerConfig) bool {
	if c == nil {
		return false
	}
	if len(c.Certificates) > 0 {
		return true
	}
	if len(c.ExtraCerts) > 0 {
		return true
	}
	return c.GetACMECert != nil
}
