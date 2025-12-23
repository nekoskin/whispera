package main

import (
	"flag"
	"log"
	"os"
	"strconv"
	"time"
)

// getEnvOrDefault возвращает значение переменной окружения или значение по умолчанию
func getEnvOrDefault(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

// getEnvBool возвращает значение переменной окружения как bool или значение по умолчанию
func getEnvBool(key string, defaultValue bool) bool {
	if value := os.Getenv(key); value != "" {
		if b, err := strconv.ParseBool(value); err == nil {
			return b
		}
	}
	return defaultValue
}

var (
	server                 *string
	serverTCP              *string
	serverWS               *string
	serverWS2              *string
	tunName                *string
	tunIP                  *string
	tunGateway             *string
	tunPrefix              *int
	pskHex                 *string
	dualMode               *bool
	serverPubHex           *string
	stunSrv                *string
	proxyMode              *bool
	kaSec                  *int
	splitTunnel            *bool
	splitTunnelRules       *string
	splitTunnelMode        *string
	autoProfile            *bool
	enableMonitoring       *bool
	enableTesting          *bool
	appProfile             *string
	rkMin                  *int
	padMin                 *int
	padMax                 *int
	chaffSec               *int
	mtu                    *int
	chaffDist              *string
	chaffAlpha             *float64
	chaffXm                *float64
	chaffSizeMin           *int
	chaffSizeMax           *int
	obfsPreset             *string
	hsTO                   *int
	udpRetries             *int
	udpOnly                *bool
	metricsAddr            *string
	configPath             *string
	pprofAddr              *string
	obfsStrict             *bool
	shapeMeanMs            *int
	shapeTarget            *int
	rkBytes                *int64
	rkPkts                 *int64
	watchdog               *int
	autoSwitch             *bool
	udpUpgradeSec          *int
	useTLS                 *bool
	tlsMode                *string
	tlsSkipVerify          *bool
	speedtestEnabled       *bool
	speedtestServer        *string
	speedtestInterval      *time.Duration
	p2pEnabled             *bool
	p2pBootstrapCSV        *string
	p2pListen              *string
	p2pSendID              *string
	p2pSendMsg             *string
	tunstackLocalEgress    *bool
	tunstackMaxUDPSessions *int
	netstackEnable         *bool
	netstackDebug          *bool
	netstackTCPOnly        *bool
	configURI              *string
	coreEnable             *bool
	useV2                  *bool
	verbosePackets         *bool
)

func initFlags() {
	server = flag.String("server", getEnvOrDefault("WHISPERA_SERVER", "127.0.0.1:51820"), "server UDP address")
	serverTCP = flag.String("server-tcp", "", "optional TCP server address for fallback")
	serverWS = flag.String("server-ws", "", "optional WebSocket URL (wss:// for HTTPS, ws:// will be auto-upgraded to wss://) for fallback")
	serverWS2 = flag.String("server-ws2", "", "optional HTTP/2 WebSocket URL (wss://) for TLS mimicry")
	tunName = flag.String("tun", "", "TUN interface name (optional)")
	tunIP = flag.String("tun-ip", "198.18.0.1", "TUN interface IP address (default: 198.18.0.1, RFC 2544 test range)")
	tunGateway = flag.String("tun-gateway", "198.18.0.2", "TUN virtual gateway IP for routing (default: 198.18.0.2)")
	tunPrefix = flag.Int("tun-prefix", 30, "TUN interface prefix length (default: 30 for /30 subnet)")
	pskHex = flag.String("psk", "", "hex-encoded 32-byte PSK (used if no -server-pub)")
	dualMode = flag.Bool("dual-mode", false, "use both UDP and TCP simultaneously for redundancy")
	serverPubHex = flag.String("server-pub", "", "server static X25519 public key (hex32) for Noise IK")
	stunSrv = flag.String("stun", "", "optional STUN server host:port for NAT discovery")
	proxyMode = flag.Bool("proxy-mode", false, "run as SOCKS5 proxy instead of TUN interface (default: false, TUN mode)")
	kaSec = flag.Int("keepalive", 20, "keepalive interval seconds (Noise mode)")

	// Split tunneling flags
	splitTunnel = flag.Bool("split-tunnel", false, "enable split tunneling")
	splitTunnelRules = flag.String("split-rules", "", "split tunneling rules file (JSON format)")
	splitTunnelMode = flag.String("split-mode", "exclude", "split tunnel mode: exclude (default) or include")

	// Log split tunneling configuration
	if *splitTunnel {
		log.Printf("Split tunneling enabled: mode=%s, rules=%s", *splitTunnelMode, *splitTunnelRules)
	}

	// Автоматический выбор профилей
	autoProfile = flag.Bool("auto-profile", false, "автоматический выбор оптимального профиля")
	enableMonitoring = flag.Bool("monitoring", false, "включить мониторинг эффективности")
	enableTesting = flag.Bool("testing", false, "включить тестирование против блокировок")
	appProfile = flag.String("app-profile", "", "профиль приложения для мимикрии: vk|messenger_max|yandex|mailru|rutube|ozon")
	rkMin = flag.Int("rekey", 5, "rekey interval minutes (Noise mode)")
	padMin = flag.Int("pad-min", 0, "minimum random padding bytes")
	padMax = flag.Int("pad-max", 0, "maximum random padding bytes")
	chaffSec = flag.Int("chaff", 0, "send keepalive chaff (mean seconds; 0=off)")
	mtu = flag.Int("mtu", 1200, "maximum UDP packet size (bytes) including headers and AEAD")
	chaffDist = flag.String("chaff-dist", "const", "chaff distribution: const|exp|pareto")
	chaffAlpha = flag.Float64("chaff-alpha", 1.5, "pareto shape alpha (when chaff-dist=pareto)")
	chaffXm = flag.Float64("chaff-xm", 1.0, "pareto scale xm seconds (when chaff-dist=pareto)")
	chaffSizeMin = flag.Int("chaff-size-min", 256, "min target total packet size for chaff (bytes)")
	chaffSizeMax = flag.Int("chaff-size-max", 1200, "max target total packet size for chaff (bytes)")
	obfsPreset = flag.String("obfs-preset", "", "obfuscation preset: quic")
	hsTO = flag.Int("handshake-timeout", 60, "UDP handshake timeout seconds before TCP fallback (increased for better reliability)")
	udpRetries = flag.Int("udp-retries", 3, "number of UDP handshake retry attempts")
	udpOnly = flag.Bool("udp-only", false, "use only UDP, disable TCP/WebSocket fallback")
	metricsAddr = flag.String("metrics", "", "optional Prometheus metrics listen address (e.g. :9102)")
	configPath = flag.String("config", "", "optional YAML/JSON config file to load defaults")
	pprofAddr = flag.String("pprof", "", "optional pprof listen address (e.g. :6061)")
	// Strict obfuscation (timing/length shaping)
	obfsStrict = flag.Bool("obfs-strict", false, "enable strict obfuscation (timing/length shaping)")
	shapeMeanMs = flag.Int("shape-mean-ms", 15, "mean pacing interval (ms) for strict obfuscation")
	shapeTarget = flag.Int("shape-target", 900, "target ciphertext total length (bytes) for strict obfuscation")
	// Reliability/Security thresholds
	rkBytes = flag.Int64("rekey-bytes", 0, "trigger rekey after sending this many plaintext bytes (0=off)")
	rkPkts = flag.Int64("rekey-pkts", 0, "trigger rekey after sending this many packets (0=off)")
	watchdog = flag.Int("watchdog", 0, "watchdog seconds without inbound packets to trigger rekey (0=off)")
	autoSwitch = flag.Bool("auto-switch", true, "automatically switch to TCP on UDP failure and upgrade back to UDP")
	udpUpgradeSec = flag.Int("udp-upgrade-sec", 10, "when on TCP, probe and upgrade back to UDP every N seconds")

	// TLS/DTLS flags
	useTLS = flag.Bool("tls", os.Getenv("WHISPERA_USE_TLS") == "1", "enable TLS/DTLS modes (in addition to Noise/UDP)")
	tlsMode = flag.String("tls-mode", getEnvOrDefault("WHISPERA_TLS_MODE", "auto"), "TLS mode: auto|tls|dtls")
	tlsSkipVerify = flag.Bool("tls-skip-verify", false, "skip TLS certificate verification (INSECURE)")

	// Speedtest flags
	speedtestEnabled = flag.Bool("speedtest", false, "enable speedtest functionality")
	speedtestServer = flag.String("speedtest-server", getEnvOrDefault("WHISPERA_SPEEDTEST_SERVER", "http://localhost:8080"), "speedtest server URL")
	speedtestInterval = flag.Duration("speedtest-interval", 5*time.Minute, "speedtest interval")

	// P2P flags
	p2pEnabled = flag.Bool("p2p", false, "enable decentralized P2P sidecar")
	p2pBootstrapCSV = flag.String("p2p-bootstrap", "", "comma-separated bootstrap peers host:port for P2P discovery (udp)")
	p2pListen = flag.String("p2p-listen", ":0", "P2P discovery UDP listen address (e.g. :51821, :0=auto)")
	p2pSendID = flag.String("p2p-send", "", "send a P2P message to specified nodeID and exit if not tunneling")
	p2pSendMsg = flag.String("p2p-msg", "hello", "message payload for -p2p-send")

	// Experimental: локальный tun2socks через tunstack.DialFunc (как в Prizrak-Box).
	tunstackLocalEgress = flag.Bool("tunstack-local-egress", false, "enable experimental local tun2socks via tunstack.DialFunc (egress on client)")
	tunstackMaxUDPSessions = flag.Int("tunstack-max-udp-sessions", 0, "maximum number of UDP sessions in local tun2socks stack (0 = unlimited)")

	// Experimental: userspace TCP/IP стек gVisor netstack поверх TUN.
	netstackEnable = flag.Bool("netstack-enable", false, "enable experimental gVisor netstack on client (future STREAM/TCP dataplane)")
	netstackDebug = flag.Bool("netstack-debug", false, "enable verbose logging for gVisor netstack on client")
	netstackTCPOnly = flag.Bool("netstack-tcp-only", false, "when using gVisor netstack, divert only TCP flows into netstack/STREAM and keep UDP/ICMP as raw IP tunnel")

	configURI = flag.String("config-uri", "", "whispera:// URI to configure client in one flag")
	// Feature flag: Core obfuscation in datapath (default off)
	coreEnable = flag.Bool("core-enable", os.Getenv("WHISPERA_CORE_ENABLE") == "1", "enable core obfuscation processing in datapath (default off)")
	// V2 Protocol: улучшенный протокол с меньшим overhead и мультиплексированием
	useV2 = flag.Bool("use-v2", getEnvBool("WHISPERA_USE_V2", true), "use V2 protocol (compact header, batch encryption, multiplexing)")
	// Детальное логирование пакетов
	verbosePackets = flag.Bool("verbose-packets", false, "log all packets passing through tunnel (TX/RX with sizes)")

	flag.Parse()
}
