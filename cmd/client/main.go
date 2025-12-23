package main


import (
	"context"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"runtime"
	"runtime/debug"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	aeadpkg "whispera/internal/crypto"
	clientconnect "whispera/internal/client/connect"
	"whispera/internal/client/routing"
	"whispera/internal/client/session"
	netstackpkg "whispera/internal/netstack"
	"whispera/internal/obfuscation"
	"whispera/internal/proto"
	securitypkg "whispera/internal/security"
	tunpkg "whispera/internal/tun"
	"whispera/internal/tunstack"
)

// Global flag variables (from config/init.go)
var (
	// Server connection flags - XHTTP only
	serverTCP = flag.String("server", "", "XHTTP server address (e.g. example.com:443)")
	
	// Domain fronting flags (not used with XHTTP, but kept for compatibility)
	frontDomain  = flag.String("front-domain", "", "domain for DNS and TLS SNI (domain fronting) - not used with XHTTP")
	backendDomain = flag.String("backend-domain", "", "domain for Host/authority header (domain fronting) - not used with XHTTP")

	// TUN/TAP interface flags
	tunName     = flag.String("tun", "", "TUN interface name (optional)")
	useTAP      = flag.Bool("use-tap", false, "use TAP interface instead of TUN (L2 instead of L3)")
	tunIP       = flag.String("tun-ip", "198.18.0.1", "TUN interface IP address (default: 198.18.0.1, RFC 2544 test range)")
	tunGateway  = flag.String("tun-gateway", "198.18.0.2", "TUN virtual gateway IP for routing (default: 198.18.0.2)")
	tunPrefix   = flag.Int("tun-prefix", 30, "TUN interface prefix length (default: 30 for /30 subnet)")
	
	// TUN Stack mode: "mixed" (gVisor for TCP/UDP + system fallback), "gvisor" (gVisor only), "system" (direct TUN read only)
	tunStackMode = flag.String("tun-stack", "mixed", "TUN stack mode: mixed (gVisor + system fallback, like Prizrak Box), gvisor (gVisor only), system (direct TUN read only)")
	
	// Certificate pinning flags
	certPinningEnabled = flag.Bool("cert-pinning", false, "enable certificate pinning for TLS connections")
	certPinningFile    = flag.String("cert-pinning-file", "", "file with certificate pins (hostname:hash format)")

	// XHTTP authentication flags (required)
	xhttpPublicKey = flag.String("xhttp-public-key", "", "XHTTP public key (ed25519, hex64) - REQUIRED")
	xhttpShortID = flag.String("xhttp-short-id", "", "XHTTP short ID (hex16) - REQUIRED")
	xhttpServerName = flag.String("xhttp-server-name", "", "XHTTP server name (e.g. example.com) - REQUIRED")
	xhttpFingerprint = flag.String("xhttp-fingerprint", "chrome", "XHTTP TLS fingerprint: chrome|firefox|safari|edge")
	xhttpMode = flag.String("xhttp-mode", "stream-up", "XHTTP mode: packet-up|stream-up|stream-one")
	xhttpMaxConcurrency = flag.Int("xhttp-max-concurrency", 8, "XHTTP max concurrent streams (XMUX-like)")
	xhttpALPN = flag.String("xhttp-alpn", "h2,http/1.1", "XHTTP ALPN list, comma-separated (e.g. h2,http/1.1)")

	// Proxy mode
	proxyMode = flag.Bool("proxy-mode", false, "run as SOCKS5 proxy instead of TUN interface (default: false, TUN mode)")
	kaSec     = flag.Int("keepalive", 20, "keepalive interval seconds (Noise mode)")
	// STUN server (совместимость с Tauri, пока не используется напрямую в Go-клиенте)
	stunServerFlag = flag.String("stun", "", "STUN server for NAT discovery (currently handled by Tauri/UI)")

	// Core obfuscation
	coreEnable = flag.Bool("core-enable", os.Getenv("WHISPERA_CORE_ENABLE") == "1", "enable core obfuscation processing in datapath (default off)")

	// Verbose packet logging
	verbosePackets = flag.Bool("verbose-packets", false, "log all packets passing through tunnel (TX/RX with sizes)")

	// Auto-detection and monitoring flags
	autoProfile      = flag.Bool("auto-profile", false, "автоматический выбор оптимального профиля")
	enableMonitoring = flag.Bool("monitoring", false, "включить мониторинг эффективности")
	appProfile       = flag.String("app-profile", "", "профиль приложения для мимикрии: vk|messenger_max|yandex|mailru|rutube|ozon")

	// TLS/DTLS flags
	useTLS        = flag.Bool("tls", os.Getenv("WHISPERA_USE_TLS") == "1", "enable TLS/DTLS modes (in addition to Noise/UDP)")
	tlsSkipVerify = flag.Bool("tls-skip-verify", false, "skip TLS certificate verification (INSECURE)")

	// Outbound tag flag
	outboundTag = flag.String("outbound-tag", "", "outbound tag to send to server after handshake")

	// Connection retry flags
	maxRetries     = flag.Int("max-retries", 5, "maximum number of connection retry attempts (0 = infinite)")
	retryInterval  = flag.Duration("retry-interval", 5*time.Second, "initial retry interval (exponential backoff)")
	retryMaxDelay  = flag.Duration("retry-max-delay", 60*time.Second, "maximum retry delay (caps exponential backoff)")
)

// Helper functions (from config/init.go)
func getEnvOrDefault(key, defaultValue string) string {
	if val := os.Getenv(key); val != "" {
		return val
	}
	return defaultValue
}

func setupLogging() {
	log.SetOutput(os.Stderr)
	log.SetFlags(log.LstdFlags | log.Lmicroseconds)
	os.Stderr.Sync()
}

func logStartupInfo() {
	log.Printf("[INFO] ========================================")
	log.Printf("[INFO] Whispera Go Client Starting")
	log.Printf("[INFO] ========================================")
	log.Printf("[INFO] PID: %d", os.Getpid())
	if wd, err := os.Getwd(); err == nil {
		log.Printf("[INFO] Working directory: %s", wd)
	}
	log.Printf("[INFO] ========================================")
}

func handlePanic() {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("[FATAL] Panic recovered: %v", r)
			debug.PrintStack()
			os.Exit(1)
		}
	}()
}

func initFlags() {
	flag.Parse()
}

// retryWithBackoff выполняет функцию с экспоненциальной задержкой при ошибках
// Возвращает результат функции или последнюю ошибку после всех попыток
func retryWithBackoff(fn func() error, operationName string) error {
	var lastErr error
	delay := *retryInterval
	attempt := 0
	
	for {
		lastErr = fn()
		if lastErr == nil {
			return nil // Успех
		}
		
		attempt++
		
		// Проверяем лимит попыток (0 = бесконечно)
		if *maxRetries > 0 && attempt >= *maxRetries {
			log.Printf("[RETRY] ❌ %s failed after %d attempts, giving up. Last error: %v", operationName, attempt, lastErr)
			return fmt.Errorf("%s failed after %d attempts: %w", operationName, attempt, lastErr)
		}
		
		// Логируем попытку
		log.Printf("[RETRY] ⚠️ %s failed (attempt %d/%v): %v. Retrying in %v...", 
			operationName, attempt, 
			func() string {
				if *maxRetries == 0 {
					return "∞"
				}
				return fmt.Sprintf("%d", *maxRetries)
			}(), 
			lastErr, delay)
		
		// Ждем перед следующей попыткой
		time.Sleep(delay)
		
		// Экспоненциальная задержка с ограничением максимума
		delay = time.Duration(float64(delay) * 1.5)
		if delay > *retryMaxDelay {
			delay = *retryMaxDelay
		}
	}
}

// retryConnectionInBackground запускает функцию подключения в фоне с повторными попытками
// TUN адаптер остается открытым во время повторных попыток
func retryConnectionInBackground(fn func() error, operationName string, successCallback func()) {
	go func() {
		var lastErr error
		delay := *retryInterval
		attempt := 0
		
		for {
			lastErr = fn()
			if lastErr == nil {
				log.Printf("[RETRY] ✅ %s succeeded after %d attempts", operationName, attempt)
				if successCallback != nil {
					successCallback()
				}
				return
			}
			
			attempt++
			
			// Проверяем лимит попыток (0 = бесконечно)
			if *maxRetries > 0 && attempt >= *maxRetries {
				log.Printf("[RETRY] ❌ %s failed after %d attempts, will keep retrying. Last error: %v", operationName, attempt, lastErr)
				// Не выходим, продолжаем попытки даже после достижения лимита
				// Это позволяет клиенту продолжать работать с открытым TUN адаптером
			}
			
			// Логируем попытку (реже после первых попыток, чтобы не засорять логи)
			if attempt <= 5 || attempt%10 == 0 {
				log.Printf("[RETRY] ⚠️ %s failed (attempt %d/%v): %v. Retrying in %v... (TUN adapter remains open)", 
					operationName, attempt, 
					func() string {
						if *maxRetries == 0 {
							return "∞"
						}
						return fmt.Sprintf("%d", *maxRetries)
					}(), 
					lastErr, delay)
			}
			
			// Ждем перед следующей попыткой
			time.Sleep(delay)
			
			// Экспоненциальная задержка с ограничением максимума
			delay = time.Duration(float64(delay) * 1.5)
			if delay > *retryMaxDelay {
				delay = *retryMaxDelay
			}
		}
	}()
}

// connectWithBackgroundRetry устанавливает соединение с фоновыми повторными попытками
// Возвращает канал, который закрывается когда соединение установлено
// Если первая попытка успешна, канал закрывается немедленно
// Если первая попытка неудачна, запускается фоновая ретрай-логика
func connectWithBackgroundRetry(fn func() error, operationName string) <-chan struct{} {
	ready := make(chan struct{})
	
	// Пробуем подключиться один раз
	err := fn()
	if err == nil {
		// Успех - закрываем канал немедленно
		close(ready)
		return ready
	}
	
	// Неудача - запускаем фоновые повторные попытки
	log.Printf("[RETRY] Initial %s failed: %v. Starting background retry (TUN adapter remains open)...", operationName, err)
	retryConnectionInBackground(fn, operationName, func() {
		close(ready)
	})
	
	return ready
}

// tunStack является глобальным экземпляром tun2socks-стека для клиентского процесса.
// На первом шаге он используется как единственный читатель TUN в UDP-режиме и
// передаёт сырые IP-пакеты наверх через PacketHandler.
var tunStack *tunstack.Stack

// gVisorNetstack — экспериментальный userspace-стек gVisor поверх TUN.
// На текущем этапе он только инициализируется и будет использоваться
// для будущей интеграции TCP/UDP через STREAM-слой вместо ручного tun2socks.
var gVisorNetstack *netstackpkg.Stack
var tunStackStarted int32
var netstackTCPHandlerSet int32

// clientStreamConn описывает клиентский TCP-поток, перенаправленный в gVisor netstack
// и обёрнутый в STREAM-слой UDP V2.
type clientStreamConn struct {
	Flow     tunstack.FlowKey
	StreamID uint16
	EP       interface{} // tcpip.Endpoint when with_gvisor, interface{} otherwise

	// Канал с данными приложения, которые нужно отправить на сервер в виде STREAM_DATA.
	ToRemote chan *netstackStreamFrame
	Done     chan struct{}
}

// netstackStreamFrame представляет собой единицу данных/сигнал для UDP-датаплейна:
// либо STREAM_DATA (Payload != nil), либо STREAM_CLOSE (Close=true).
type netstackStreamFrame struct {
	StreamID uint16
	Payload  []byte
	Close    bool
}

// Глобальная таблица потоков netstack StreamID -> clientStreamConn.
var (
	netstackStreamsMu    sync.RWMutex
	netstackStreams      = make(map[uint16]*clientStreamConn)
	netstackStreamChanMu sync.RWMutex
	netstackStreamChan   chan *netstackStreamFrame
)

// SessionCtx инкапсулирует общее состояние сессии клиента:
//   - один SessionID для всех транспортов;
//   - один AEADState (Noise/PSK) для всех туннелей;
//   - единый глобальный счётчик SeqSend, используемый всеми транспортами.
//
// Это позволяет прозрачно мигрировать между UDP/TCP/WS/WS2, сохраняя
// согласованный порядок пакетов и единое sliding-окно для приёма.
type SessionCtx struct {
	// Immutable after handshake
	SessionID uint32
	AEAD      *aeadpkg.AEADState

	// Global send sequence number shared across all transports.
	// MUST be incremented атомарно через atomic.AddUint32.
	SeqSend uint32

	// Per-session receive window and reassembler.
	RecvWin *aeadpkg.SlidingWindow
	Reasm   *proto.Reassembler
}

// NextSeq атомарно увеличивает глобальный счётчик и возвращает новое значение.
func (s *SessionCtx) NextSeq() uint32 {
	if s == nil {
		return 0
	}
	return atomic.AddUint32(&s.SeqSend, 1)
}

// They abstract transport layer (UDP/TCP/WS/WS2/gRPC/QUIC/HTTP2) for STREAM protocol

func main() {
	// НЕМЕДЛЕННЫЙ вывод в stderr ДО любой инициализации - чтобы увидеть, что процесс запустился
	os.Stderr.WriteString("[INIT] Go client main() started\n")
	os.Stderr.Sync()
	
	// Инициализация логирования
	setupLogging()
	
	// Немедленный вывод после setupLogging
	log.Printf("[INIT] Logging initialized")
	os.Stderr.Sync()
	
	logStartupInfo()
	handlePanic()

	// Парсинг флагов
	initFlags()
	
	// Немедленный вывод после парсинга флагов
	log.Printf("[INIT] Flags parsed successfully")
	os.Stderr.Sync()

	// Логируем полученные параметры для диагностики
	log.Printf("[DEBUG] Command line arguments parsed")
	// Фиктивное использование stunServerFlag, чтобы избежать unused, даже если логика STUN пока в UI
	if stunServerFlag != nil && *stunServerFlag != "" {
		log.Printf("[DEBUG] STUN server flag provided (client currently does not use it directly): %s", *stunServerFlag)
	}
	// Проверка обязательных параметров XHTTP
	if *xhttpPublicKey == "" || *xhttpShortID == "" || *xhttpServerName == "" {
		log.Fatal("[FATAL] XHTTP mode requires -xhttp-public-key, -xhttp-short-id, and -xhttp-server-name")
	}
	if *serverTCP == "" {
		log.Fatal("[FATAL] XHTTP mode requires -server (server address, e.g. example.com:443)")
	}
	log.Printf("[INFO] ✅ XHTTP mode - all required parameters provided")

	// Инициализация certificate pinning
	var certPinner *securitypkg.CertPinner
	if *certPinningEnabled {
		certPinner = securitypkg.NewCertPinner()
		certPinner.SetEnabled(true)
		
		if *certPinningFile != "" {
			if err := certPinner.LoadPinsFromFile(*certPinningFile); err != nil {
				log.Printf("[WARN] Failed to load certificate pins from file: %v", err)
			} else {
				log.Printf("[INFO] ✅ Certificate pinning enabled, loaded pins from %s", *certPinningFile)
			}
		} else {
			log.Printf("[INFO] ✅ Certificate pinning enabled (no pin file specified)")
		}
	}

	// Общая ошибка для последующих операций
	var err error

	// Создание TUN/TAP интерфейса
	log.Printf("[INFO] Preparing to create TUN/TAP interface...")
	os.Stderr.Sync()
	
	tunNameVal := *tunName
	if tunNameVal == "" {
		tunNameVal = "Whispera"
	}
	
	log.Printf("[INFO] Interface name: %s, useTAP: %v", tunNameVal, *useTAP)
	os.Stderr.Sync()
	
	var tun *tunpkg.Interface
	if *useTAP {
		log.Printf("[INFO] Creating TAP interface: %s", tunNameVal)
		os.Stderr.Sync()
		tun, err = tunpkg.OpenTAP(tunNameVal)
		if err != nil {
			log.Printf("[FATAL] Failed to create TAP interface: %v", err)
			os.Stderr.Sync()
			log.Fatalf("[FATAL] Failed to create TAP interface: %v", err)
		}
		log.Printf("[INFO] ✅ TAP interface created: %s", tun.Name())
		os.Stderr.Sync()
	} else {
		log.Printf("[INFO] Creating TUN interface: %s", tunNameVal)
		os.Stderr.Sync()
		tun, err = tunpkg.Open(tunNameVal)
		if err != nil {
			log.Printf("[FATAL] Failed to create TUN interface: %v", err)
			os.Stderr.Sync()
			log.Fatalf("[FATAL] Failed to create TUN interface: %v", err)
		}
		log.Printf("[INFO] ✅ TUN interface created: %s", tun.Name())
		os.Stderr.Sync()
	}
	// ВАЖНО: defer tun.Close() закрывает TUN адаптер при выходе из main()
	// Если подключение к серверу не удается, клиент завершается через log.Fatal(),
	// что вызывает закрытие TUN адаптера. Это ожидаемое поведение, но может
	// создавать впечатление, что адаптер "исчезает сразу".
	// Для production рекомендуется добавить retry-логику вместо немедленного выхода.
	defer tun.Close()

	// Настройка маршрутизации (Windows)
	if runtime.GOOS == "windows" {
		serverIP := ""
		if *serverTCP != "" {
			host, _, err := net.SplitHostPort(*serverTCP)
			if err == nil {
				serverIP = host
			}
		}
		if err := routing.ConfigureWindowsRoutes(tun.Name(), serverIP, *tunIP, *tunGateway, *tunPrefix); err != nil {
			log.Printf("[WARN] Failed to configure Windows routes: %v (continuing anyway)", err)
		} else {
			log.Printf("[INFO] ✅ Windows routes configured")
		}
	}

	// Создание сессии - только XHTTP
	var sess *session.SessionCtx
	var conn net.Conn

	// Подключение к серверу через XHTTP
	log.Printf("[INFO] 🚀 Connecting to XHTTP server: %s", *serverTCP)
	
	// Get obfuscation manager for XHTTP
	var obfuscationMgr *obfuscation.IntegrationManager
	if *coreEnable {
		obfuscationMgr = obfuscation.NewIntegrationManager()
	}
	
	var sid uint32
	
	// Try XHTTP connection
	err = func() error {
		var e error
		sid, conn, e = clientconnect.RunXHTTPClient(
			*serverTCP,
			*xhttpPublicKey,
			*xhttpShortID,
			*xhttpServerName,
			*xhttpFingerprint,
			*xhttpALPN,
			obfuscationMgr,
		)
		return e
	}()
	
	if err != nil {
		log.Printf("[WARN] Initial XHTTP connection failed: %v. Starting background retry (TUN adapter remains open)...", err)
		ready := make(chan struct{})
		retryConnectionInBackground(func() error {
			var e error
			var newSid uint32
			var newC net.Conn
			newSid, newC, e = clientconnect.RunXHTTPClient(
				*serverTCP,
				*xhttpPublicKey,
				*xhttpShortID,
				*xhttpServerName,
				*xhttpFingerprint,
				*xhttpALPN,
				obfuscationMgr,
			)
			if e == nil {
				sid = newSid
				conn = newC
				sess = &session.SessionCtx{
					SessionID: sid,
					AEAD:      nil, // XHTTP doesn't use AEAD
					SeqSend:   0,
					RecvWin:   nil, // XHTTP doesn't use sliding window
					Reasm:     proto.NewReassembler(30*time.Second, 1024),
				}
				log.Printf("[INFO] ✅ Connected to XHTTP server via retry, sessionID=%d", sid)
				close(ready)
			}
			return e
		}, "XHTTP connection", nil)
		<-ready
	} else {
		sess = &session.SessionCtx{
			SessionID: sid,
			AEAD:      nil, // XHTTP doesn't use AEAD
			SeqSend:   0,
			RecvWin:   nil, // XHTTP doesn't use sliding window
			Reasm:     proto.NewReassembler(30*time.Second, 1024),
		}
		log.Printf("[INFO] ✅ Connected to XHTTP server, sessionID=%d", sid)
	}

	// Создание core handler (используется только IntegrationManager для ML/обфускации)
	coreIM := obfuscation.NewIntegrationManager()

	// Инициализация TUN stack в зависимости от режима
	// Mixed mode (как в Prizrak Box): gVisor для TCP/UDP + system fallback для остальных пакетов
	// gVisor mode: только gVisor (если доступен)
	// System mode: только direct TUN read (dataplane)
	tunStackModeLower := strings.ToLower(*tunStackMode)
	useGVisor := tunStackModeLower == "mixed" || tunStackModeLower == "gvisor"
	useSystemStack := tunStackModeLower == "mixed" || tunStackModeLower == "system"
	
	log.Printf("[INFO] TUN Stack mode: %s (gVisor: %v, System: %v)", *tunStackMode, useGVisor, useSystemStack)
	
	// Функция для отправки данных через XHTTP туннель
	var sendThroughTunnel func([]byte) error
	if conn != nil {
		sendThroughTunnel = func(data []byte) error {
			// XHTTP уже обрабатывает обфускацию через ObfuscatedConn,
			// поэтому используем прямое соединение
			_, err := conn.Write(data)
			return err
		}
	}
	
	// Инициализируем gVisor tunstack (если требуется)
	if useGVisor && sendThroughTunnel != nil {
		tcpHandler := func(conn net.Conn, target string, protocol string) {
			log.Printf("[TUNSTACK] ✅ New %s connection intercepted from TUN to %s", protocol, target)
			go handleTunStackConnection(conn, target, protocol, sendThroughTunnel)
		}
		
		udpHandler := func(conn net.Conn, target string, protocol string) {
			log.Printf("[TUNSTACK] ✅ New %s connection intercepted from TUN to %s", protocol, target)
			go handleTunStackConnection(conn, target, protocol, sendThroughTunnel)
		}
		
		log.Printf("[INFO] Attempting to create gVisor tunstack (compiled with -tags=with_gvisor)...")
		var err error
		tunStack, err = tunstack.NewStack(tun, 1500, tcpHandler, udpHandler)
		if err != nil {
			log.Printf("[WARN] Failed to initialize gVisor tunstack: %v", err)
			if tunStackModeLower == "gvisor" {
				log.Fatal("[FATAL] gVisor mode requires gVisor, but initialization failed. Use -tun-stack=mixed or -tun-stack=system")
			}
			log.Printf("[INFO] Falling back to system stack (direct TUN read)")
			tunStack = nil
			useSystemStack = true // Fallback на system stack
		} else if tunStack != nil && !tunStack.IsActive() {
			log.Printf("[WARN] gVisor tunstack is stub (gvisor not compiled with -tags=with_gvisor)")
			if tunStackModeLower == "gvisor" {
				log.Fatal("[FATAL] gVisor mode requires gVisor, but it's not compiled. Use: go build -tags=with_gvisor ...")
			}
			log.Printf("[INFO] Falling back to system stack (direct TUN read)")
			tunStack = nil
			useSystemStack = true // Fallback на system stack
		} else {
			log.Printf("[INFO] ✅ gVisor tunstack initialized with XHTTP VPN tunnel integration")
			ctx := context.Background()
			tunStack.Start(ctx)
			if tunStackModeLower == "mixed" {
				log.Printf("[INFO] ✅ gVisor tunstack started (Mixed mode: TCP/UDP via gVisor, other packets via system stack)")
			} else {
				log.Printf("[INFO] ✅ gVisor tunstack started (gVisor mode: all traffic via gVisor)")
			}
		}
	} else if useGVisor {
		log.Printf("[WARN] gVisor mode requested but no transport available - falling back to system stack")
		useSystemStack = true
	}

	// Запуск data plane - только XHTTP (system stack для direct TUN read)
	if conn != nil && useSystemStack {
		log.Printf("[INFO] 🚀 Starting XHTTP data plane (system stack: direct TUN read)...")
		go runXHTTPClientDataPlane(conn, sess, tun, *kaSec, coreIM, *verbosePackets, *xhttpMode, *xhttpMaxConcurrency)
		log.Printf("[INFO] ✅ XHTTP data plane started")
	} else if conn == nil {
		log.Fatal("[FATAL] No XHTTP connection established")
	} else if !useSystemStack {
		log.Printf("[INFO] System stack disabled (gVisor mode) - data plane handled by gVisor tunstack")
	}

	// Ожидание сигнала завершения
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	log.Printf("[INFO] ✅ Client started, waiting for interrupt signal...")
	<-sigChan
	log.Printf("[INFO] Shutting down...")
}

// handleTunStackConnection обрабатывает соединение из gvisor tunstack и перенаправляет через VPN туннель
func handleTunStackConnection(conn net.Conn, target string, protocol string, sendFunc func([]byte) error) {
	defer func() {
		log.Printf("[TUNSTACK] 🔄 Handler finished for connection to %s (%s)", target, protocol)
	}()
	
	log.Printf("[TUNSTACK] Handling %s connection to %s", protocol, target)
	
	buf := make([]byte, 65535)
	readTimeout := 30 * time.Second
	if protocol == "udp" {
		readTimeout = 5 * time.Second
	}
	
	for {
		if tcpConn, ok := conn.(*net.TCPConn); ok {
			tcpConn.SetReadDeadline(time.Now().Add(readTimeout))
		}
		
		n, err := conn.Read(buf)
		
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			} else if err != io.EOF {
				log.Printf("[TUNSTACK] Read error from %s (%s): %v", target, protocol, err)
				return
			} else {
				log.Printf("[TUNSTACK] EOF from %s (%s), closing connection", target, protocol)
				return
			}
		}
		if n == 0 {
			continue
		}
		
		// Отправляем данные через XHTTP туннель
		if err := sendFunc(buf[:n]); err != nil {
			log.Printf("[TUNSTACK] Error sending data to %s (%s): %v", target, protocol, err)
			return
		}
	}
}

// createIPPacketFromConnection создает IP пакет из данных соединения
func createIPPacketFromConnection(data []byte, target string, protocol string) []byte {
	// Парсим target (например "192.168.1.1:80")
	host, _, err := net.SplitHostPort(target)
	if err != nil {
		return nil
	}
	
	// Получаем IP адрес назначения
	dstIP := net.ParseIP(host)
	if dstIP == nil {
		return nil
	}
	
	// Определяем протокол
	var protoNum byte
	if protocol == "tcp" {
		protoNum = 6
	} else if protocol == "udp" {
		protoNum = 17
	} else {
		return nil
	}
	
	// Создаем простой IPv4 пакет
	// IP заголовок: 20 байт минимум
	ipHeader := make([]byte, 20)
	ipHeader[0] = 0x45 // Version 4, IHL 5
	ipHeader[1] = 0x00 // TOS
	// Total Length будет установлен позже
	ipHeader[4] = 0x00 // ID
	ipHeader[5] = 0x00
	ipHeader[6] = 0x40 // Flags: DF
	ipHeader[7] = 0x00 // Fragment Offset
	ipHeader[8] = 64   // TTL
	ipHeader[9] = protoNum
	// Checksum будет установлен позже
	// Source IP (используем фиктивный адрес)
	copy(ipHeader[12:16], net.IPv4(10, 0, 0, 2).To4())
	// Destination IP
	if dstIP.To4() != nil {
		copy(ipHeader[16:20], dstIP.To4())
	} else {
		return nil // Пока только IPv4
	}
	
	// Объединяем IP заголовок и данные
	return append(ipHeader, data...)
}
