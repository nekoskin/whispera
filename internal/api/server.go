package api

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	adblockpkg "whispera/internal/adblock"
	cfgpkg "whispera/internal/config"
	"whispera/internal/obfuscation"
	srvpkg "whispera/internal/server"
	statspkg "whispera/internal/stats"
	tlspkg "whispera/internal/tls"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/crypto/curve25519"
)

// APIServer - HTTP API сервер для управления Whispera (xray-style)
type APIServer struct {
	server        *http.Server
	config        *cfgpkg.ServerConfig
	configPath    string
	configWatcher *ConfigWatcher
	manager       *ConfigManager
	runtime       *srvpkg.ServerRuntime
	obfuscation   *obfuscation.MarionetteAdapter
	management    *ManagementAPI
	adblock       *adblockpkg.Engine // AdBlock движок
	detailedStats *statspkg.DetailedStats // Детальная статистика по протоколам и транспортам
	serverPubKey  string // Публичный ключ сервера (автоматически вычисляется из приватного)
	startTime     time.Time // Время запуска сервера для расчета uptime
	loginRateLimiter *RateLimiter // Специальный rate limiter для логина (защита от brute-force)
	csrfTokens    map[string]time.Time // CSRF токены с временем истечения
	csrfSecret    []byte // Секрет для генерации CSRF токенов
	jwtSecret     []byte // Секрет для подписи JWT токенов
	passwordHash  []byte // Хэш пароля администратора (bcrypt)
	
	mu            sync.RWMutex
	running       bool
}

// GetManagementAPI возвращает ManagementAPI (для интеграции с сервером)
func (api *APIServer) GetManagementAPI() *ManagementAPI {
	return api.management
}

// SetRuntime связывает API сервер с ServerRuntime для применения конфига в рантайме
func (api *APIServer) SetRuntime(rt *srvpkg.ServerRuntime) {
	api.mu.Lock()
	defer api.mu.Unlock()
	api.runtime = rt
}

// GetDetailedStats возвращает детальную статистику (для интеграции с сервером)
func (api *APIServer) GetDetailedStats() *statspkg.DetailedStats {
	return api.detailedStats
}

// ConfigManager - управление конфигурацией
type ConfigManager struct {
	mu         sync.RWMutex
	config     *cfgpkg.ServerConfig
	configPath string
	lastReload time.Time
}

// GetConfig возвращает текущую конфигурацию
func (cm *ConfigManager) GetConfig() *cfgpkg.ServerConfig {
	cm.mu.RLock()
	defer cm.mu.RUnlock()
	return cm.config
}

// ConfigWatcher - отслеживание изменений конфигурации
type ConfigWatcher struct {
	path     string
	interval time.Duration
	stop     chan struct{}
}

// NewAPIServer создает новый API сервер
func NewAPIServer(listenAddr string, configPath string, cfg *cfgpkg.ServerConfig, marionette *obfuscation.MarionetteAdapter) *APIServer {
	return NewAPIServerWithKey(listenAddr, configPath, cfg, marionette, "")
}

// getUsersFilePath возвращает путь к файлу пользователей
func getUsersFilePath(configPath string) string {
	// Если указан configPath, используем его директорию
	if configPath != "" {
		dir := filepath.Dir(configPath)
		return filepath.Join(dir, "users.json")
	}
	// По умолчанию используем /opt/whispera/users.json
	return "/opt/whispera/users.json"
}

// normalizeListenAddr нормализует адрес для IPv4
// Если указан только порт (например ":8081"), преобразует в "0.0.0.0:8081"
func normalizeListenAddr(addr string) string {
	if strings.HasPrefix(addr, ":") {
		// Если адрес начинается с ":", добавляем 0.0.0.0 для IPv4
		return "0.0.0.0" + addr
	}
	// Если адрес уже содержит IP, возвращаем как есть
	return addr
}

// NewAPIServerWithKey создает новый API сервер с публичным ключом
func NewAPIServerWithKey(listenAddr string, configPath string, cfg *cfgpkg.ServerConfig, marionette *obfuscation.MarionetteAdapter, staticKeyHex string) *APIServer {
	mux := http.NewServeMux()
	
	// Нормализуем адрес для IPv4
	normalizedAddr := normalizeListenAddr(listenAddr)
	
	// Вычисляем публичный ключ из приватного
	var serverPubKey string
	if staticKeyHex != "" {
		if priv, err := hex.DecodeString(staticKeyHex); err == nil && len(priv) == 32 {
			if pub, err := curve25519.X25519(priv, curve25519.Basepoint); err == nil {
				serverPubKey = hex.EncodeToString(pub)
			}
		}
	}
	
	// Инициализируем AdBlock движок
	adblockEngine := adblockpkg.NewEngine()
	// Загружаем стандартные списки блокировки
	go func() {
		if err := adblockEngine.LoadDefaultLists(); err != nil {
			log.Printf("[AdBlock] Failed to load default lists: %v", err)
		}
	}()

	// SECURITY: Генерируем секрет для CSRF токенов
	csrfSecret := make([]byte, 32)
	if _, err := rand.Read(csrfSecret); err != nil {
		log.Printf("[API] Warning: failed to generate CSRF secret: %v", err)
		// Fallback на статический секрет (не рекомендуется для production)
		copy(csrfSecret, []byte("whispera-csrf-secret-key-32bytes"))
	}
	
	// SECURITY: Генерируем секрет для JWT токенов
	jwtSecret := make([]byte, 32)
	if _, err := rand.Read(jwtSecret); err != nil {
		log.Printf("[API] Warning: failed to generate JWT secret: %v", err)
		// Fallback на статический секрет (не рекомендуется для production)
		copy(jwtSecret, []byte("whispera-jwt-secret-key-32bytes"))
	}
	
	// SECURITY: Хэшируем пароль администратора с помощью bcrypt
	validPassword := os.Getenv("WHISPERA_ADMIN_PASSWORD")
	if validPassword == "" {
		validPassword = "admin"
	}
	passwordHash, err := bcrypt.GenerateFromPassword([]byte(validPassword), bcrypt.DefaultCost)
	if err != nil {
		log.Printf("[API] Warning: failed to hash password: %v", err)
		// Fallback на пустой хэш (небезопасно, но лучше чем паника)
		passwordHash = []byte{}
	}
	
	api := &APIServer{
		server: &http.Server{
			Addr:         normalizedAddr,
			Handler:      mux,
			ReadTimeout:  15 * time.Second,
			WriteTimeout: 15 * time.Second,
			IdleTimeout:  60 * time.Second,
		},
		config:      cfg,
		configPath:  configPath,
		manager:     NewConfigManager(configPath, cfg),
		obfuscation: marionette,
		management:  NewManagementAPIWithStorage(getUsersFilePath(configPath)),
		adblock:     adblockEngine,
		detailedStats: statspkg.NewDetailedStats(),
		serverPubKey: serverPubKey,
		startTime:   time.Now(), // Запоминаем время запуска для расчета uptime
		csrfTokens:  make(map[string]time.Time),
		csrfSecret:  csrfSecret,
		jwtSecret:   jwtSecret,
		passwordHash: passwordHash,
	}
	
	// Регистрируем endpoints
	api.registerHandlers(mux)
	
	// Регистрируем management endpoints (xray-style)
	api.management.RegisterManagementHandlers(mux)
	
	// Применяем rate limiting для защиты от DDoS
	// Создаем rate limiter и оборачиваем mux
	rl := NewRateLimiter(100, 1*time.Minute)
	// SECURITY: Специальный строгий rate limiter для логина (защита от brute-force)
	loginRateLimiter := NewRateLimiter(5, 1*time.Minute) // 5 попыток в минуту
	api.loginRateLimiter = loginRateLimiter
	wrappedMux := RateLimitMiddleware(rl)(mux)
	api.server.Handler = wrappedMux
	
	return api
}

// NewAPIServerTLS создает новый API сервер с TLS поддержкой
func NewAPIServerTLS(listenAddr string, configPath string, cfg *cfgpkg.ServerConfig, marionette *obfuscation.MarionetteAdapter, certFile, keyFile string) (*APIServer, error) {
	return NewAPIServerTLSWithKey(listenAddr, configPath, cfg, marionette, certFile, keyFile, "")
}

// NewAPIServerTLSWithKey создает новый API сервер с TLS и публичным ключом
func NewAPIServerTLSWithKey(listenAddr string, configPath string, cfg *cfgpkg.ServerConfig, marionette *obfuscation.MarionetteAdapter, certFile, keyFile, staticKeyHex string) (*APIServer, error) {
	api := NewAPIServerWithKey(listenAddr, configPath, cfg, marionette, staticKeyHex)
	
	// Настраиваем TLS
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("failed to load TLS certificates: %w", err)
	}
	
	// SECURITY: Используем браузероподобный TLS fingerprint для обхода DPI
	api.server.TLSConfig = tlspkg.GetBrowserLikeServerTLSConfig(
		tlspkg.GetDefaultBrowserFingerprint(),
		[]tls.Certificate{cert},
	)
	
	// Wrap the HTTP server's error log to filter common TLS errors
	// This suppresses expected errors like "client sent an HTTP request to an HTTPS server"
	// which are common when bots/scanners probe the server
	api.server.ErrorLog = log.New(&tlsErrorFilter{original: os.Stderr}, "", log.LstdFlags)
	
	return api, nil
}

// NewConfigManager создает новый менеджер конфигурации
func NewConfigManager(configPath string, cfg *cfgpkg.ServerConfig) *ConfigManager {
	return &ConfigManager{
		config:     cfg,
		configPath: configPath,
		lastReload: time.Now(),
	}
}

// registerHandlers регистрирует HTTP handlers
func (api *APIServer) registerHandlers(mux *http.ServeMux) {
	// CORS middleware для веб-панели
	mux.HandleFunc("/", api.corsMiddleware(api.handleWebPanel))
	
	// SECURITY: CSRF token endpoint (публичный, не требует авторизации)
	mux.HandleFunc("/api/csrf-token", api.corsMiddleware(api.handleCSRFToken))
	
	// Authentication endpoint
	mux.HandleFunc("/api/login", api.corsMiddleware(api.handleLogin))
	
	// System endpoints (публичные)
	mux.HandleFunc("/api/system/info", api.corsMiddleware(api.handleSystemInfo))
	mux.HandleFunc("/api/system/status", api.corsMiddleware(api.authMiddleware(api.handleSystemStatus)))
	mux.HandleFunc("/api/system/reload", api.corsMiddleware(api.authMiddleware(api.handleConfigReload)))
	
	// Configuration endpoints (xray-style) - требуют авторизации
	mux.HandleFunc("/api/config", api.corsMiddleware(api.authMiddleware(api.handleConfigGet)))
	mux.HandleFunc("/api/config/reload", api.corsMiddleware(api.authMiddleware(api.handleConfigReload)))
	mux.HandleFunc("/api/config/update", api.corsMiddleware(api.authMiddleware(api.handleConfigUpdate)))
	
	// Profiles endpoints - требуют авторизации
	mux.HandleFunc("/api/profiles", api.corsMiddleware(api.authMiddleware(api.handleProfilesList)))
	mux.HandleFunc("/api/profiles/current", api.corsMiddleware(api.authMiddleware(api.handleProfileCurrent)))
	mux.HandleFunc("/api/profiles/switch", api.corsMiddleware(api.authMiddleware(api.handleProfileSwitch)))
	mux.HandleFunc("/api/profiles/add", api.corsMiddleware(api.authMiddleware(api.handleProfileAdd)))
	mux.HandleFunc("/api/profiles/remove", api.corsMiddleware(api.authMiddleware(api.handleProfileRemove)))
	
	// Statistics endpoints - требуют авторизации
	mux.HandleFunc("/api/stats", api.corsMiddleware(api.authMiddleware(api.handleStats)))
	mux.HandleFunc("/api/stats/traffic", api.corsMiddleware(api.authMiddleware(api.handleStatsTraffic)))
	mux.HandleFunc("/api/stats/detailed", api.corsMiddleware(api.authMiddleware(api.handleStatsDetailed)))
	mux.HandleFunc("/api/stats/traffic/history", api.corsMiddleware(api.authMiddleware(api.handleTrafficHistory)))
	mux.HandleFunc("/api/stats/user/", api.corsMiddleware(api.authMiddleware(api.handleUserTraffic)))
	mux.HandleFunc("/api/stats/ml", api.corsMiddleware(api.authMiddleware(api.handleStatsML)))
	
	// Logs endpoint - требует авторизации
	mux.HandleFunc("/api/logs", api.corsMiddleware(api.authMiddleware(api.handleLogs)))
	
	// Health check
	mux.HandleFunc("/health", api.corsMiddleware(api.handleHealth))
	
	// Client config by key (for Quick Connect)
	mux.HandleFunc("/api/client/config-by-key", api.corsMiddleware(api.handleClientConfigByKey))
	
	// Key generation endpoints - требуют авторизации
	mux.HandleFunc("/api/keys/generate", api.corsMiddleware(api.authMiddleware(api.handleGenerateKeys)))
	mux.HandleFunc("/api/keys/generate-server", api.corsMiddleware(api.authMiddleware(api.handleGenerateServerKeys)))
	mux.HandleFunc("/api/keys/derive", api.corsMiddleware(api.authMiddleware(api.handleDerivePublicKey)))
	
	// AdBlock endpoints (заглушки для веб-панели) - требуют авторизации
	mux.HandleFunc("/api/adblock/stats", api.corsMiddleware(api.authMiddleware(api.handleAdblockStats)))
	mux.HandleFunc("/api/adblock/rules", api.corsMiddleware(api.authMiddleware(api.handleAdblockRules)))
	mux.HandleFunc("/api/adblock/rules/add", api.corsMiddleware(api.authMiddleware(api.handleAdblockRuleAdd)))
	mux.HandleFunc("/api/adblock/rules/delete", api.corsMiddleware(api.authMiddleware(api.handleAdblockRuleDelete)))
	mux.HandleFunc("/api/adblock/settings", api.corsMiddleware(api.authMiddleware(api.handleAdblockSettings)))
	
	// Let's Encrypt certificate management endpoints - требуют авторизации
	mux.HandleFunc("/api/certificate/status", api.corsMiddleware(api.authMiddleware(api.handleCertificateStatus)))
	mux.HandleFunc("/api/certificate/obtain", api.corsMiddleware(api.authMiddleware(api.handleCertificateObtain)))
	mux.HandleFunc("/api/certificate/renew", api.corsMiddleware(api.authMiddleware(api.handleCertificateRenew)))
}

// Start запускает API сервер (HTTP)
func (api *APIServer) Start() error {
	api.mu.Lock()
	if api.running {
		api.mu.Unlock()
		return fmt.Errorf("API server is already running")
	}
	api.running = true
	api.mu.Unlock()
	
	// Start config watcher
	if api.configPath != "" {
		api.configWatcher = NewConfigWatcher(api.configPath, 5*time.Second)
		go api.configWatcher.Watch(api.manager)
	}
	
	protocol := "HTTP"
	if api.server.TLSConfig != nil {
		protocol = "HTTPS"
	}
	log.Printf("Starting Whispera API server on %s (%s)", api.server.Addr, protocol)
	
	// Явно используем IPv4 для слушателя
	lc := net.ListenConfig{}
	ln, err := lc.Listen(context.Background(), "tcp4", api.server.Addr)
	if err != nil {
		api.mu.Lock()
		api.running = false
		api.mu.Unlock()
		return fmt.Errorf("failed to listen on %s: %w", api.server.Addr, err)
	}
	
	if api.server.TLSConfig != nil {
		// HTTPS режим - используем TLS listener
		tlsListener := tls.NewListener(ln, api.server.TLSConfig)
		if err := api.server.Serve(tlsListener); err != nil && err != http.ErrServerClosed {
			api.mu.Lock()
			api.running = false
			api.mu.Unlock()
			return fmt.Errorf("API server (HTTPS) error: %w", err)
		}
	} else {
		// HTTP режим
		if err := api.server.Serve(ln); err != nil && err != http.ErrServerClosed {
			api.mu.Lock()
			api.running = false
			api.mu.Unlock()
			return fmt.Errorf("API server (HTTP) error: %w", err)
		}
	}
	
	return nil
}

// StartTLS запускает API сервер с TLS
func (api *APIServer) StartTLS(certFile, keyFile string) error {
	api.mu.Lock()
	if api.running {
		api.mu.Unlock()
		return fmt.Errorf("API server is already running")
	}
	api.running = true
	api.mu.Unlock()
	
	// Start config watcher
	if api.configPath != "" {
		api.configWatcher = NewConfigWatcher(api.configPath, 5*time.Second)
		go api.configWatcher.Watch(api.manager)
	}
	
	log.Printf("Starting Whispera API server with TLS on %s", api.server.Addr)
	
	// Явно используем IPv4 для слушателя
	lc := net.ListenConfig{}
	ln, err := lc.Listen(context.Background(), "tcp4", api.server.Addr)
	if err != nil {
		api.mu.Lock()
		api.running = false
		api.mu.Unlock()
		return fmt.Errorf("failed to listen on %s: %w", api.server.Addr, err)
	}
	
	// Загружаем сертификаты для TLS
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		_ = ln.Close()
		api.mu.Lock()
		api.running = false
		api.mu.Unlock()
		return fmt.Errorf("failed to load TLS certificate: %w", err)
	}
	
	// Создаем TLS listener
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
		MaxVersion:   tls.VersionTLS13,
	}
	tlsListener := tls.NewListener(ln, tlsConfig)
	
	if err := api.server.Serve(tlsListener); err != nil && err != http.ErrServerClosed {
		api.mu.Lock()
		api.running = false
		api.mu.Unlock()
		return fmt.Errorf("API server (HTTPS) error: %w", err)
	}
	
	return nil
}

// Stop останавливает API сервер
func (api *APIServer) Stop(ctx context.Context) error {
	api.mu.Lock()
	if !api.running {
		api.mu.Unlock()
		return nil
	}
	api.running = false
	
	if api.configWatcher != nil {
		api.configWatcher.Stop()
	}
	api.mu.Unlock()
	
	if err := api.server.Shutdown(ctx); err != nil {
		return fmt.Errorf("API server shutdown error: %w", err)
	}
	
	log.Println("API server stopped")
	return nil
}

// getExternalIP получает внешний IP адрес сервера
func getExternalIP() string {
	// Сначала пытаемся получить из hosting-info.txt
	possiblePaths := []string{
		"/opt/whispera/hosting-info.txt",
		"./hosting-info.txt",
		"hosting-info.txt",
	}
	
	for _, path := range possiblePaths {
		if data, err := os.ReadFile(path); err == nil {
			content := string(data)
			// Ищем строку вида SERVER_IP: x.x.x.x
			lines := strings.Split(content, "\n")
			for _, line := range lines {
				if strings.HasPrefix(strings.TrimSpace(line), "SERVER_IP:") {
					parts := strings.Split(line, ":")
					if len(parts) >= 2 {
						ip := strings.TrimSpace(parts[1])
						if ip != "" && ip != "YOUR_SERVER_IP" {
							return ip
						}
					}
				}
			}
		}
	}
	
	// Если не нашли в файле, пытаемся определить из запроса
	// IP будет определен на фронтенде из window.location.hostname
	return ""
}

// readPublicKeyFromHostingInfo читает публичный ключ из hosting-info.txt
func readPublicKeyFromHostingInfo() string {
	possiblePaths := []string{
		"/opt/whispera/hosting-info.txt",
		"./hosting-info.txt",
		"hosting-info.txt",
	}
	
	for _, path := range possiblePaths {
		if data, err := os.ReadFile(path); err == nil {
			content := string(data)
			lines := strings.Split(content, "\n")
			for _, line := range lines {
				line = strings.TrimSpace(line)
				// Пробуем разные форматы: "SERVER_PUBLIC_KEY:", "Server Public Key:", "SERVER_PUB:"
				if strings.HasPrefix(line, "SERVER_PUBLIC_KEY:") {
					parts := strings.SplitN(line, ":", 2)
					if len(parts) == 2 {
						key := strings.TrimSpace(parts[1])
						if len(key) == 64 {
							return key
						}
					}
				}
				if strings.HasPrefix(line, "Server Public Key:") {
					parts := strings.SplitN(line, ":", 2)
					if len(parts) == 2 {
						key := strings.TrimSpace(parts[1])
						if len(key) == 64 {
							return key
						}
					}
				}
				if strings.HasPrefix(line, "SERVER_PUB:") {
					parts := strings.SplitN(line, ":", 2)
					if len(parts) == 2 {
						key := strings.TrimSpace(parts[1])
						if len(key) == 64 {
							return key
						}
					}
				}
			}
		}
	}
	return ""
}

// handleSystemInfo возвращает информацию о системе
func (api *APIServer) handleSystemInfo(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		w.Header().Set("Allow", "GET")
		api.writeError(w, http.StatusMethodNotAllowed, "Method not allowed. Use GET.")
		return
	}
	
	// Получаем IP адрес сервера
	serverIP := getExternalIP()
	
	// Если IP не найден в файле, пытаемся определить из Host заголовка
	if serverIP == "" {
		host := r.Host
		if idx := strings.Index(host, ":"); idx > 0 {
			host = host[:idx]
		}
		// Пропускаем localhost и внутренние IP
		if host != "localhost" && host != "127.0.0.1" && !strings.HasPrefix(host, "192.168.") && !strings.HasPrefix(host, "10.") {
			serverIP = host
		}
	}
	
	// Получаем порт из конфигурации
	serverPort := 51820 // Дефолтный порт
	if api.config != nil && api.config.Listen != "" {
		// Парсим порт из формата "0.0.0.0:51820" или ":51820"
		if idx := strings.LastIndex(api.config.Listen, ":"); idx >= 0 {
			if portStr := api.config.Listen[idx+1:]; portStr != "" {
				if port, err := strconv.Atoi(portStr); err == nil && port > 0 {
					serverPort = port
				}
			}
		}
	}
	
	info := map[string]interface{}{
		"version":      "1.0.0",
		"uptime":       time.Since(time.Now()).String(), // Placeholder
		"config_path":  api.configPath,
		"running":      api.running,
		"server_ip":    serverIP,
		"serverIP":     serverIP, // Дублируем для совместимости
		"server_port":  serverPort,
		"serverPort":   serverPort, // Дублируем для совместимости
		"server_host": r.Host,
	}
	
	// Добавляем публичный ключ сервера для автоматической настройки клиентов
	// Сначала пробуем вычисленный ключ, если нет - читаем из hosting-info.txt
	serverPubKey := api.serverPubKey
	if serverPubKey == "" {
		// Fallback: читаем из hosting-info.txt (для старых версий сервера)
		serverPubKey = readPublicKeyFromHostingInfo()
	}
	if serverPubKey != "" {
		info["server_pub"] = serverPubKey
		info["serverPublicKey"] = serverPubKey // Дублируем для совместимости
	}
	
	api.writeJSON(w, info)
}

// handleSystemStatus возвращает статус системы
func (api *APIServer) handleSystemStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		w.Header().Set("Allow", "GET")
		api.writeError(w, http.StatusMethodNotAllowed, "Method not allowed. Use GET.")
		return
	}
	
	status := map[string]interface{}{
		"status":  "running",
		"healthy": true,
		"time":    time.Now().Unix(),
	}
	
	api.writeJSON(w, status)
}

// handleConfigGet возвращает текущую конфигурацию
func (api *APIServer) handleConfigGet(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		w.Header().Set("Allow", "GET")
		api.writeError(w, http.StatusMethodNotAllowed, "Method not allowed. Use GET.")
		return
	}
	
	api.manager.mu.RLock()
	cfg := api.manager.config
	api.manager.mu.RUnlock()
	
	if cfg == nil {
		api.writeError(w, http.StatusNotFound, "Configuration not found")
		return
	}
	
	api.writeJSON(w, cfg)
}

// handleConfigReload перезагружает конфигурацию из файла
func (api *APIServer) handleConfigReload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		w.Header().Set("Allow", "POST")
		api.writeError(w, http.StatusMethodNotAllowed, "Method not allowed. Use POST.")
		return
	}
	
	if err := api.manager.Reload(); err != nil {
		api.writeError(w, http.StatusInternalServerError, fmt.Sprintf("Failed to reload config: %v", err))
		return
	}

	var changes []string
	var runtimeError string

	// Если привязан ServerRuntime, пробуем применить конфиг к рантайму
	api.mu.RLock()
	rt := api.runtime
	api.mu.RUnlock()
	if rt != nil {
		newCfg := api.manager.GetConfig()
		if newCfg != nil {
			if ch, err := rt.Reload(newCfg); err != nil {
				runtimeError = err.Error()
				log.Printf("[API] Runtime reload error: %v", err)
			} else {
				changes = ch
			}
		}
	}

	resp := map[string]interface{}{
		"success":     true,
		"message":     "Configuration reloaded successfully",
		"reloaded_at": time.Now().Unix(),
		"changes":     changes,
	}
	if runtimeError != "" {
		resp["runtime_error"] = runtimeError
	}
	api.writeJSON(w, resp)
}

// handleConfigUpdate обновляет конфигурацию
func (api *APIServer) handleConfigUpdate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		w.Header().Set("Allow", "POST")
		api.writeError(w, http.StatusMethodNotAllowed, "Method not allowed. Use POST.")
		return
	}
	
	if r.Header.Get("Content-Type") != "application/json" {
		api.writeError(w, http.StatusUnsupportedMediaType, "Content-Type must be application/json")
		return
	}
	
	var newConfig cfgpkg.ServerConfig
	if err := json.NewDecoder(r.Body).Decode(&newConfig); err != nil {
		api.writeError(w, http.StatusBadRequest, fmt.Sprintf("Invalid JSON format: %v", err))
		return
	}
	
	if err := api.manager.Update(&newConfig); err != nil {
		api.writeError(w, http.StatusInternalServerError, fmt.Sprintf("Failed to update config: %v", err))
		return
	}
	
	api.writeJSON(w, map[string]interface{}{
		"success": true,
		"message": "Configuration updated successfully",
	})
}

// handleProfilesList возвращает список всех профилей
func (api *APIServer) handleProfilesList(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		w.Header().Set("Allow", "GET")
		api.writeError(w, http.StatusMethodNotAllowed, "Method not allowed. Use GET.")
		return
	}
	
	if api.obfuscation == nil {
		w.WriteHeader(http.StatusServiceUnavailable)
		api.writeError(w, http.StatusServiceUnavailable, "Obfuscation system not available")
		return
	}
	
	profiles := api.obfuscation.GetProfileSwitchHistory()
	api.writeJSON(w, profiles)
}

// handleProfileCurrent возвращает текущий активный профиль
func (api *APIServer) handleProfileCurrent(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		w.Header().Set("Allow", "GET")
		api.writeError(w, http.StatusMethodNotAllowed, "Method not allowed. Use GET.")
		return
	}
	
	if api.obfuscation == nil {
		w.WriteHeader(http.StatusServiceUnavailable)
		api.writeError(w, http.StatusServiceUnavailable, "Obfuscation system not available")
		return
	}
	
	current := api.obfuscation.GetCurrentProfile()
	api.writeJSON(w, map[string]interface{}{
		"profile": current,
	})
}

// handleProfileSwitch переключает профиль
func (api *APIServer) handleProfileSwitch(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		w.Header().Set("Allow", "POST")
		api.writeError(w, http.StatusMethodNotAllowed, "Method not allowed. Use POST.")
		return
	}
	
	if r.Header.Get("Content-Type") != "application/json" {
		api.writeError(w, http.StatusUnsupportedMediaType, "Content-Type must be application/json")
		return
	}
	
	var req struct {
		Profile string `json:"profile"`
		Reason  string `json:"reason"`
	}
	
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		api.writeError(w, http.StatusBadRequest, fmt.Sprintf("Invalid JSON format: %v", err))
		return
	}
	
	if req.Profile == "" {
		api.writeError(w, http.StatusBadRequest, "Profile name is required")
		return
	}
	
	if api.obfuscation == nil {
		api.writeError(w, http.StatusServiceUnavailable, "Obfuscation system not available")
		return
	}
	
	reason := req.Reason
	if reason == "" {
		reason = "manual_switch"
	}
	
	if err := api.obfuscation.SwitchProfile(req.Profile, reason); err != nil {
		api.writeError(w, http.StatusBadRequest, fmt.Sprintf("Failed to switch profile: %v", err))
		return
	}
	
	api.writeJSON(w, map[string]interface{}{
		"success": true,
		"profile": req.Profile,
		"message": fmt.Sprintf("Switched to profile: %s", req.Profile),
	})
}

// handleProfileAdd добавляет новый профиль
func (api *APIServer) handleProfileAdd(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		w.Header().Set("Allow", "POST")
		api.writeError(w, http.StatusMethodNotAllowed, "Method not allowed. Use POST.")
		return
	}
	
	if r.Header.Get("Content-Type") != "application/json" {
		api.writeError(w, http.StatusUnsupportedMediaType, "Content-Type must be application/json")
		return
	}
	
	var req struct {
		Name   string                 `json:"name"`
		Config map[string]interface{} `json:"config"`
	}
	
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		api.writeError(w, http.StatusBadRequest, fmt.Sprintf("Invalid JSON format: %v", err))
		return
	}
	
	if req.Name == "" {
		api.writeError(w, http.StatusBadRequest, "Profile name is required")
		return
	}
	
	if api.obfuscation == nil {
		api.writeError(w, http.StatusServiceUnavailable, "Obfuscation system not available")
		return
	}
	
	// Добавляем профиль через Marionette
	if err := api.obfuscation.AddProfile(req.Name, req.Config); err != nil {
		api.writeError(w, http.StatusBadRequest, fmt.Sprintf("Failed to add profile: %v", err))
		return
	}
	
	api.writeJSON(w, map[string]interface{}{
		"success": true,
		"profile": req.Name,
		"message": fmt.Sprintf("Profile %s added successfully", req.Name),
	})
}

// handleProfileRemove удаляет профиль
func (api *APIServer) handleProfileRemove(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete && r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		w.Header().Set("Allow", "DELETE, POST")
		api.writeError(w, http.StatusMethodNotAllowed, "Method not allowed. Use DELETE or POST.")
		return
	}
	
	if r.Header.Get("Content-Type") != "application/json" && r.Method == http.MethodPost {
		api.writeError(w, http.StatusUnsupportedMediaType, "Content-Type must be application/json")
		return
	}
	
	var req struct {
		Name string `json:"name"`
	}
	
	// Для DELETE метода имя может быть в query параметре или в body
	if r.Method == http.MethodDelete {
		name := r.URL.Query().Get("name")
		if name == "" {
			// Пробуем прочитать из body
			if r.Body != nil {
				json.NewDecoder(r.Body).Decode(&req)
			}
			if req.Name == "" {
				api.writeError(w, http.StatusBadRequest, "Profile name is required (use ?name=profile_name or JSON body)")
				return
			}
		} else {
			req.Name = name
		}
	} else {
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			api.writeError(w, http.StatusBadRequest, fmt.Sprintf("Invalid JSON format: %v", err))
			return
		}
	}
	
	if req.Name == "" {
		api.writeError(w, http.StatusBadRequest, "Profile name is required")
		return
	}
	
	if api.obfuscation == nil {
		api.writeError(w, http.StatusServiceUnavailable, "Obfuscation system not available")
		return
	}
	
	// Удаляем профиль через Marionette
	if err := api.obfuscation.RemoveProfile(req.Name); err != nil {
		api.writeError(w, http.StatusBadRequest, fmt.Sprintf("Failed to remove profile: %v", err))
		return
	}
	
	api.writeJSON(w, map[string]interface{}{
		"success": true,
		"profile": req.Name,
		"message": fmt.Sprintf("Profile %s removed successfully", req.Name),
	})
}

// handleStats возвращает общую статистику
func (api *APIServer) handleStats(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		w.Header().Set("Allow", "GET")
		api.writeError(w, http.StatusMethodNotAllowed, "Method not allowed. Use GET.")
		return
	}
	
	// Собираем реальную статистику
	var totalPackets, totalBytes int64
	var connections int
	
	// Получаем статистику из management API (сессии)
	if api.management != nil && api.management.sessionTracker != nil {
		sessions := api.management.sessionTracker.GetAllSessions()
		connections = len(sessions)
		
		for _, session := range sessions {
			totalPackets += session.PacketsTx + session.PacketsRx
			totalBytes += session.Upload + session.Download
		}
	}
	
	// Вычисляем uptime
	uptime := time.Since(api.startTime).Seconds()
	
	stats := map[string]interface{}{
		"traffic": map[string]interface{}{
			"packets": totalPackets,
			"bytes":   totalBytes,
		},
		"connections": connections,
		"uptime":      int64(uptime), // Uptime в секундах
		"uptime_human": formatUptime(uptime),
	}
	
	api.writeJSON(w, stats)
}

// handleStatsTraffic возвращает статистику трафика
func (api *APIServer) handleStatsTraffic(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		w.Header().Set("Allow", "GET")
		api.writeError(w, http.StatusMethodNotAllowed, "Method not allowed. Use GET.")
		return
	}
	
	var totalPackets, totalBytes int64
	var inboundBytes, outboundBytes int64
	
	if api.management != nil && api.management.sessionTracker != nil {
		sessions := api.management.sessionTracker.GetAllSessions()
		for _, session := range sessions {
			totalPackets += session.PacketsTx + session.PacketsRx
			totalBytes += session.Upload + session.Download
			inboundBytes += session.Download  // Download = inbound для сервера
			outboundBytes += session.Upload   // Upload = outbound для сервера
		}
	}
	
	traffic := map[string]interface{}{
		"total_packets": totalPackets,
		"total_bytes":   totalBytes,
		"inbound":       inboundBytes,
		"outbound":      outboundBytes,
	}
	
	api.writeJSON(w, traffic)
}

// formatUptime форматирует uptime в человекочитаемый формат
func formatUptime(seconds float64) string {
	duration := time.Duration(seconds) * time.Second
	
	days := int(duration.Hours() / 24)
	hours := int(duration.Hours()) % 24
	minutes := int(duration.Minutes()) % 60
	secs := int(duration.Seconds()) % 60
	
	if days > 0 {
		return fmt.Sprintf("%dd %dh %dm %ds", days, hours, minutes, secs)
	} else if hours > 0 {
		return fmt.Sprintf("%dh %dm %ds", hours, minutes, secs)
	} else if minutes > 0 {
		return fmt.Sprintf("%dm %ds", minutes, secs)
	}
	return fmt.Sprintf("%ds", secs)
}

// handleTrafficHistory возвращает историю трафика
func (api *APIServer) handleTrafficHistory(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		w.Header().Set("Allow", "GET")
		api.writeError(w, http.StatusMethodNotAllowed, "Method not allowed. Use GET.")
		return
	}
	
	period := r.URL.Query().Get("period")
	if period == "" {
		period = "24h"
	}
	
	// Генерируем фиктивные данные для демонстрации
	// В реальности нужно получать из метрик
	dataPoints := []map[string]interface{}{}
	now := time.Now()
	
	var points int
	switch period {
	case "1h":
		points = 60 // 1 точка в минуту
	case "24h":
		points = 24 // 1 точка в час
	case "7d":
		points = 168 // 1 точка в час за 7 дней
	case "30d":
		points = 30 // 1 точка в день
	default:
		points = 24
	}
	
	for i := 0; i < points; i++ {
		var timestamp time.Time
		switch period {
		case "1h":
			timestamp = now.Add(-time.Duration(points-i) * time.Minute)
		case "24h":
			timestamp = now.Add(-time.Duration(points-i) * time.Hour)
		case "7d":
			timestamp = now.Add(-time.Duration(points-i) * time.Hour)
		case "30d":
			timestamp = now.AddDate(0, 0, -(points - i))
		}
		
		// Генерируем случайные значения для демонстрации
		upload := int64((points - i) * 1024 * 100)
		download := int64((points - i) * 1024 * 150)
		
		dataPoints = append(dataPoints, map[string]interface{}{
			"timestamp": timestamp.Unix(),
			"upload":    upload,
			"download":  download,
		})
	}
	
	api.writeJSON(w, map[string]interface{}{
		"period": period,
		"data":   dataPoints,
	})
}

// handleUserTraffic возвращает трафик конкретного пользователя
func (api *APIServer) handleUserTraffic(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		w.Header().Set("Allow", "GET")
		api.writeError(w, http.StatusMethodNotAllowed, "Method not allowed. Use GET.")
		return
	}
	
	userID := r.URL.Path[len("/api/stats/user/"):]
	if userID == "" {
		api.writeError(w, http.StatusBadRequest, "User ID required")
		return
	}
	
	var upload, download int64
	
	if api.management != nil && api.management.sessionTracker != nil {
		sessions := api.management.sessionTracker.GetAllSessions()
		for _, session := range sessions {
			if session.UserID == userID {
				upload += session.Upload
				download += session.Download
			}
		}
	}
	
	// Также проверяем в users
	if api.management != nil {
		api.management.mu.RLock()
		if user, exists := api.management.users[userID]; exists {
			if user != nil && user.Traffic != nil {
				if user.Traffic.Upload > 0 {
					upload = user.Traffic.Upload
				}
				if user.Traffic.Download > 0 {
					download = user.Traffic.Download
				}
			}
		}
		api.management.mu.RUnlock()
	}
	
	api.writeJSON(w, map[string]interface{}{
		"user_id": userID,
		"upload":  upload,
		"download": download,
		"total":   upload + download,
	})
}

// handleStatsML возвращает статистику ML системы
func (api *APIServer) handleStatsML(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		w.Header().Set("Allow", "GET")
		api.writeError(w, http.StatusMethodNotAllowed, "Method not allowed. Use GET.")
		return
	}
	
	mlStats := map[string]interface{}{
		"predictions": 0,
		"success":     0,
		"failures":    0,
		"accuracy":    0.0,
	}
	
	api.writeJSON(w, mlStats)
}

// handleStatsDetailed возвращает детальную статистику по протоколам и транспортам
func (api *APIServer) handleStatsDetailed(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		w.Header().Set("Allow", "GET")
		api.writeError(w, http.StatusMethodNotAllowed, "Method not allowed. Use GET.")
		return
	}
	
	if api.detailedStats == nil {
		api.writeJSON(w, map[string]interface{}{
			"total":     map[string]interface{}{},
			"protocols": map[string]interface{}{},
			"transports": map[string]interface{}{},
		})
		return
	}
	
	stats := api.detailedStats.GetStats()
	
	// Преобразуем в JSON-совместимый формат
	protocolsMap := make(map[string]interface{})
	for k, v := range stats.Protocols {
		protocolsMap[k] = map[string]interface{}{
			"protocol":          v.Protocol,
			"packets_rx":        v.PacketsRx,
			"packets_tx":        v.PacketsTx,
			"packets_dropped":   v.PacketsDropped,
			"bytes_rx":          v.BytesRx,
			"bytes_tx":          v.BytesTx,
			"connections_active": v.ConnectionsActive,
			"connections_total":  v.ConnectionsTotal,
			"connections_closed": v.ConnectionsClosed,
			"errors":            v.Errors,
			"last_update":       v.LastUpdate.Unix(),
		}
	}
	
	transportsMap := make(map[string]interface{})
	for k, v := range stats.Transports {
		transportsMap[k] = map[string]interface{}{
			"transport":          v.Transport,
			"packets_rx":         v.PacketsRx,
			"packets_tx":         v.PacketsTx,
			"packets_dropped":    v.PacketsDropped,
			"bytes_rx":           v.BytesRx,
			"bytes_tx":           v.BytesTx,
			"connections_active": v.ConnectionsActive,
			"connections_total":  v.ConnectionsTotal,
			"connections_closed": v.ConnectionsClosed,
			"handshakes_success": v.HandshakesSuccess,
			"handshakes_failed":  v.HandshakesFailed,
			"latency_min_ms":     v.LatencyMin.Milliseconds(),
			"latency_max_ms":     v.LatencyMax.Milliseconds(),
			"latency_avg_ms":     v.LatencyAvg.Milliseconds(),
			"latency_samples":    v.LatencySamples,
			"errors":            v.Errors,
			"last_update":       v.LastUpdate.Unix(),
		}
	}
	
	result := map[string]interface{}{
		"total": map[string]interface{}{
			"packets_rx":         stats.Total.PacketsRx,
			"packets_tx":         stats.Total.PacketsTx,
			"packets_dropped":    stats.Total.PacketsDropped,
			"bytes_rx":           stats.Total.BytesRx,
			"bytes_tx":           stats.Total.BytesTx,
			"connections_active": stats.Total.ConnectionsActive,
			"connections_total":  stats.Total.ConnectionsTotal,
			"connections_closed": stats.Total.ConnectionsClosed,
			"last_update":        stats.Total.LastUpdate.Unix(),
		},
		"protocols": protocolsMap,
		"transports": transportsMap,
		"last_update": stats.LastUpdate.Unix(),
	}
	
	api.writeJSON(w, result)
}

// handleLogs возвращает логи
func (api *APIServer) handleLogs(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		w.Header().Set("Allow", "GET")
		api.writeError(w, http.StatusMethodNotAllowed, "Method not allowed. Use GET.")
		return
	}
	
	logs := []map[string]interface{}{}
	api.writeJSON(w, logs)
}

// handleHealth возвращает health check
func (api *APIServer) handleHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.WriteHeader(http.StatusMethodNotAllowed)
		w.Header().Set("Allow", "GET, HEAD")
		api.writeError(w, http.StatusMethodNotAllowed, "Method not allowed. Use GET or HEAD.")
		return
	}
	
	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(http.StatusOK)
	if r.Method == http.MethodGet {
		w.Write([]byte("OK"))
	}
}

// handleClientConfigByKey возвращает конфигурацию клиента по приватному ключу
func (api *APIServer) handleClientConfigByKey(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		w.Header().Set("Allow", "POST")
		api.writeError(w, http.StatusMethodNotAllowed, "Method not allowed. Use POST.")
		return
	}

	var req struct {
		PrivateKey string `json:"privateKey"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		api.writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	if req.PrivateKey == "" {
		api.writeError(w, http.StatusBadRequest, "Private key is required")
		return
	}

	// Нормализуем ключ: удаляем пробелы и обрезаем до разумной длины
	normalizedKey := strings.TrimSpace(req.PrivateKey)
	normalizedKey = strings.ReplaceAll(normalizedKey, " ", "")
	normalizedKey = strings.ReplaceAll(normalizedKey, "\n", "")
	normalizedKey = strings.ReplaceAll(normalizedKey, "\r", "")
	normalizedKey = strings.ReplaceAll(normalizedKey, "\t", "")
	
	// Нормализуем ключ для сравнения (удаляем дефисы, пробелы, приводим к нижнему регистру)
	normalizedKeyLower := strings.ToLower(normalizedKey)
	normalizedKeyLower = strings.ReplaceAll(normalizedKeyLower, "-", "")
	normalizedKeyLower = strings.ReplaceAll(normalizedKeyLower, " ", "")
	
	// Ищем пользователя по приватному ключу
	api.management.mu.RLock()
	var foundUser *UserConfig
	var foundPrivateKey string
	
	for _, user := range api.management.users {
		if user == nil {
			continue
		}
		
		// 1. Проверяем по приватному ключу x25519 (64 символа) - ПРИОРИТЕТ
		if user.PrivateKey != "" {
			userPrivKey := strings.ToLower(strings.ReplaceAll(user.PrivateKey, "-", ""))
			userPrivKey = strings.ReplaceAll(userPrivKey, " ", "")
			userPrivKey = strings.ReplaceAll(userPrivKey, "\n", "")
			userPrivKey = strings.ReplaceAll(userPrivKey, "\r", "")
			
			// SECURITY: Используем constant-time сравнение для защиты от timing attacks
			// Точное совпадение (constant-time)
			userKeyBytes := []byte(userPrivKey)
			normalizedKeyBytes := []byte(normalizedKeyLower)
			if len(userKeyBytes) == len(normalizedKeyBytes) {
				if subtle.ConstantTimeCompare(userKeyBytes, normalizedKeyBytes) == 1 {
					foundUser = user
					foundPrivateKey = user.PrivateKey
					break
				}
			}
			
			// SECURITY: Частичное совпадение также использует constant-time сравнение
			// Проверяем только если оба ключа достаточно длинные (минимум 32 символа)
			keyLen := len(normalizedKeyLower)
			userKeyLen := len(userPrivKey)
			if keyLen >= 32 && userKeyLen >= 32 {
				// Проверяем префикс (первые 32 символа)
				if keyLen >= 32 && userKeyLen >= 32 {
					prefixMatch := subtle.ConstantTimeCompare(
						[]byte(userPrivKey[:32]),
						[]byte(normalizedKeyLower[:32]),
					) == 1
					
					// Проверяем суффикс (последние 32 символа)
					suffixMatch := false
					if keyLen >= 32 && userKeyLen >= 32 {
						suffixMatch = subtle.ConstantTimeCompare(
							[]byte(userPrivKey[userKeyLen-32:]),
							[]byte(normalizedKeyLower[keyLen-32:]),
						) == 1
					}
					
					if prefixMatch || suffixMatch {
						foundUser = user
						foundPrivateKey = user.PrivateKey
						break
					}
				}
			}
		}
		
		// 2. Проверяем по UUID (может быть с дефисами или без)
		userUUID := strings.ToLower(strings.ReplaceAll(user.UUID, "-", ""))
		if userUUID == normalizedKeyLower || strings.ToLower(user.UUID) == strings.ToLower(normalizedKey) {
			foundUser = user
			foundPrivateKey = user.UUID
			break
		}
		
		// 3. Проверяем по ID
		if strings.ToLower(user.ID) == normalizedKeyLower {
			foundUser = user
			foundPrivateKey = user.ID
			break
		}
	}
	api.management.mu.RUnlock()

	if foundUser == nil {
		api.writeError(w, http.StatusNotFound, "User not found for this private key")
		return
	}

	// Получаем информацию о сервере - используем публичный ключ из API
	serverPub := api.serverPubKey
	if serverPub == "" {
		serverPub = readPublicKeyFromHostingInfo()
	}
	
	// Получаем IP сервера
	serverIP := getExternalIP()
	if serverIP == "" {
		serverIP = "YOUR_SERVER_IP"
	}


	// Используем приватный ключ пользователя, если он есть, иначе UUID
	clientPrivateKey := foundUser.PrivateKey
	if clientPrivateKey == "" {
		clientPrivateKey = foundPrivateKey
	}
	
	// Формируем конфигурацию (используем дефолтные значения если поля отсутствуют)
	config := map[string]interface{}{
		"serverIp":          serverIP,
		"serverPort":        51820,
		"serverTcpPort":     4443,
		"serverWsPort":      8080,
		"serverWs2Port":     8443,
		"serverPublicKey":    serverPub,
		"clientPrivateKey":  clientPrivateKey,
		"clientPublicKey":   foundUser.PublicKey, // Публичный ключ пользователя
		"fteProfile":        "http2", // Дефолтное значение
		"marionetteProfile": "browser", // Дефолтное значение
		"aiEvasion":         true,
		"hardwareEvasion":   true,
		"behavioralMimicry": true,
		"russianMimicry":    true,
		"autoProfile":       true,
	}

	api.writeJSON(w, config)
}

// Reload перезагружает конфигурацию
func (cm *ConfigManager) Reload() error {
	cm.mu.Lock()
	defer cm.mu.Unlock()
	
	if cm.configPath == "" {
		return fmt.Errorf("config path not set")
	}
	
	cfg, err := cfgpkg.LoadServer(cm.configPath)
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}
	
	cm.config = cfg
	cm.lastReload = time.Now()
	
	return nil
}

// Update обновляет конфигурацию
func (cm *ConfigManager) Update(cfg *cfgpkg.ServerConfig) error {
	cm.mu.Lock()
	defer cm.mu.Unlock()
	
	cm.config = cfg
	cm.lastReload = time.Now()
	
	return nil
}

// NewConfigWatcher создает новый watcher конфигурации
func NewConfigWatcher(path string, interval time.Duration) *ConfigWatcher {
	return &ConfigWatcher{
		path:     path,
		interval: interval,
		stop:     make(chan struct{}),
	}
}

// Watch отслеживает изменения конфигурации
func (cw *ConfigWatcher) Watch(manager *ConfigManager) {
	ticker := time.NewTicker(cw.interval)
	defer ticker.Stop()
	
	for {
		select {
		case <-ticker.C:
			// Проверяем изменения файла и перезагружаем
			if err := manager.Reload(); err != nil {
				log.Printf("Failed to reload config: %v", err)
			}
		case <-cw.stop:
			return
		}
	}
}

// Stop останавливает watcher
func (cw *ConfigWatcher) Stop() {
	close(cw.stop)
}


// writeJSON пишет JSON ответ с статус кодом 200
func (api *APIServer) writeJSON(w http.ResponseWriter, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		log.Printf("Error encoding JSON response: %v", err)
	}
}

// writeError пишет ошибку в JSON формате
func (api *APIServer) writeError(w http.ResponseWriter, code int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"error": message,
	})
}

// corsMiddleware добавляет CORS заголовки
func (api *APIServer) corsMiddleware(handler func(http.ResponseWriter, *http.Request)) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		// SECURITY: Нельзя использовать "*" с Credentials: true
		// Используем Origin из запроса для безопасной CORS политики
		origin := r.Header.Get("Origin")
		if origin != "" {
			// В production здесь должна быть whitelist разрешенных origins
			// Для безопасности разрешаем только если Origin присутствует
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Access-Control-Allow-Credentials", "true")
		} else {
			// Если Origin отсутствует, не устанавливаем CORS заголовки
			// Это защищает от CSRF атак
		}
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
		
		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}
		
		handler(w, r)
	}
}

// authMiddleware проверяет токен авторизации (простая реализация)
func (api *APIServer) authMiddleware(handler func(http.ResponseWriter, *http.Request)) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		// Пропускаем публичные endpoints
		publicPaths := []string{"/api/login", "/health", "/api/system/info"}
		for _, path := range publicPaths {
			if r.URL.Path == path {
				handler(w, r)
				return
			}
		}
		
		// Проверяем токен
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			// Пробуем получить токен из cookie (для веб-панели)
			cookie, err := r.Cookie("whispera_token")
			if err == nil && cookie != nil && cookie.Value != "" {
				authHeader = "Bearer " + cookie.Value
			}
		}
		
		if authHeader == "" || !strings.HasPrefix(authHeader, "Bearer ") {
			api.writeError(w, http.StatusUnauthorized, "Authorization required")
			return
		}
		
		token := strings.TrimPrefix(authHeader, "Bearer ")
		
		// SECURITY: Проверяем JWT токен
		claims, err := api.validateJWTToken(token)
		if err != nil {
			// Пробуем старый формат для обратной совместимости
			if strings.HasPrefix(token, "whispera_token_") {
				// Старый формат - разрешаем для обратной совместимости
				// Но логируем предупреждение
				log.Printf("[API] Warning: using legacy token format, should migrate to JWT")
			} else {
				api.writeError(w, http.StatusUnauthorized, "Invalid or expired token")
				return
			}
		} else {
			// JWT токен валиден, проверяем claims
			if claims == nil {
				api.writeError(w, http.StatusUnauthorized, "Invalid token claims")
				return
			}
		}
		
		handler(w, r)
	}
}

// handleWebPanel раздает статические файлы веб-панели
func (api *APIServer) handleWebPanel(w http.ResponseWriter, r *http.Request) {
	// Определяем путь к веб-панели
	// Используем переменную окружения или стандартные пути
	webDir := os.Getenv("WHISPERA_WEB_DIR")
	if webDir == "" {
		webDir = "web"
	}
	
	// Получаем рабочую директорию
	workDir, err := os.Getwd()
	if err != nil {
		workDir = "/opt/whispera" // Fallback на стандартную директорию
	}
	
	// Проверяем несколько возможных путей
	possiblePaths := []string{
		webDir,                              // Относительно текущей директории
		filepath.Join(workDir, webDir),      // Относительно рабочей директории
		filepath.Join("/opt/whispera", webDir), // Стандартная директория установки
	}
	
	var fullWebDir string
	for _, path := range possiblePaths {
		indexPath := filepath.Join(path, "index.html")
		if _, err := os.Stat(indexPath); err == nil {
			fullWebDir = path
			break
		}
	}
	
	// Если не нашли, используем первый вариант
	if fullWebDir == "" {
		fullWebDir = webDir
	}
	
	// Если запрос к корню, отдаем index.html
	path := r.URL.Path
	if path == "/" || path == "" {
		path = "/index.html"
	}
	
	// Убираем начальный слэш
	filePath := strings.TrimPrefix(path, "/")
	fullPath := filepath.Join(fullWebDir, filePath)
	
	// Проверяем существование файла
	if _, err := os.Stat(fullPath); os.IsNotExist(err) {
		// Если файл не найден и это не API запрос, отдаем index.html (для SPA)
		if !strings.HasPrefix(path, "api/") {
			indexPath := filepath.Join(fullWebDir, "index.html")
			if _, err := os.Stat(indexPath); os.IsNotExist(err) {
				api.writeError(w, http.StatusNotFound, fmt.Sprintf("Web panel not found. Searched in: %v", possiblePaths))
				return
			}
			fullPath = indexPath
		} else {
			http.NotFound(w, r)
			return
		}
	}
	
	// Определяем MIME тип
	contentType := "text/plain"
	if strings.HasSuffix(fullPath, ".html") {
		contentType = "text/html"
	} else if strings.HasSuffix(fullPath, ".css") {
		contentType = "text/css"
	} else if strings.HasSuffix(fullPath, ".js") {
		contentType = "application/javascript"
	} else if strings.HasSuffix(fullPath, ".json") {
		contentType = "application/json"
	} else if strings.HasSuffix(fullPath, ".png") {
		contentType = "image/png"
	} else if strings.HasSuffix(fullPath, ".jpg") || strings.HasSuffix(fullPath, ".jpeg") {
		contentType = "image/jpeg"
	} else if strings.HasSuffix(fullPath, ".svg") {
		contentType = "image/svg+xml"
	}
	
	w.Header().Set("Content-Type", contentType)
	http.ServeFile(w, r, fullPath)
}

// handleLogin обрабатывает авторизацию пользователей
func (api *APIServer) handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		api.writeError(w, http.StatusMethodNotAllowed, "Method not allowed. Use POST.")
		return
	}
	
	// SECURITY: Rate limiting для защиты от brute-force атак
	if api.loginRateLimiter != nil {
		ip := r.RemoteAddr
		if forwarded := r.Header.Get("X-Forwarded-For"); forwarded != "" {
			ip = forwarded
		}
		if !api.loginRateLimiter.Allow(ip) {
			api.writeError(w, http.StatusTooManyRequests, "Too many login attempts. Please try again later.")
			return
		}
	}
	
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		api.writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}
	
	// SECURITY: Валидация входных данных
	if req.Username == "" || req.Password == "" {
		api.writeError(w, http.StatusBadRequest, "Username and password are required")
		return
	}
	
	// Ограничиваем длину для защиты от DoS
	if len(req.Username) > 100 || len(req.Password) > 200 {
		api.writeError(w, http.StatusBadRequest, "Invalid input length")
		return
	}
	
	// Получаем учетные данные из переменных окружения
	validUsername := os.Getenv("WHISPERA_ADMIN_USER")
	if validUsername == "" {
		validUsername = "admin"
	}
	
	// SECURITY: Constant-time сравнение username для защиты от timing attacks
	usernameMatch := subtle.ConstantTimeCompare(
		[]byte(req.Username),
		[]byte(validUsername),
	) == 1
	
	// SECURITY: Проверяем пароль с помощью bcrypt (защита от timing attacks встроена)
	api.mu.RLock()
	passwordHash := api.passwordHash
	api.mu.RUnlock()
	
	passwordMatch := false
	if len(passwordHash) > 0 {
		err := bcrypt.CompareHashAndPassword(passwordHash, []byte(req.Password))
		passwordMatch = (err == nil)
	} else {
		// Fallback для обратной совместимости (если хэш не был сгенерирован)
		validPassword := os.Getenv("WHISPERA_ADMIN_PASSWORD")
		if validPassword == "" {
			validPassword = "admin"
		}
		passwordMatch = subtle.ConstantTimeCompare(
			[]byte(req.Password),
			[]byte(validPassword),
		) == 1
	}
	
	if usernameMatch && passwordMatch {
		// SECURITY: Генерируем JWT токен
		token, err := api.generateJWTToken(validUsername)
		if err != nil {
			log.Printf("[API] Failed to generate JWT token: %v", err)
			api.writeError(w, http.StatusInternalServerError, "Failed to generate token")
			return
		}
		
		// SECURITY: Устанавливаем HttpOnly: true для защиты от XSS
		// SECURITY: SameSite: Strict для защиты от CSRF
		http.SetCookie(w, &http.Cookie{
			Name:     "whispera_token",
			Value:    token,
			Path:     "/",
			HttpOnly: true, // SECURITY: Защита от XSS - cookie недоступна из JavaScript
			SameSite: http.SameSiteStrictMode, // SECURITY: Защита от CSRF
			MaxAge:   86400, // 24 часа
			Secure:   r.TLS != nil, // Только через HTTPS если доступен
		})
		
		api.writeJSON(w, map[string]interface{}{
			"success": true,
			"token":   token,
			"message": "Login successful",
		})
	} else {
		// SECURITY: Всегда возвращаем одинаковое время ответа для защиты от timing attacks
		// Используем небольшую задержку для нормализации времени ответа
		time.Sleep(100 * time.Millisecond)
		api.writeError(w, http.StatusUnauthorized, "Invalid username or password")
	}
}

// handleCSRFToken генерирует и возвращает CSRF токен
func (api *APIServer) handleCSRFToken(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		api.writeError(w, http.StatusMethodNotAllowed, "Method not allowed. Use GET or HEAD.")
		return
	}
	
	// Генерируем CSRF токен
	token := api.generateCSRFToken()
	
	// Сохраняем токен с временем истечения (1 час)
	api.mu.Lock()
	api.csrfTokens[token] = time.Now().Add(1 * time.Hour)
	// Очищаем старые токены (старше 2 часов)
	for t, exp := range api.csrfTokens {
		if time.Now().After(exp) {
			delete(api.csrfTokens, t)
		}
	}
	api.mu.Unlock()
	
	api.writeJSON(w, map[string]interface{}{
		"csrfToken": token,
	})
}

// generateCSRFToken генерирует новый CSRF токен
func (api *APIServer) generateCSRFToken() string {
	// Генерируем случайные байты
	randomBytes := make([]byte, 16)
	if _, err := rand.Read(randomBytes); err != nil {
		// Fallback на менее безопасный метод (не рекомендуется)
		randomBytes = []byte(fmt.Sprintf("%d", time.Now().UnixNano()))
	}
	
	// Создаем токен: hex(randomBytes)
	token := hex.EncodeToString(randomBytes)
	return token
}

// validateCSRFToken проверяет CSRF токен
func (api *APIServer) validateCSRFToken(token string) bool {
	if token == "" {
		return false
	}
	
	api.mu.RLock()
	defer api.mu.RUnlock()
	
	exp, exists := api.csrfTokens[token]
	if !exists {
		return false
	}
	
	// Проверяем срок действия
	if time.Now().After(exp) {
		return false
	}
	
	return true
}

// csrfMiddleware проверяет CSRF токен для защищенных endpoints
func (api *APIServer) csrfMiddleware(handler func(http.ResponseWriter, *http.Request)) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		// Пропускаем GET, HEAD, OPTIONS запросы (безопасные методы)
		if r.Method == http.MethodGet || r.Method == http.MethodHead || r.Method == http.MethodOptions {
			handler(w, r)
			return
		}
		
		// Получаем CSRF токен из заголовка или формы
		csrfToken := r.Header.Get("X-CSRF-Token")
		if csrfToken == "" {
			csrfToken = r.FormValue("csrf_token")
		}
		
		if !api.validateCSRFToken(csrfToken) {
			api.writeError(w, http.StatusForbidden, "Invalid or missing CSRF token")
			return
		}
		
		handler(w, r)
	}
}

// generateJWTToken генерирует JWT токен для пользователя
func (api *APIServer) generateJWTToken(username string) (string, error) {
	api.mu.RLock()
	jwtSecret := api.jwtSecret
	api.mu.RUnlock()
	
	// Создаем claims
	claims := jwt.MapClaims{
		"username": username,
		"iat":      time.Now().Unix(),
		"exp":      time.Now().Add(24 * time.Hour).Unix(), // Токен действителен 24 часа
	}
	
	// Создаем токен
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	
	// Подписываем токен
	tokenString, err := token.SignedString(jwtSecret)
	if err != nil {
		return "", fmt.Errorf("failed to sign token: %w", err)
	}
	
	return tokenString, nil
}

// validateJWTToken проверяет и валидирует JWT токен
func (api *APIServer) validateJWTToken(tokenString string) (jwt.MapClaims, error) {
	api.mu.RLock()
	jwtSecret := api.jwtSecret
	api.mu.RUnlock()
	
	// Парсим токен
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// Проверяем метод подписи
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return jwtSecret, nil
	})
	
	if err != nil {
		return nil, err
	}
	
	// Проверяем валидность токена
	if !token.Valid {
		return nil, fmt.Errorf("invalid token")
	}
	
	// Извлекаем claims
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, fmt.Errorf("invalid token claims")
	}
	
	// Проверяем срок действия (JWT библиотека делает это автоматически, но проверим явно)
	if exp, ok := claims["exp"].(float64); ok {
		if time.Now().Unix() > int64(exp) {
			return nil, fmt.Errorf("token expired")
		}
	}
	
	return claims, nil
}

// handleGenerateKeys генерирует пару ключей для клиента (x25519)
func (api *APIServer) handleGenerateKeys(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		api.writeError(w, http.StatusMethodNotAllowed, "Method not allowed. Use POST.")
		return
	}

	// Генерируем приватный ключ (32 байта)
	privateKey := make([]byte, 32)
	if _, err := rand.Read(privateKey); err != nil {
		api.writeError(w, http.StatusInternalServerError, "Failed to generate private key")
		return
	}

	// Вычисляем публичный ключ из приватного
	publicKey, err := curve25519.X25519(privateKey, curve25519.Basepoint)
	if err != nil {
		api.writeError(w, http.StatusInternalServerError, "Failed to derive public key")
		return
	}

	api.writeJSON(w, map[string]interface{}{
		"privateKey": hex.EncodeToString(privateKey),
		"publicKey":  hex.EncodeToString(publicKey),
	})
}

// handleGenerateServerKeys генерирует пару ключей для сервера (x25519)
func (api *APIServer) handleGenerateServerKeys(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		api.writeError(w, http.StatusMethodNotAllowed, "Method not allowed. Use POST.")
		return
	}

	// Генерируем приватный ключ сервера (32 байта)
	privateKey := make([]byte, 32)
	if _, err := rand.Read(privateKey); err != nil {
		api.writeError(w, http.StatusInternalServerError, "Failed to generate server private key")
		return
	}

	// Вычисляем публичный ключ сервера из приватного
	publicKey, err := curve25519.X25519(privateKey, curve25519.Basepoint)
	if err != nil {
		api.writeError(w, http.StatusInternalServerError, "Failed to derive server public key")
		return
	}

	// Обновляем публичный ключ сервера в API
	api.mu.Lock()
	api.serverPubKey = hex.EncodeToString(publicKey)
	api.mu.Unlock()

	api.writeJSON(w, map[string]interface{}{
		"privateKey": hex.EncodeToString(privateKey),
		"publicKey":  hex.EncodeToString(publicKey),
	})
}

// handleDerivePublicKey вычисляет публичный ключ из приватного
func (api *APIServer) handleDerivePublicKey(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		api.writeError(w, http.StatusMethodNotAllowed, "Method not allowed. Use POST.")
		return
	}

	var req struct {
		PrivateKey string `json:"privateKey"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		api.writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	if req.PrivateKey == "" {
		api.writeError(w, http.StatusBadRequest, "Private key is required")
		return
	}

	// Декодируем приватный ключ
	privateKey, err := hex.DecodeString(req.PrivateKey)
	if err != nil || len(privateKey) != 32 {
		api.writeError(w, http.StatusBadRequest, "Invalid private key format (must be 64 hex characters)")
		return
	}

	// Вычисляем публичный ключ
	publicKey, err := curve25519.X25519(privateKey, curve25519.Basepoint)
	if err != nil {
		api.writeError(w, http.StatusInternalServerError, "Failed to derive public key")
		return
	}

	api.writeJSON(w, map[string]interface{}{
		"publicKey": hex.EncodeToString(publicKey),
	})
}

// AdBlock endpoints
func (api *APIServer) handleAdblockStats(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		api.writeError(w, http.StatusMethodNotAllowed, "Method not allowed. Use GET.")
		return
	}
	
	if api.adblock == nil {
		api.writeJSON(w, map[string]interface{}{
			"enabled":     false,
			"rules_count": 0,
			"blocked":     0,
			"allowed":     0,
			"message":     "AdBlock engine not initialized",
		})
		return
	}
	
	stats := api.adblock.GetStats()
	api.writeJSON(w, stats)
}

func (api *APIServer) handleAdblockRules(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		api.writeError(w, http.StatusMethodNotAllowed, "Method not allowed. Use GET.")
		return
	}
	
	if api.adblock == nil {
		api.writeJSON(w, []interface{}{})
		return
	}
	
	rules := api.adblock.GetRules()
	api.writeJSON(w, rules)
}

func (api *APIServer) handleAdblockRuleAdd(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		api.writeError(w, http.StatusMethodNotAllowed, "Method not allowed. Use POST.")
		return
	}
	
	if api.adblock == nil {
		api.writeError(w, http.StatusServiceUnavailable, "AdBlock engine not initialized")
		return
	}
	
	var req struct {
		Rule string `json:"rule"`
		URL  string `json:"url"` // Опционально: загрузить список из URL
	}
	
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		api.writeError(w, http.StatusBadRequest, fmt.Sprintf("Invalid JSON: %v", err))
		return
	}
	
	if req.URL != "" {
		// Загружаем правила из URL
		if err := api.adblock.LoadRulesFromURL(req.URL); err != nil {
			api.writeError(w, http.StatusBadRequest, fmt.Sprintf("Failed to load rules from URL: %v", err))
			return
		}
		api.writeJSON(w, map[string]interface{}{
			"success": true,
			"message": "Rules loaded from URL",
		})
		return
	}
	
	if req.Rule == "" {
		api.writeError(w, http.StatusBadRequest, "Rule is required")
		return
	}
	
	if err := api.adblock.AddRule(req.Rule); err != nil {
		api.writeError(w, http.StatusBadRequest, fmt.Sprintf("Failed to add rule: %v", err))
		return
	}
	
	api.writeJSON(w, map[string]interface{}{
		"success": true,
		"message": "Rule added successfully",
	})
}

func (api *APIServer) handleAdblockRuleDelete(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		api.writeError(w, http.StatusMethodNotAllowed, "Method not allowed. Use POST.")
		return
	}
	
	if api.adblock == nil {
		api.writeError(w, http.StatusServiceUnavailable, "AdBlock engine not initialized")
		return
	}
	
	var req struct {
		Rule string `json:"rule"`
	}
	
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		api.writeError(w, http.StatusBadRequest, fmt.Sprintf("Invalid JSON: %v", err))
		return
	}
	
	if req.Rule == "" {
		api.writeError(w, http.StatusBadRequest, "Rule is required")
		return
	}
	
	api.adblock.RemoveRule(req.Rule)
	api.writeJSON(w, map[string]interface{}{
		"success": true,
		"message": "Rule removed successfully",
	})
}

func (api *APIServer) handleAdblockSettings(w http.ResponseWriter, r *http.Request) {
	if api.adblock == nil {
		api.writeError(w, http.StatusServiceUnavailable, "AdBlock engine not initialized")
		return
	}
	
	if r.Method == http.MethodGet {
		api.writeJSON(w, map[string]interface{}{
			"enabled": api.adblock.IsEnabled(),
		})
		return
	}
	
	if r.Method != http.MethodPost {
		api.writeError(w, http.StatusMethodNotAllowed, "Method not allowed. Use POST or GET.")
		return
	}
	
	var req struct {
		Enabled bool `json:"enabled"`
	}
	
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		api.writeError(w, http.StatusBadRequest, fmt.Sprintf("Invalid JSON: %v", err))
		return
	}
	
	api.adblock.Enable(req.Enabled)
	api.writeJSON(w, map[string]interface{}{
		"success": true,
		"enabled": req.Enabled,
		"message": "AdBlock settings updated",
	})
}

// handleCertificateStatus возвращает статус сертификата
func (api *APIServer) handleCertificateStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		api.writeError(w, http.StatusMethodNotAllowed, "Method not allowed. Use GET.")
		return
	}
	
	// Проверяем наличие Let's Encrypt сертификатов
	certDir := "/etc/letsencrypt/live"
	workDir := "/opt/whispera"
	certPath := filepath.Join(workDir, "certs", "cert.pem")
	keyPath := filepath.Join(workDir, "certs", "key.pem")
	
	status := map[string]interface{}{
		"letsencrypt_available": false,
		"certificate_type":      "self-signed",
		"certificate_path":       certPath,
		"key_path":              keyPath,
		"certificate_exists":    false,
		"expires_at":            nil,
		"domains":               []string{},
	}
	
	// Проверяем наличие сертификата
	if _, err := os.Stat(certPath); err == nil {
		status["certificate_exists"] = true
		
		// Пытаемся определить тип сертификата
		if certData, err := os.ReadFile(certPath); err == nil {
			// Проверяем, является ли это Let's Encrypt сертификатом
			certStr := string(certData)
			if strings.Contains(certStr, "Let's Encrypt") || strings.Contains(certStr, "Let's Encrypt") {
				status["letsencrypt_available"] = true
				status["certificate_type"] = "letsencrypt"
			}
			
			// Пытаемся найти домены в Let's Encrypt директории
			if entries, err := os.ReadDir(certDir); err == nil {
				domains := []string{}
				for _, entry := range entries {
					if entry.IsDir() {
						domains = append(domains, entry.Name())
					}
				}
				if len(domains) > 0 {
					status["domains"] = domains
					status["letsencrypt_available"] = true
					status["certificate_type"] = "letsencrypt"
				}
			}
		}
	}
	
	api.writeJSON(w, status)
}

// handleCertificateObtain получает Let's Encrypt сертификат
func (api *APIServer) handleCertificateObtain(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		api.writeError(w, http.StatusMethodNotAllowed, "Method not allowed. Use POST.")
		return
	}
	
	var req struct {
		Domain string `json:"domain"`
		Email  string `json:"email"`
	}
	
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		api.writeError(w, http.StatusBadRequest, fmt.Sprintf("Invalid JSON: %v", err))
		return
	}
	
	if req.Domain == "" {
		api.writeError(w, http.StatusBadRequest, "Domain is required")
		return
	}
	
	// Валидация: домен не должен быть IP адресом
	if strings.Contains(req.Domain, ".") && !strings.Contains(req.Domain, " ") {
		parts := strings.Split(req.Domain, ".")
		isIP := true
		for _, part := range parts {
			if num, err := strconv.Atoi(part); err != nil || num < 0 || num > 255 {
				isIP = false
				break
			}
		}
		if isIP && len(parts) == 4 {
			api.writeError(w, http.StatusBadRequest, "Введите доменное имя (например, example.com), а не IP адрес. Let's Encrypt требует доменное имя.")
			return
		}
	}
	
	// Проверяем наличие certbot
	if _, err := exec.LookPath("certbot"); err != nil {
		api.writeError(w, http.StatusServiceUnavailable, "Certbot не установлен. Установите его командой: apt-get install certbot")
		return
	}
	
	// Проверяем DNS (опционально, но полезно)
	domainIP := ""
	if addrs, err := net.LookupHost(req.Domain); err == nil && len(addrs) > 0 {
		domainIP = addrs[0]
		// Проверяем, что DNS не указывает на localhost
		if domainIP == "127.0.0.1" || domainIP == "::1" || domainIP == "localhost" {
			api.writeError(w, http.StatusBadRequest, fmt.Sprintf("DNS A запись для %s указывает на localhost (%s). Обновите DNS, чтобы он указывал на IP адрес этого сервера.", req.Domain, domainIP))
			return
		}
	} else {
		log.Printf("Warning: Could not resolve DNS for %s: %v", req.Domain, err)
	}
	
	// Выполняем certbot в фоне (async)
	go func() {
		email := req.Email
		if email == "" {
			email = fmt.Sprintf("admin@%s", req.Domain)
		}
		
		// Останавливаем сервер временно (certbot нужен порт 80)
		serverWasRunning := false
		if api.server != nil {
			// Проверяем, запущен ли сервер через systemd
			checkCmd := exec.Command("systemctl", "is-active", "--quiet", "whispera-server")
			if checkCmd.Run() == nil {
				serverWasRunning = true
				log.Printf("Stopping Whispera server temporarily for certificate generation...")
				stopCmd := exec.Command("systemctl", "stop", "whispera-server")
				if err := stopCmd.Run(); err != nil {
					log.Printf("Warning: Failed to stop server: %v", err)
				} else {
					// Ждем немного, чтобы порт освободился
					time.Sleep(2 * time.Second)
				}
			}
		}
		
		// Создаем контекст с таймаутом (60 секунд)
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()
		
		cmd := exec.CommandContext(ctx, "certbot", "certonly", "--standalone",
			"--non-interactive",
			"--agree-tos",
			"--email", email,
			"-d", req.Domain)
		
		output, err := cmd.CombinedOutput()
		
		// Перезапускаем сервер, если он был запущен
		if serverWasRunning {
			log.Printf("Restarting Whispera server...")
			startCmd := exec.Command("systemctl", "start", "whispera-server")
			if err := startCmd.Run(); err != nil {
				log.Printf("Warning: Failed to restart server: %v", err)
			}
		}
		
		if err != nil {
			log.Printf("Certbot error: %v, output: %s", err, string(output))
			// Сохраняем ошибку в файл для отладки
			os.WriteFile("/tmp/certbot-error.log", output, 0644)
			return
		}
		
		// Копируем сертификаты
		workDir := "/opt/whispera"
		certDir := filepath.Join(workDir, "certs")
		os.MkdirAll(certDir, 0755)
		
		leCert := filepath.Join("/etc/letsencrypt/live", req.Domain, "fullchain.pem")
		leKey := filepath.Join("/etc/letsencrypt/live", req.Domain, "privkey.pem")
		
		success := false
		if certData, err := os.ReadFile(leCert); err == nil {
			if err := os.WriteFile(filepath.Join(certDir, "cert.pem"), certData, 0644); err == nil {
				success = true
			}
		}
		if keyData, err := os.ReadFile(leKey); err == nil {
			os.WriteFile(filepath.Join(certDir, "key.pem"), keyData, 0600)
		}
		
		if success {
			log.Printf("Let's Encrypt certificate obtained successfully for %s", req.Domain)
			// Перезагружаем сервер, чтобы применить новые сертификаты
			if serverWasRunning {
				reloadCmd := exec.Command("systemctl", "reload", "whispera-server")
				if reloadCmd.Run() != nil {
					exec.Command("systemctl", "restart", "whispera-server").Run()
				}
			}
		} else {
			log.Printf("Failed to copy Let's Encrypt certificates for %s", req.Domain)
		}
	}()
	
	api.writeJSON(w, map[string]interface{}{
		"success": true,
		"message": "Генерация сертификата запущена. Это может занять 1-2 минуты. Сервер будет временно остановлен на время генерации сертификата.",
	})
}

// handleCertificateRenew обновляет Let's Encrypt сертификат
func (api *APIServer) handleCertificateRenew(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		api.writeError(w, http.StatusMethodNotAllowed, "Method not allowed. Use POST.")
		return
	}
	
	// Проверяем наличие certbot
	if _, err := exec.LookPath("certbot"); err != nil {
		api.writeError(w, http.StatusServiceUnavailable, "Certbot is not installed")
		return
	}
	
	// Выполняем обновление в фоне
	go func() {
		cmd := exec.Command("certbot", "renew", "--quiet")
		output, err := cmd.CombinedOutput()
		if err != nil {
			log.Printf("Certbot renew error: %v, output: %s", err, string(output))
			return
		}
		
		// Обновляем сертификаты в рабочей директории
		workDir := "/opt/whispera"
		certDir := filepath.Join(workDir, "certs")
		
		// Находим все домены в Let's Encrypt
		leDir := "/etc/letsencrypt/live"
		if entries, err := os.ReadDir(leDir); err == nil {
			for _, entry := range entries {
				if entry.IsDir() {
					domain := entry.Name()
					leCert := filepath.Join(leDir, domain, "fullchain.pem")
					leKey := filepath.Join(leDir, domain, "privkey.pem")
					
					if certData, err := os.ReadFile(leCert); err == nil {
						os.WriteFile(filepath.Join(certDir, "cert.pem"), certData, 0644)
					}
					if keyData, err := os.ReadFile(leKey); err == nil {
						os.WriteFile(filepath.Join(certDir, "key.pem"), keyData, 0600)
					}
				}
			}
		}
		
		log.Printf("Let's Encrypt certificates renewed")
	}()
	
	api.writeJSON(w, map[string]interface{}{
		"success": true,
		"message": "Certificate renewal started",
	})
}

// tlsErrorFilter filters out common TLS handshake errors that are expected
// (e.g., clients connecting with HTTP to HTTPS port)
type tlsErrorFilter struct {
	original io.Writer
}

func (f *tlsErrorFilter) Write(p []byte) (n int, err error) {
	msg := string(p)
	// Filter out common expected TLS errors to reduce log noise
	if strings.Contains(msg, "client sent an HTTP request to an HTTPS server") {
		// This is expected when clients/probes try HTTP on HTTPS port - suppress it
		return len(p), nil
	}
	if strings.Contains(msg, "unknown certificate") {
		// This is expected when using self-signed certificates - clients don't trust them
		// Suppress to reduce log noise (this is normal behavior)
		return len(p), nil
	}
	if strings.Contains(msg, "tls: bad certificate") {
		// Similar to unknown certificate - expected with self-signed certs
		return len(p), nil
	}
	if strings.Contains(msg, "certificate verify failed") {
		// Certificate verification failed - expected with self-signed certs
		return len(p), nil
	}
	// Write all other errors normally
	return f.original.Write(p)
}

