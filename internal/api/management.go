package api

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
	
	"whispera/internal/firewall"
	"whispera/internal/policy"
	routingpkg "whispera/internal/routing"
)

// ManagementAPI - расширенный API управления как в xray/vless
type ManagementAPI struct {
	users          map[string]*UserConfig
	sessions       map[string]*Session
	sessionTracker *SessionTracker    // Трекер сессий сервера
	firewallEngine *firewall.FirewallEngine // Движок файрвола
	inbounds       map[string]*InboundConfig
	outbounds      map[string]*OutboundConfig
	routing        *RoutingManager
	firewall        *FirewallManager
	portMgr        *PortManager
	usersFilePath  string // Путь к файлу для сохранения пользователей
	routingEngine  *routingpkg.Engine // Routing engine для доступа к subscription manager
	
	// Policy management
	policyMgr          *policy.PolicyManager
	bandwidthEnforcer  *policy.BandwidthEnforcer
	connectionEnforcer *policy.ConnectionEnforcer
	timeBasedEnforcer  *policy.TimeBasedEnforcer
	
	mu             sync.RWMutex
}

// UserConfig - конфигурация пользователя
type UserConfig struct {
	ID          string    `json:"id"`
	UUID        string    `json:"uuid"`
	Email       string    `json:"email,omitempty"`
	Level       int       `json:"level"`
	AlterID     int       `json:"alterId,omitempty"`
	Flow        string    `json:"flow,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
	Enabled     bool      `json:"enabled"`
	Traffic     *UserTraffic `json:"traffic,omitempty"`
	PrivateKey  string    `json:"privateKey,omitempty"` // Приватный ключ x25519 для Quick Connect
	PublicKey   string    `json:"publicKey,omitempty"`  // Публичный ключ x25519
	IPAddresses []string  `json:"ipAddresses,omitempty"` // Список разрешенных IP адресов для этого пользователя
}

// UserTraffic - статистика трафика пользователя
type UserTraffic struct {
	Upload      int64     `json:"upload"`
	Download    int64     `json:"download"`
	Total       int64     `json:"total"`
	LastActive  time.Time `json:"last_active"`
	Connections int       `json:"connections"`
}

// Session - активная сессия пользователя
type Session struct {
	ID          string    `json:"id"`
	UserID      string    `json:"user_id"`
	RemoteAddr  string    `json:"remote_addr"`
	StartTime   time.Time `json:"start_time"`
	Upload      int64     `json:"upload"`
	Download    int64     `json:"download"`
	Packets     int64     `json:"packets"`
	LastActivity time.Time `json:"last_activity"`
}

// InboundConfig - конфигурация входящего подключения (как в xray)
type InboundConfig struct {
	Tag            string                 `json:"tag"`
	Port           int                    `json:"port"`
	Protocol       string                 `json:"protocol"` // "vmess", "vless", "shadowsocks", "trojan"
	Listen         string                 `json:"listen"`
	Settings       map[string]interface{} `json:"settings"`
	StreamSettings *StreamSettings        `json:"streamSettings,omitempty"`
	Sniffing       *SniffingConfig        `json:"sniffing,omitempty"`
	Enabled        bool                   `json:"enabled"`
}

// OutboundConfig - конфигурация исходящего подключения
type OutboundConfig struct {
	Tag            string                 `json:"tag"`
	Protocol       string                 `json:"protocol"`
	Settings       map[string]interface{} `json:"settings"`
	StreamSettings *StreamSettings        `json:"streamSettings,omitempty"`
	ProxySettings  *ProxySettings         `json:"proxySettings,omitempty"`
	Enabled        bool                   `json:"enabled"`
}

// StreamSettings - настройки потока (как в xray)
type StreamSettings struct {
	Network      string                 `json:"network"` // "tcp", "kcp", "ws", "http", "quic", "grpc"
	Security     string                 `json:"security"` // "none", "tls", "reality"
	TLSSettings  map[string]interface{} `json:"tlsSettings,omitempty"`
	TCPSettings  map[string]interface{} `json:"tcpSettings,omitempty"`
	WSSettings   map[string]interface{} `json:"wsSettings,omitempty"`
	HTTPSettings map[string]interface{} `json:"httpSettings,omitempty"`
	KCPSettings  map[string]interface{} `json:"kcpSettings,omitempty"`
	QUICSettings map[string]interface{} `json:"quicSettings,omitempty"`
	GRPCSettings map[string]interface{} `json:"grpcSettings,omitempty"`
}

// SniffingConfig - настройки sniffing
type SniffingConfig struct {
	Enabled      bool     `json:"enabled"`
	DestOverride []string `json:"destOverride"`
}

// ProxySettings - настройки прокси
type ProxySettings struct {
	Tag string `json:"tag"`
}

// RoutingManager - менеджер маршрутизации
type RoutingManager struct {
	Rules  []RoutingRule `json:"rules"`
	Domain string        `json:"domain"`
	IP     string        `json:"ip"`
	mu     sync.RWMutex
}

// GetRules возвращает копию правил (thread-safe)
func (rm *RoutingManager) GetRules() []RoutingRule {
	rm.mu.RLock()
	defer rm.mu.RUnlock()
	rules := make([]RoutingRule, len(rm.Rules))
	copy(rules, rm.Rules)
	return rules
}

// RoutingRule - правило маршрутизации
type RoutingRule struct {
	Type        string   `json:"type"`
	Domain      []string `json:"domain,omitempty"`
	IP          []string `json:"ip,omitempty"`
	Port        string   `json:"port,omitempty"`
	Network     string   `json:"network,omitempty"`
	Source      []string `json:"source,omitempty"`
	User        []string `json:"user,omitempty"`
	InboundTag  []string `json:"inboundTag,omitempty"`
	Protocol    []string `json:"protocol,omitempty"`
	Attrs       string   `json:"attrs,omitempty"`
	OutboundTag string   `json:"outboundTag"`
	BalancerTag string   `json:"balancerTag,omitempty"`
	Enabled     bool     `json:"enabled"`
}

// FirewallManager - менеджер файрвола
type FirewallManager struct {
	Rules []FirewallRule `json:"rules"`
	mu    sync.RWMutex
}

// FirewallRule - правило файрвола
type FirewallRule struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Action      string   `json:"action"` // "allow", "deny", "reject"
	Direction   string   `json:"direction"` // "inbound", "outbound", "both"
	Protocol    string   `json:"protocol"` // "tcp", "udp", "icmp", "all"
	Port        string   `json:"port,omitempty"` // "80", "443", "80,443", "1000-2000"
	SourceIP    []string `json:"source_ip,omitempty"`
	DestIP      []string `json:"dest_ip,omitempty"`
	Enabled     bool     `json:"enabled"`
	Priority    int      `json:"priority"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// PortManager - менеджер портов
type PortManager struct {
	Ports map[int]*PortInfo `json:"ports"`
	mu    sync.RWMutex
}

// PortInfo - информация о порте
type PortInfo struct {
	Port       int       `json:"port"`
	Protocol   string    `json:"protocol"` // "tcp", "udp", "tcp+udp"
	InboundTag string    `json:"inbound_tag,omitempty"`
	Enabled    bool      `json:"enabled"`
	Connections int      `json:"connections"`
	LastUsed   time.Time `json:"last_used"`
}

// NewManagementAPI создает новый API управления
func NewManagementAPI() *ManagementAPI {
	return NewManagementAPIWithStorage("")
}

// NewManagementAPIWithStorage создает новый API управления с указанным путем для сохранения пользователей
func NewManagementAPIWithStorage(usersFilePath string) *ManagementAPI {
	// Инициализируем систему политик
	policyMgr := policy.NewPolicyManager()
	bandwidthEnforcer := policy.NewBandwidthEnforcer(policyMgr)
	connectionEnforcer := policy.NewConnectionEnforcer(policyMgr)
	timeBasedEnforcer := policy.NewTimeBasedEnforcer(policyMgr)
	api := &ManagementAPI{
		users:              make(map[string]*UserConfig),
		sessions:           make(map[string]*Session),
		sessionTracker:     NewSessionTracker(),
		firewallEngine:     firewall.NewFirewallEngine(),
		inbounds:           make(map[string]*InboundConfig),
		outbounds:          make(map[string]*OutboundConfig),
		routing:            NewRoutingManager(),
		firewall:           NewFirewallManager(),
		portMgr:            NewPortManager(),
		usersFilePath:      usersFilePath,
		policyMgr:          policyMgr,
		bandwidthEnforcer:  bandwidthEnforcer,
		connectionEnforcer: connectionEnforcer,
		timeBasedEnforcer:  timeBasedEnforcer,
	}
	
	// Загружаем пользователей при старте, если файл указан
	if usersFilePath != "" {
		api.LoadUsers()
	}
	
	return api
}

// LoadUsers загружает пользователей из файла
func (api *ManagementAPI) LoadUsers() {
	if api.usersFilePath == "" {
		return
	}
	
	data, err := os.ReadFile(api.usersFilePath)
	if err != nil {
		// Файл не существует - это нормально при первом запуске
		if !os.IsNotExist(err) {
			fmt.Printf("Error loading users: %v\n", err)
		}
		return
	}
	
	var users []*UserConfig
	if err := json.Unmarshal(data, &users); err != nil {
		fmt.Printf("Error parsing users file: %v\n", err)
		return
	}
	
	api.mu.Lock()
	for _, user := range users {
		if user != nil {
			api.users[user.ID] = user
		}
	}
	api.mu.Unlock()
	
	fmt.Printf("Loaded %d users from %s\n", len(users), api.usersFilePath)
}

// SaveUsers сохраняет пользователей в файл
func (api *ManagementAPI) SaveUsers() {
	if api.usersFilePath == "" {
		return
	}
	
	api.mu.RLock()
	users := make([]*UserConfig, 0, len(api.users))
	for _, user := range api.users {
		if user != nil {
			users = append(users, user)
		}
	}
	api.mu.RUnlock()
	
	data, err := json.MarshalIndent(users, "", "  ")
	if err != nil {
		fmt.Printf("Error marshaling users: %v\n", err)
		return
	}
	
	// Создаем директорию, если не существует
	dir := filepath.Dir(api.usersFilePath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		fmt.Printf("Error creating directory: %v\n", err)
		return
	}
	
	// Сохраняем во временный файл, затем переименовываем (atomic write)
	tmpFile := api.usersFilePath + ".tmp"
	if err := os.WriteFile(tmpFile, data, 0600); err != nil {
		fmt.Printf("Error writing users file: %v\n", err)
		return
	}
	
	if err := os.Rename(tmpFile, api.usersFilePath); err != nil {
		fmt.Printf("Error renaming users file: %v\n", err)
		os.Remove(tmpFile)
		return
	}
}

// GetSessionTracker возвращает трекер сессий
func (api *ManagementAPI) GetSessionTracker() *SessionTracker {
	return api.sessionTracker
}

// GetFirewallEngine возвращает движок файрвола
func (api *ManagementAPI) GetFirewallEngine() *firewall.FirewallEngine {
	return api.firewallEngine
}

// GetRoutingManager возвращает менеджер маршрутизации
func (api *ManagementAPI) GetRoutingManager() *RoutingManager {
	api.mu.RLock()
	defer api.mu.RUnlock()
	return api.routing
}

// SetRoutingEngine устанавливает routing engine для доступа к subscription manager
func (api *ManagementAPI) SetRoutingEngine(engine *routingpkg.Engine) {
	api.mu.Lock()
	defer api.mu.Unlock()
	api.routingEngine = engine
}

// GetRoutingEngine возвращает routing engine
func (api *ManagementAPI) GetRoutingEngine() *routingpkg.Engine {
	api.mu.RLock()
	defer api.mu.RUnlock()
	return api.routingEngine
}

// GetBandwidthEnforcer возвращает bandwidth enforcer
func (api *ManagementAPI) GetBandwidthEnforcer() *policy.BandwidthEnforcer {
	api.mu.RLock()
	defer api.mu.RUnlock()
	return api.bandwidthEnforcer
}

// GetConnectionEnforcer возвращает connection enforcer
func (api *ManagementAPI) GetConnectionEnforcer() *policy.ConnectionEnforcer {
	api.mu.RLock()
	defer api.mu.RUnlock()
	return api.connectionEnforcer
}

// GetTimeBasedEnforcer возвращает time-based enforcer
func (api *ManagementAPI) GetTimeBasedEnforcer() *policy.TimeBasedEnforcer {
	api.mu.RLock()
	defer api.mu.RUnlock()
	return api.timeBasedEnforcer
}

// GetUserByIP ищет пользователя по IP адресу
// Возвращает userID если найден пользователь с таким IP в IPAddresses
func (api *ManagementAPI) GetUserByIP(ipAddr string) string {
	api.mu.RLock()
	defer api.mu.RUnlock()
	
	// Ищем пользователя, у которого IP адрес в списке разрешенных
	for userID, user := range api.users {
		if user == nil || !user.Enabled {
			continue
		}
		
		// Проверяем список IP адресов
		if len(user.IPAddresses) > 0 {
			for _, allowedIP := range user.IPAddresses {
				if allowedIP == ipAddr {
					return userID
				}
			}
		}
	}
	
	return "" // Не найдено - будет использован IP адрес
}

// GetUserByPublicKey ищет пользователя по публичному ключу x25519
func (api *ManagementAPI) GetUserByPublicKey(publicKeyHex string) string {
	api.mu.RLock()
	defer api.mu.RUnlock()
	
	// Нормализуем ключ
	normalizedKey := strings.ToLower(strings.TrimSpace(publicKeyHex))
	normalizedKey = strings.ReplaceAll(normalizedKey, "-", "")
	normalizedKey = strings.ReplaceAll(normalizedKey, " ", "")
	normalizedKey = strings.ReplaceAll(normalizedKey, "\n", "")
	normalizedKey = strings.ReplaceAll(normalizedKey, "\r", "")
	
	for userID, user := range api.users {
		if user == nil {
			continue
		}
		
		// Проверяем по публичному ключу
		if user.PublicKey != "" {
			userPubKey := strings.ToLower(strings.ReplaceAll(user.PublicKey, "-", ""))
			userPubKey = strings.ReplaceAll(userPubKey, " ", "")
			userPubKey = strings.ReplaceAll(userPubKey, "\n", "")
			userPubKey = strings.ReplaceAll(userPubKey, "\r", "")
			
			if userPubKey == normalizedKey {
				return userID
			}
		}
	}
	
	return "" // Не найдено
}

// NewRoutingManager создает новый менеджер маршрутизации
func NewRoutingManager() *RoutingManager {
	return &RoutingManager{
		Rules:  []RoutingRule{},
		Domain: "geosite.dat",
		IP:     "geoip.dat",
	}
}

// NewFirewallManager создает новый менеджер файрвола
func NewFirewallManager() *FirewallManager {
	return &FirewallManager{
		Rules: []FirewallRule{},
	}
}

// NewPortManager создает новый менеджер портов
func NewPortManager() *PortManager {
	return &PortManager{
		Ports: make(map[int]*PortInfo),
	}
}

// RegisterManagementHandlers регистрирует handlers для управления
func (api *ManagementAPI) RegisterManagementHandlers(mux *http.ServeMux) {
	// User management
	mux.HandleFunc("/api/users", api.handleUsers)
	mux.HandleFunc("/api/users/", api.handleUserByID)
	mux.HandleFunc("/api/users/add", api.handleUserAdd)
	mux.HandleFunc("/api/users/update", api.handleUserUpdate)
	mux.HandleFunc("/api/users/delete", api.handleUserDelete)
	mux.HandleFunc("/api/users/reset-traffic", api.handleUserResetTraffic)
	
	// Sessions
	mux.HandleFunc("/api/sessions", api.handleSessions)
	mux.HandleFunc("/api/sessions/", api.handleSessionByID)
	mux.HandleFunc("/api/sessions/kill", api.handleSessionKill)
	
	// Inbound management
	mux.HandleFunc("/api/inbounds", api.handleInbounds)
	mux.HandleFunc("/api/inbounds/add", api.handleInboundAdd)
	mux.HandleFunc("/api/inbounds/update", api.handleInboundUpdate)
	mux.HandleFunc("/api/inbounds/delete", api.handleInboundDelete)
	mux.HandleFunc("/api/inbounds/enable", api.handleInboundEnable)
	
	// Outbound management
	mux.HandleFunc("/api/outbounds", api.handleOutbounds)
	mux.HandleFunc("/api/outbounds/add", api.handleOutboundAdd)
	mux.HandleFunc("/api/outbounds/update", api.handleOutboundUpdate)
	mux.HandleFunc("/api/outbounds/delete", api.handleOutboundDelete)
	
	// Routing
	mux.HandleFunc("/api/routing", api.handleRouting)
	mux.HandleFunc("/api/routing/rules", api.handleRoutingRules)
	mux.HandleFunc("/api/routing/rules/add", api.handleRoutingRuleAdd)
	mux.HandleFunc("/api/routing/rules/delete", api.handleRoutingRuleDelete)
	
	// Firewall
	mux.HandleFunc("/api/firewall", api.handleFirewall)
	mux.HandleFunc("/api/firewall/rules", api.handleFirewallRules)
	mux.HandleFunc("/api/firewall/rules/add", api.handleFirewallRuleAdd)
	mux.HandleFunc("/api/firewall/rules/delete", api.handleFirewallRuleDelete)
	mux.HandleFunc("/api/firewall/rules/update", api.handleFirewallRuleUpdate)
	
	// Port management
	mux.HandleFunc("/api/ports", api.handlePorts)
	mux.HandleFunc("/api/ports/add", api.handlePortAdd)
	mux.HandleFunc("/api/ports/delete", api.handlePortDelete)
	mux.HandleFunc("/api/ports/enable", api.handlePortEnable)
	mux.HandleFunc("/api/ports/check", api.handlePortCheck)
	mux.HandleFunc("/api/ports/used", api.handlePortsUsed)
	
	// Firewall configure
	mux.HandleFunc("/api/firewall/configure", api.handleFirewallConfigure)
	
	// Subscriptions
	mux.HandleFunc("/api/subscriptions", api.handleSubscriptions)
	mux.HandleFunc("/api/subscriptions/add", api.handleSubscriptionAdd)
	mux.HandleFunc("/api/subscriptions/update", api.handleSubscriptionUpdate)
	mux.HandleFunc("/api/subscriptions/delete", api.handleSubscriptionDelete)
	mux.HandleFunc("/api/subscriptions/enable", api.handleSubscriptionEnable)
	mux.HandleFunc("/api/subscriptions/update-all", api.handleSubscriptionUpdateAll)
	
	// Geo databases
	mux.HandleFunc("/api/geo/status", api.handleGeoStatus)
	mux.HandleFunc("/api/geo/update", api.handleGeoUpdate)
	mux.HandleFunc("/api/geo/reload", api.handleGeoReload)
	mux.HandleFunc("/api/geo/settings", api.handleGeoSettings)
	
	// Policy management
	mux.HandleFunc("/api/policy/", api.handlePolicyByUserID)
	mux.HandleFunc("/api/policy/set", api.handlePolicySet)
	mux.HandleFunc("/api/policy/get", api.handlePolicyGet)
	mux.HandleFunc("/api/policy/remove", api.handlePolicyRemove)
	mux.HandleFunc("/api/policy/stats", api.handlePolicyStats)
}

// User management handlers
func (api *ManagementAPI) handleUsers(w http.ResponseWriter, r *http.Request) {
	api.mu.RLock()
	defer api.mu.RUnlock()
	
	if r.Method == http.MethodGet {
		users := make([]*UserConfig, 0, len(api.users))
		for _, user := range api.users {
			users = append(users, user)
		}
		writeJSON(w, users)
		return
	}
	
	writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
}

func (api *ManagementAPI) handleUserByID(w http.ResponseWriter, r *http.Request) {
	userID := r.URL.Path[len("/api/users/"):]
	if userID == "" {
		writeError(w, http.StatusBadRequest, "User ID required")
		return
	}
	
	api.mu.RLock()
	user, exists := api.users[userID]
	api.mu.RUnlock()
	
	if !exists {
		writeError(w, http.StatusNotFound, "User not found")
		return
	}
	
	if r.Method == http.MethodGet {
		writeJSON(w, user)
	} else if r.Method == http.MethodPut {
		// Поддержка PUT для обновления пользователя (как в веб-панели)
		var updatedUser UserConfig
		if err := json.NewDecoder(r.Body).Decode(&updatedUser); err != nil {
			writeError(w, http.StatusBadRequest, "Invalid user config")
			return
		}
		
		// Убеждаемся, что ID совпадает
		updatedUser.ID = userID
		
		api.mu.Lock()
		if existing, exists := api.users[userID]; exists {
			updatedUser.CreatedAt = existing.CreatedAt
			updatedUser.UpdatedAt = time.Now()
			if updatedUser.Traffic == nil {
				updatedUser.Traffic = existing.Traffic
			}
			api.users[userID] = &updatedUser
			api.mu.Unlock()
			
			api.SaveUsers()
			
			writeJSON(w, map[string]interface{}{
				"success": true,
				"user":    updatedUser,
			})
		} else {
			api.mu.Unlock()
			writeError(w, http.StatusNotFound, "User not found")
		}
	} else {
		writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
	}
}

func (api *ManagementAPI) handleUserAdd(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}
	
	var user UserConfig
	if err := json.NewDecoder(r.Body).Decode(&user); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid user config")
		return
	}
	
	// Auto-generate ID if not provided
	if user.ID == "" {
		user.ID = fmt.Sprintf("u_%d", time.Now().UnixNano())
	}
	
	// Auto-generate UUID if not provided
	if user.UUID == "" {
		// Generate UUID v4
		uuidBytes := make([]byte, 16)
		rand.Read(uuidBytes)
		uuidBytes[6] = (uuidBytes[6] & 0x0f) | 0x40 // Version 4
		uuidBytes[8] = (uuidBytes[8] & 0x3f) | 0x80 // Variant 10
		user.UUID = fmt.Sprintf("%08x-%04x-%04x-%04x-%12x",
			uuidBytes[0:4], uuidBytes[4:6], uuidBytes[6:8], uuidBytes[8:10], uuidBytes[10:16])
	}
	
	user.CreatedAt = time.Now()
	user.UpdatedAt = time.Now()
	if user.Traffic == nil {
		user.Traffic = &UserTraffic{}
	}
	
	// Set default values
	if user.Level == 0 {
		user.Level = 1
	}
	if !user.Enabled {
		user.Enabled = true
	}
	
	api.mu.Lock()
	api.users[user.ID] = &user
	api.mu.Unlock()
	
	// Сохраняем пользователей на диск
	api.SaveUsers()
	
	writeJSON(w, map[string]interface{}{
		"success": true,
		"user":    user,
	})
}

func (api *ManagementAPI) handleUserUpdate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}
	
	var user UserConfig
	if err := json.NewDecoder(r.Body).Decode(&user); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid user config")
		return
	}
	
	api.mu.Lock()
	if existing, exists := api.users[user.ID]; exists {
		user.CreatedAt = existing.CreatedAt
		user.UpdatedAt = time.Now()
		if user.Traffic == nil {
			user.Traffic = existing.Traffic
		}
		api.users[user.ID] = &user
		api.mu.Unlock()
		
		// Сохраняем пользователей на диск
		api.SaveUsers()
		
		writeJSON(w, map[string]interface{}{"success": true})
	} else {
		api.mu.Unlock()
		writeError(w, http.StatusNotFound, "User not found")
	}
}

func (api *ManagementAPI) handleUserDelete(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "Method not allowed. Use POST.")
		return
	}
	
	var req struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request")
		return
	}
	
	api.mu.Lock()
	delete(api.users, req.ID)
	api.mu.Unlock()
	
	// Сохраняем пользователей на диск
	api.SaveUsers()
	
	writeJSON(w, map[string]interface{}{"success": true})
}

func (api *ManagementAPI) handleUserResetTraffic(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}
	
	// Проверяем, не является ли это запросом с ID в URL (формат: /api/users/{id}/reset-traffic)
	path := r.URL.Path
	if strings.Contains(path, "/reset-traffic") && strings.HasPrefix(path, "/api/users/") {
		// Формат: /api/users/{id}/reset-traffic
		parts := strings.Split(path, "/")
		if len(parts) >= 5 && parts[4] == "reset-traffic" {
			userID := parts[3]
			if userID != "" {
				api.mu.Lock()
				if user, exists := api.users[userID]; exists {
					if user.Traffic == nil {
						user.Traffic = &UserTraffic{}
					}
					user.Traffic.Upload = 0
					user.Traffic.Download = 0
					user.Traffic.Total = 0
					api.mu.Unlock()
					
					api.SaveUsers()
					
					writeJSON(w, map[string]interface{}{"success": true})
					return
				}
				api.mu.Unlock()
				writeError(w, http.StatusNotFound, "User not found")
				return
			}
		}
	}
	
	// Старый формат: /api/users/reset-traffic с ID в body
	var req struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request")
		return
	}
	
	api.mu.Lock()
	if user, exists := api.users[req.ID]; exists {
		if user.Traffic == nil {
			user.Traffic = &UserTraffic{}
		}
		user.Traffic.Upload = 0
		user.Traffic.Download = 0
		user.Traffic.Total = 0
		api.mu.Unlock()
		api.SaveUsers()
		writeJSON(w, map[string]interface{}{"success": true})
	} else {
		api.mu.Unlock()
		writeError(w, http.StatusNotFound, "User not found")
	}
}

// Session handlers
func (api *ManagementAPI) handleSessions(w http.ResponseWriter, r *http.Request) {
	// Возвращаем сессии из трекера (реальные сессии сервера)
	if api.sessionTracker != nil {
		serverSessions := api.sessionTracker.GetAllSessions()
		writeJSON(w, serverSessions)
		return
	}
	
	// Fallback на старые сессии если трекер не инициализирован
	api.mu.RLock()
	defer api.mu.RUnlock()
	
	sessions := make([]*Session, 0, len(api.sessions))
	for _, session := range api.sessions {
		sessions = append(sessions, session)
	}
	writeJSON(w, sessions)
}

func (api *ManagementAPI) handleSessionByID(w http.ResponseWriter, r *http.Request) {
	sessionID := r.URL.Path[len("/api/sessions/"):]
	if sessionID == "" {
		http.Error(w, "Session ID required", http.StatusBadRequest)
		return
	}
	
	// Проверяем, не является ли это запросом на kill (формат: /api/sessions/{id}/kill)
	if strings.HasSuffix(sessionID, "/kill") {
		// Убираем "/kill" из пути
		sessionID = strings.TrimSuffix(sessionID, "/kill")
		if sessionID == "" {
			writeError(w, http.StatusBadRequest, "Session ID required")
			return
		}
		
		// Обрабатываем kill запрос
		if r.Method == http.MethodPost {
			api.mu.Lock()
			delete(api.sessions, sessionID)
			api.mu.Unlock()
			
			writeJSON(w, map[string]interface{}{"success": true})
			return
		}
	}
	
	api.mu.RLock()
	session, exists := api.sessions[sessionID]
	api.mu.RUnlock()
	
	if !exists {
		http.Error(w, "Session not found", http.StatusNotFound)
		return
	}
	
	writeJSON(w, session)
}

func (api *ManagementAPI) handleSessionKill(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}
	
	var req struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request")
		return
	}
	
	api.mu.Lock()
	delete(api.sessions, req.ID)
	api.mu.Unlock()
	
	writeJSON(w, map[string]interface{}{"success": true})
}

// Inbound handlers
func (api *ManagementAPI) handleInbounds(w http.ResponseWriter, r *http.Request) {
	api.mu.RLock()
	defer api.mu.RUnlock()
	
	inbounds := make([]*InboundConfig, 0, len(api.inbounds))
	for _, inbound := range api.inbounds {
		inbounds = append(inbounds, inbound)
	}
	writeJSON(w, inbounds)
}

func (api *ManagementAPI) handleInboundAdd(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}
	
	var inbound InboundConfig
	if err := json.NewDecoder(r.Body).Decode(&inbound); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid inbound config")
		return
	}
	
	if inbound.Tag == "" {
		writeError(w, http.StatusBadRequest, "Tag required")
		return
	}
	
	api.mu.Lock()
	api.inbounds[inbound.Tag] = &inbound
	api.mu.Unlock()
	
	// Регистрируем порт
	if inbound.Port > 0 {
		api.portMgr.mu.Lock()
		api.portMgr.Ports[inbound.Port] = &PortInfo{
			Port:       inbound.Port,
			Protocol:   getProtocolFromInbound(inbound),
			InboundTag: inbound.Tag,
			Enabled:    inbound.Enabled,
		}
		api.portMgr.mu.Unlock()
	}
	
	writeJSON(w, map[string]interface{}{"success": true})
}

func (api *ManagementAPI) handleInboundUpdate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}
	
	var inbound InboundConfig
	if err := json.NewDecoder(r.Body).Decode(&inbound); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid inbound config")
		return
	}
	
	api.mu.Lock()
	api.inbounds[inbound.Tag] = &inbound
	api.mu.Unlock()
	
	writeJSON(w, map[string]interface{}{"success": true})
}

func (api *ManagementAPI) handleInboundDelete(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}
	
	var req struct {
		Tag string `json:"tag"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request")
		return
	}
	
	api.mu.Lock()
	if inbound, exists := api.inbounds[req.Tag]; exists {
		delete(api.inbounds, req.Tag)
		// Удаляем порт
		if inbound.Port > 0 {
			delete(api.portMgr.Ports, inbound.Port)
		}
		api.mu.Unlock()
		writeJSON(w, map[string]interface{}{"success": true})
	} else {
		api.mu.Unlock()
		writeError(w, http.StatusNotFound, "Inbound not found")
	}
}

func (api *ManagementAPI) handleInboundEnable(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}
	
	var req struct {
		Tag     string `json:"tag"`
		Enabled bool   `json:"enabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request")
		return
	}
	
	api.mu.Lock()
	if inbound, exists := api.inbounds[req.Tag]; exists {
		inbound.Enabled = req.Enabled
		if inbound.Port > 0 {
			if port, ok := api.portMgr.Ports[inbound.Port]; ok {
				port.Enabled = req.Enabled
			}
		}
		api.mu.Unlock()
		writeJSON(w, map[string]interface{}{"success": true})
	} else {
		api.mu.Unlock()
		writeError(w, http.StatusNotFound, "Inbound not found")
	}
}

// Outbound handlers
func (api *ManagementAPI) handleOutbounds(w http.ResponseWriter, r *http.Request) {
	api.mu.RLock()
	defer api.mu.RUnlock()
	
	outbounds := make([]*OutboundConfig, 0, len(api.outbounds))
	for _, outbound := range api.outbounds {
		outbounds = append(outbounds, outbound)
	}
	writeJSON(w, outbounds)
}

func (api *ManagementAPI) handleOutboundAdd(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}
	
	var outbound OutboundConfig
	if err := json.NewDecoder(r.Body).Decode(&outbound); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid outbound config")
		return
	}
	
	if outbound.Tag == "" {
		writeError(w, http.StatusBadRequest, "Tag required")
		return
	}
	
	api.mu.Lock()
	api.outbounds[outbound.Tag] = &outbound
	api.mu.Unlock()
	
	writeJSON(w, map[string]interface{}{"success": true})
}

func (api *ManagementAPI) handleOutboundUpdate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}
	
	var outbound OutboundConfig
	if err := json.NewDecoder(r.Body).Decode(&outbound); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid outbound config")
		return
	}
	
	api.mu.Lock()
	api.outbounds[outbound.Tag] = &outbound
	api.mu.Unlock()
	
	writeJSON(w, map[string]interface{}{"success": true})
}

func (api *ManagementAPI) handleOutboundDelete(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}
	
	var req struct {
		Tag string `json:"tag"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request")
		return
	}
	
	api.mu.Lock()
	delete(api.outbounds, req.Tag)
	api.mu.Unlock()
	
	writeJSON(w, map[string]interface{}{"success": true})
}

// Routing handlers
func (api *ManagementAPI) handleRouting(w http.ResponseWriter, r *http.Request) {
	api.routing.mu.RLock()
	defer api.routing.mu.RUnlock()
	
	writeJSON(w, api.routing)
}

func (api *ManagementAPI) handleRoutingRules(w http.ResponseWriter, r *http.Request) {
	api.routing.mu.RLock()
	defer api.routing.mu.RUnlock()
	
	writeJSON(w, api.routing.Rules)
}

func (api *ManagementAPI) handleRoutingRuleAdd(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}
	
	var rule RoutingRule
	if err := json.NewDecoder(r.Body).Decode(&rule); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid routing rule")
		return
	}
	
	api.routing.mu.Lock()
	api.routing.Rules = append(api.routing.Rules, rule)
	api.routing.mu.Unlock()
	
	writeJSON(w, map[string]interface{}{"success": true})
}

func (api *ManagementAPI) handleRoutingRuleDelete(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}
	
	var req struct {
		Index int `json:"index"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request")
		return
	}
	
	api.routing.mu.Lock()
	if req.Index >= 0 && req.Index < len(api.routing.Rules) {
		api.routing.Rules = append(api.routing.Rules[:req.Index], api.routing.Rules[req.Index+1:]...)
		api.routing.mu.Unlock()
		writeJSON(w, map[string]interface{}{"success": true})
	} else {
		api.routing.mu.Unlock()
		writeError(w, http.StatusBadRequest, "Invalid index")
	}
}

// Firewall handlers
func (api *ManagementAPI) handleFirewall(w http.ResponseWriter, r *http.Request) {
	api.firewall.mu.RLock()
	defer api.firewall.mu.RUnlock()
	
	writeJSON(w, api.firewall)
}

func (api *ManagementAPI) handleFirewallRules(w http.ResponseWriter, r *http.Request) {
	api.firewall.mu.RLock()
	defer api.firewall.mu.RUnlock()
	
	writeJSON(w, api.firewall.Rules)
}

func (api *ManagementAPI) handleFirewallRuleAdd(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}
	
	var rule FirewallRule
	if err := json.NewDecoder(r.Body).Decode(&rule); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid firewall rule")
		return
	}
	
	rule.CreatedAt = time.Now()
	rule.UpdatedAt = time.Now()
	
	api.firewall.mu.Lock()
	api.firewall.Rules = append(api.firewall.Rules, rule)
	api.firewall.mu.Unlock()
	
	writeJSON(w, map[string]interface{}{"success": true})
}

func (api *ManagementAPI) handleFirewallRuleUpdate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}
	
	var rule FirewallRule
	if err := json.NewDecoder(r.Body).Decode(&rule); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid firewall rule")
		return
	}
	
	api.firewall.mu.Lock()
	found := false
	for i, r := range api.firewall.Rules {
		if r.ID == rule.ID {
			rule.UpdatedAt = time.Now()
			rule.CreatedAt = api.firewall.Rules[i].CreatedAt
			api.firewall.Rules[i] = rule
			found = true
			break
		}
	}
	api.firewall.mu.Unlock()
	
	if found {
		writeJSON(w, map[string]interface{}{"success": true})
	} else {
		writeError(w, http.StatusNotFound, "Rule not found")
	}
}

func (api *ManagementAPI) handleFirewallRuleDelete(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}
	
	var req struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request")
		return
	}
	
	api.firewall.mu.Lock()
	found := false
	for i, rule := range api.firewall.Rules {
		if rule.ID == req.ID {
			api.firewall.Rules = append(api.firewall.Rules[:i], api.firewall.Rules[i+1:]...)
			found = true
			break
		}
	}
	api.firewall.mu.Unlock()
	
	if found {
		writeJSON(w, map[string]interface{}{"success": true})
	} else {
		writeError(w, http.StatusNotFound, "Rule not found")
	}
}

// Port management handlers
func (api *ManagementAPI) handlePorts(w http.ResponseWriter, r *http.Request) {
	api.portMgr.mu.RLock()
	defer api.portMgr.mu.RUnlock()
	
	ports := make([]*PortInfo, 0, len(api.portMgr.Ports))
	for _, port := range api.portMgr.Ports {
		ports = append(ports, port)
	}
	writeJSON(w, ports)
}

func (api *ManagementAPI) handlePortAdd(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}
	
	var port PortInfo
	if err := json.NewDecoder(r.Body).Decode(&port); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid port config")
		return
	}
	
	api.portMgr.mu.Lock()
	api.portMgr.Ports[port.Port] = &port
	api.portMgr.mu.Unlock()
	
	writeJSON(w, map[string]interface{}{"success": true})
}

func (api *ManagementAPI) handlePortDelete(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}
	
	var req struct {
		Port int `json:"port"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request")
		return
	}
	
	api.portMgr.mu.Lock()
	delete(api.portMgr.Ports, req.Port)
	api.portMgr.mu.Unlock()
	
	writeJSON(w, map[string]interface{}{"success": true})
}

func (api *ManagementAPI) handlePortEnable(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}
	
	var req struct {
		Port    int  `json:"port"`
		Enabled bool `json:"enabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request")
		return
	}
	
	api.portMgr.mu.Lock()
	if port, exists := api.portMgr.Ports[req.Port]; exists {
		port.Enabled = req.Enabled
		api.portMgr.mu.Unlock()
		writeJSON(w, map[string]interface{}{"success": true})
	} else {
		api.portMgr.mu.Unlock()
		writeError(w, http.StatusNotFound, "Port not found")
	}
}

func (api *ManagementAPI) handlePortCheck(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}
	
	port := r.URL.Query().Get("port")
	protocol := r.URL.Query().Get("protocol")
	if port == "" {
		writeError(w, http.StatusBadRequest, "Port parameter required")
		return
	}
	
	var portNum int
	if _, err := fmt.Sscanf(port, "%d", &portNum); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid port number")
		return
	}
	
	if protocol == "" {
		protocol = "tcp"
	}
	
	// Проверяем доступность порта
	available := true
	occupiedBy := ""
	
	// Простая проверка - пытаемся подключиться
	address := fmt.Sprintf(":%d", portNum)
	conn, err := net.DialTimeout(protocol, address, 2*time.Second)
	if err == nil {
		conn.Close()
		available = false
		occupiedBy = "Unknown service"
	}
	
	// Проверяем в списке портов
	api.portMgr.mu.RLock()
	if portInfo, exists := api.portMgr.Ports[portNum]; exists {
		if portInfo.Enabled {
			available = false
			occupiedBy = portInfo.InboundTag
		}
	}
	api.portMgr.mu.RUnlock()
	
	writeJSON(w, map[string]interface{}{
		"port":       portNum,
		"protocol":   protocol,
		"available":  available,
		"occupiedBy": occupiedBy,
	})
}

func (api *ManagementAPI) handlePortsUsed(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}
	
	api.portMgr.mu.RLock()
	defer api.portMgr.mu.RUnlock()
	
	usedPorts := make([]map[string]interface{}, 0, len(api.portMgr.Ports))
	for _, port := range api.portMgr.Ports {
		if port.Enabled {
			usedPorts = append(usedPorts, map[string]interface{}{
				"port":     port.Port,
				"protocol": port.Protocol,
				"name":     port.InboundTag,
				"service":  port.InboundTag,
			})
		}
	}
	
	writeJSON(w, usedPorts)
}

func (api *ManagementAPI) handleFirewallConfigure(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}
	
	var req struct {
		Ports []struct {
			Port     int    `json:"port"`
			Protocol string `json:"protocol"`
			Name     string `json:"name"`
		} `json:"ports"`
	}
	
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request")
		return
	}
	
	// Здесь должна быть реальная настройка firewall (UFW/iptables)
	// Для демонстрации просто добавляем правила в наш менеджер
	results := make([]map[string]interface{}, 0)
	
	for _, portInfo := range req.Ports {
		// Добавляем правило в firewall
		ruleID := fmt.Sprintf("whispera_%s_%d", portInfo.Protocol, portInfo.Port)
		
		api.firewall.mu.Lock()
		api.firewall.Rules = append(api.firewall.Rules, FirewallRule{
			ID:        ruleID,
			Name:      portInfo.Name,
			Action:    "allow",
			Direction: "inbound",
			Protocol:  portInfo.Protocol,
			Port:      fmt.Sprintf("%d", portInfo.Port),
			Enabled:   true,
			Priority:  100,
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		})
		api.firewall.mu.Unlock()
		
		// Добавляем в порт менеджер
		api.portMgr.mu.Lock()
		api.portMgr.Ports[portInfo.Port] = &PortInfo{
			Port:       portInfo.Port,
			Protocol:   portInfo.Protocol,
			InboundTag: portInfo.Name,
			Enabled:    true,
			LastUsed:   time.Now(),
		}
		api.portMgr.mu.Unlock()
		
		results = append(results, map[string]interface{}{
			"port":     portInfo.Port,
			"protocol": portInfo.Protocol,
			"name":     portInfo.Name,
			"status":   "configured",
		})
	}
	
	writeJSON(w, map[string]interface{}{
		"success": true,
		"rules":   results,
		"message": "Firewall configured successfully",
	})
}

// Helper functions
func getProtocolFromInbound(inbound InboundConfig) string {
	// Определяем протокол на основе настроек
	switch inbound.Protocol {
	case "vmess", "vless":
		if stream := inbound.StreamSettings; stream != nil {
			switch stream.Network {
			case "tcp":
				return "tcp"
			case "ws", "websocket":
				return "tcp" // WebSocket использует TCP
			case "quic":
				return "udp"
			default:
				return "tcp"
			}
		}
		return "tcp"
	default:
		return "tcp"
	}
}

func writeJSON(w http.ResponseWriter, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(data)
}

func writeError(w http.ResponseWriter, code int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"error": message,
	})
}

// Subscription handlers
func (api *ManagementAPI) handleSubscriptions(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	routingEngine := api.GetRoutingEngine()
	if routingEngine == nil {
		writeError(w, http.StatusInternalServerError, "Routing engine not available")
		return
	}

	subMgr := routingEngine.GetSubscriptionManager()
	if subMgr == nil {
		writeJSON(w, []interface{}{})
		return
	}

	subs := subMgr.GetAllSubscriptions()
	writeJSON(w, subs)
}

func (api *ManagementAPI) handleSubscriptionAdd(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	var sub struct {
		ID       string `json:"id"`
		Name     string `json:"name"`
		URL      string `json:"url"`
		Enabled  bool   `json:"enabled"`
		Interval string `json:"interval"` // "1h", "30m", etc.
	}

	if err := json.NewDecoder(r.Body).Decode(&sub); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid subscription config")
		return
	}

	routingEngine := api.GetRoutingEngine()
	if routingEngine == nil {
		writeError(w, http.StatusInternalServerError, "Routing engine not available")
		return
	}

	subMgr := routingEngine.GetSubscriptionManager()
	if subMgr == nil {
		writeError(w, http.StatusInternalServerError, "Subscription manager not available")
		return
	}

	// Auto-generate ID if not provided
	if sub.ID == "" {
		sub.ID = fmt.Sprintf("sub_%d", time.Now().UnixNano())
	}

	// Parse interval
	interval, err := time.ParseDuration(sub.Interval)
	if err != nil || interval == 0 {
		interval = 1 * time.Hour // Default
	}

	subscription := &routingpkg.Subscription{
		ID:       sub.ID,
		Name:     sub.Name,
		URL:      sub.URL,
		Enabled:  sub.Enabled,
		Interval: interval,
	}

	if err := subMgr.AddSubscription(subscription); err != nil {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("Failed to add subscription: %v", err))
		return
	}

	writeJSON(w, map[string]interface{}{
		"success": true,
		"subscription": subscription,
	})
}

func (api *ManagementAPI) handleSubscriptionUpdate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	var sub routingpkg.Subscription
	if err := json.NewDecoder(r.Body).Decode(&sub); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid subscription config")
		return
	}

	routingEngine := api.GetRoutingEngine()
	if routingEngine == nil {
		writeError(w, http.StatusInternalServerError, "Routing engine not available")
		return
	}

	subMgr := routingEngine.GetSubscriptionManager()
	if subMgr == nil {
		writeError(w, http.StatusInternalServerError, "Subscription manager not available")
		return
	}

	if err := subMgr.UpdateSubscription(&sub); err != nil {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("Failed to update subscription: %v", err))
		return
	}

	writeJSON(w, map[string]interface{}{"success": true})
}

func (api *ManagementAPI) handleSubscriptionDelete(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	var req struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request")
		return
	}

	routingEngine := api.GetRoutingEngine()
	if routingEngine == nil {
		writeError(w, http.StatusInternalServerError, "Routing engine not available")
		return
	}

	subMgr := routingEngine.GetSubscriptionManager()
	if subMgr == nil {
		writeError(w, http.StatusInternalServerError, "Subscription manager not available")
		return
	}

	subMgr.RemoveSubscription(req.ID)
	writeJSON(w, map[string]interface{}{"success": true})
}

func (api *ManagementAPI) handleSubscriptionEnable(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	var req struct {
		ID      string `json:"id"`
		Enabled bool   `json:"enabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request")
		return
	}

	routingEngine := api.GetRoutingEngine()
	if routingEngine == nil {
		writeError(w, http.StatusInternalServerError, "Routing engine not available")
		return
	}

	subMgr := routingEngine.GetSubscriptionManager()
	if subMgr == nil {
		writeError(w, http.StatusInternalServerError, "Subscription manager not available")
		return
	}

	if err := subMgr.EnableSubscription(req.ID, req.Enabled); err != nil {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("Failed to enable/disable subscription: %v", err))
		return
	}

	writeJSON(w, map[string]interface{}{"success": true})
}

func (api *ManagementAPI) handleSubscriptionUpdateAll(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	routingEngine := api.GetRoutingEngine()
	if routingEngine == nil {
		writeError(w, http.StatusInternalServerError, "Routing engine not available")
		return
	}

	subMgr := routingEngine.GetSubscriptionManager()
	if subMgr == nil {
		writeError(w, http.StatusInternalServerError, "Subscription manager not available")
		return
	}

	subMgr.ForceUpdate()
	writeJSON(w, map[string]interface{}{"success": true})
}

// Geo database handlers
func (api *ManagementAPI) handleGeoStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	routingEngine := api.GetRoutingEngine()
	if routingEngine == nil {
		writeJSON(w, map[string]interface{}{
			"enabled": false,
			"error":   "Routing engine not initialized",
		})
		return
	}

	geoUpdater := routingEngine.GetGeoUpdater()
	if geoUpdater == nil {
		writeJSON(w, map[string]interface{}{
			"enabled":     false,
			"geoIPPath":   "",
			"geoSitePath": "",
			"lastUpdate":  nil,
			"message":     "Geo updater not configured",
		})
		return
	}

	geoIPPath := geoUpdater.GetGeoIPPath()
	geoSitePath := geoUpdater.GetGeoSitePath()
	lastUpdate := geoUpdater.GetLastUpdate()
	enabled := geoUpdater.IsEnabled()
	needsUpdate, _ := geoUpdater.CheckUpdate()

	// Получаем информацию о файлах
	var geoIPSize int64
	var geoSiteSize int64
	var geoIPModTime time.Time
	var geoSiteModTime time.Time

	if geoIPPath != "" {
		if info, err := os.Stat(geoIPPath); err == nil {
			geoIPSize = info.Size()
			geoIPModTime = info.ModTime()
		}
	}

	if geoSitePath != "" {
		if info, err := os.Stat(geoSitePath); err == nil {
			geoSiteSize = info.Size()
			geoSiteModTime = info.ModTime()
		}
	}

	writeJSON(w, map[string]interface{}{
		"enabled":       enabled,
		"geoIPPath":     geoIPPath,
		"geoSitePath":   geoSitePath,
		"lastUpdate":    lastUpdate,
		"needsUpdate":   needsUpdate,
		"geoIPSize":     geoIPSize,
		"geoSiteSize":   geoSiteSize,
		"geoIPModTime":  geoIPModTime,
		"geoSiteModTime": geoSiteModTime,
	})
}

func (api *ManagementAPI) handleGeoUpdate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	routingEngine := api.GetRoutingEngine()
	if routingEngine == nil {
		writeError(w, http.StatusServiceUnavailable, "Routing engine not initialized")
		return
	}

	geoUpdater := routingEngine.GetGeoUpdater()
	if geoUpdater == nil {
		writeError(w, http.StatusServiceUnavailable, "Geo updater not configured")
		return
	}

	// Обновляем в фоне
	go func() {
		if err := geoUpdater.Update(); err != nil {
			// Логируем ошибку, но не возвращаем её в ответе
			_ = err
			return
		}

		// Перезагружаем базы после обновления
		if err := routingEngine.ReloadGeoBases(); err != nil {
			// Логируем ошибку
			_ = err
		}
	}()

	writeJSON(w, map[string]interface{}{
		"success": true,
		"message": "Geo database update started",
	})
}

func (api *ManagementAPI) handleGeoReload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	routingEngine := api.GetRoutingEngine()
	if routingEngine == nil {
		writeError(w, http.StatusServiceUnavailable, "Routing engine not initialized")
		return
	}

	if err := routingEngine.ReloadGeoBases(); err != nil {
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("Failed to reload: %v", err))
		return
	}

	writeJSON(w, map[string]interface{}{
		"success": true,
		"message": "Geo databases reloaded",
	})
}

func (api *ManagementAPI) handleGeoSettings(w http.ResponseWriter, r *http.Request) {
	routingEngine := api.GetRoutingEngine()
	if routingEngine == nil {
		writeError(w, http.StatusServiceUnavailable, "Routing engine not initialized")
		return
	}

	geoUpdater := routingEngine.GetGeoUpdater()
	if geoUpdater == nil {
		writeError(w, http.StatusServiceUnavailable, "Geo updater not configured")
		return
	}

	if r.Method == http.MethodGet {
		writeJSON(w, map[string]interface{}{
			"enabled": geoUpdater.IsEnabled(),
		})
		return
	}

	if r.Method == http.MethodPost {
		var req struct {
			Enabled bool `json:"enabled"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, "Invalid request")
			return
		}

		geoUpdater.SetEnabled(req.Enabled)
		writeJSON(w, map[string]interface{}{
			"success": true,
			"enabled": req.Enabled,
		})
		return
	}

	writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
}

// Policy management handlers
func (api *ManagementAPI) handlePolicyByUserID(w http.ResponseWriter, r *http.Request) {
	userID := r.URL.Path[len("/api/policy/"):]
	if userID == "" {
		writeError(w, http.StatusBadRequest, "User ID required")
		return
	}
	
	if r.Method == http.MethodGet {
		pol := api.policyMgr.GetPolicy(userID)
		if pol == nil {
			writeError(w, http.StatusNotFound, "Policy not found")
			return
		}
		writeJSON(w, pol)
		return
	}
	
	writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
}

func (api *ManagementAPI) handlePolicySet(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}
	
	var req struct {
		UserID           string    `json:"user_id"`
		MaxUploadSpeed   int64     `json:"max_upload_speed,omitempty"`
		MaxDownloadSpeed int64     `json:"max_download_speed,omitempty"`
		MaxUploadBytes   int64     `json:"max_upload_bytes,omitempty"`
		MaxDownloadBytes int64     `json:"max_download_bytes,omitempty"`
		MaxConnections   int       `json:"max_connections,omitempty"`
		MaxConnectionsPerIP int    `json:"max_connections_per_ip,omitempty"`
		AllowedHours     []struct {
			Start string `json:"start"` // "HH:MM"
			End   string `json:"end"`   // "HH:MM"
		} `json:"allowed_hours,omitempty"`
		AllowedDays      []string `json:"allowed_days,omitempty"` // ["Monday", "Tuesday", ...]
		ExpiresAt        *string  `json:"expires_at,omitempty"`    // ISO 8601 format
	}
	
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("Invalid request: %v", err))
		return
	}
	
	if req.UserID == "" {
		writeError(w, http.StatusBadRequest, "User ID required")
		return
	}
	
	pol := policy.NewPolicy()
	pol.MaxUploadSpeed = req.MaxUploadSpeed
	pol.MaxDownloadSpeed = req.MaxDownloadSpeed
	pol.MaxUploadBytes = req.MaxUploadBytes
	pol.MaxDownloadBytes = req.MaxDownloadBytes
	pol.MaxConnections = req.MaxConnections
	pol.MaxConnectionsPerIP = req.MaxConnectionsPerIP
	
	// Парсим allowed hours
	if len(req.AllowedHours) > 0 {
		pol.AllowedHours = make([]policy.TimeRange, 0, len(req.AllowedHours))
		for _, hr := range req.AllowedHours {
			start, err := time.Parse("15:04", hr.Start)
			if err != nil {
				writeError(w, http.StatusBadRequest, fmt.Sprintf("Invalid start time format: %v", err))
				return
			}
			end, err := time.Parse("15:04", hr.End)
			if err != nil {
				writeError(w, http.StatusBadRequest, fmt.Sprintf("Invalid end time format: %v", err))
				return
			}
			pol.AllowedHours = append(pol.AllowedHours, policy.TimeRange{
				Start: start,
				End:   end,
			})
		}
	}
	
	// Парсим allowed days
	if len(req.AllowedDays) > 0 {
		pol.AllowedDays = make([]time.Weekday, 0, len(req.AllowedDays))
		dayMap := map[string]time.Weekday{
			"Sunday":    time.Sunday,
			"Monday":    time.Monday,
			"Tuesday":   time.Tuesday,
			"Wednesday": time.Wednesday,
			"Thursday":  time.Thursday,
			"Friday":    time.Friday,
			"Saturday":  time.Saturday,
		}
		for _, dayStr := range req.AllowedDays {
			if day, ok := dayMap[dayStr]; ok {
				pol.AllowedDays = append(pol.AllowedDays, day)
			}
		}
	}
	
	// Парсим expires_at
	if req.ExpiresAt != nil {
		expires, err := time.Parse(time.RFC3339, *req.ExpiresAt)
		if err != nil {
			writeError(w, http.StatusBadRequest, fmt.Sprintf("Invalid expires_at format: %v", err))
			return
		}
		pol.ExpiresAt = &expires
	}
	
	api.policyMgr.SetPolicy(req.UserID, pol)
	writeJSON(w, map[string]interface{}{
		"success": true,
		"user_id": req.UserID,
	})
}

func (api *ManagementAPI) handlePolicyGet(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}
	
	userID := r.URL.Query().Get("user_id")
	if userID == "" {
		writeError(w, http.StatusBadRequest, "User ID required")
		return
	}
	
	pol := api.policyMgr.GetPolicy(userID)
	if pol == nil {
		writeError(w, http.StatusNotFound, "Policy not found")
		return
	}
	
	writeJSON(w, pol)
}

func (api *ManagementAPI) handlePolicyRemove(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}
	
	var req struct {
		UserID string `json:"user_id"`
	}
	
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request")
		return
	}
	
	if req.UserID == "" {
		writeError(w, http.StatusBadRequest, "User ID required")
		return
	}
	
	api.policyMgr.RemovePolicy(req.UserID)
	writeJSON(w, map[string]interface{}{
		"success": true,
		"user_id": req.UserID,
	})
}

func (api *ManagementAPI) handlePolicyStats(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}
	
	userID := r.URL.Query().Get("user_id")
	if userID == "" {
		writeError(w, http.StatusBadRequest, "User ID required")
		return
	}
	
	uploadBytes, downloadBytes := api.bandwidthEnforcer.GetStats(userID)
	connectionCount := api.connectionEnforcer.GetConnectionCount(userID)
	
	writeJSON(w, map[string]interface{}{
		"user_id":        userID,
		"upload_bytes":   uploadBytes,
		"download_bytes": downloadBytes,
		"connections":    connectionCount,
	})
}

