package dynamicconfig

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"sync/atomic"
	"time"

	"gopkg.in/yaml.v3"

	"whispera/internal/core/base"
	"whispera/internal/logger"
)

var log = logger.Module("dynamicconfig")

const (
	ModuleName    = "config.dynamic"
	ModuleVersion = "1.0.0"
)

type ChangeType string

const (
	ChangeAdded    ChangeType = "added"
	ChangeModified ChangeType = "modified"
	ChangeRemoved  ChangeType = "removed"
)

type Change struct {
	Type     ChangeType
	Path     string 
	OldValue interface{}
	NewValue interface{}
}

type Callback func(changes []Change) error

type Config struct {
	FilePath string

	WatchEnabled  bool
	WatchInterval time.Duration

	ValidateOnLoad   bool
	ValidateOnChange bool

	OnChange []Callback

	AtomicLoad bool 

	BackupEnabled bool
	BackupDir     string
	MaxBackups    int
}

func DefaultConfig() *Config {
	return &Config{
		WatchEnabled:     true,
		WatchInterval:    5 * time.Second,
		ValidateOnLoad:   true,
		ValidateOnChange: true,
		AtomicLoad:       true,
		BackupEnabled:    true,
		BackupDir:        "./config_backups",
		MaxBackups:       10,
	}
}

type Manager struct {
	*base.Module
	config *Config

	mu          sync.RWMutex
	current     map[string]interface{}
	currentHash [32]byte
	validators  []func(map[string]interface{}) error
	callbacks   []Callback

	stopCh chan struct{}
	wg     sync.WaitGroup

	reloadCount   uint64
	reloadErrors  uint64
	lastReload    time.Time
	lastReloadErr string
}

func New(cfg *Config) (*Manager, error) {
	if cfg == nil {
		cfg = DefaultConfig()
	}

	m := &Manager{
		Module:    base.NewModule(ModuleName, ModuleVersion, nil),
		config:    cfg,
		current:   make(map[string]interface{}),
		callbacks: cfg.OnChange,
		stopCh:    make(chan struct{}),
	}

	return m, nil
}

func (m *Manager) Load() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	return m.loadLocked()
}

func (m *Manager) loadLocked() error {
	data, err := os.ReadFile(m.config.FilePath)
	if err != nil {
		return fmt.Errorf("failed to read config: %w", err)
	}

	newHash := sha256.Sum256(data)
	if newHash == m.currentHash {
		return nil 
	}

	var newConfig map[string]interface{}
	ext := filepath.Ext(m.config.FilePath)

	switch ext {
	case ".yaml", ".yml":
		if err := yaml.Unmarshal(data, &newConfig); err != nil {
			return fmt.Errorf("failed to parse YAML: %w", err)
		}
	case ".json":
		if err := json.Unmarshal(data, &newConfig); err != nil {
			return fmt.Errorf("failed to parse JSON: %w", err)
		}
	default:
		return fmt.Errorf("unsupported config format: %s", ext)
	}

	if m.config.ValidateOnLoad {
		for _, validator := range m.validators {
			if err := validator(newConfig); err != nil {
				return fmt.Errorf("validation failed: %w", err)
			}
		}
	}

	changes := m.diffConfig(m.current, newConfig)

	if m.config.BackupEnabled && len(m.current) > 0 {
		m.backupConfig()
	}

	oldConfig := m.current
	m.current = newConfig
	m.currentHash = newHash
	m.lastReload = time.Now()
	atomic.AddUint64(&m.reloadCount, 1)

	if len(changes) > 0 {
		go m.notifyCallbacks(changes, oldConfig)
	}

	log.Info("Configuration reloaded (%d changes)", len(changes))
	return nil
}

func (m *Manager) diffConfig(old, new map[string]interface{}) []Change {
	var changes []Change

	m.diffConfigRecursive("", old, new, &changes)

	return changes
}

func (m *Manager) diffConfigRecursive(prefix string, old, new map[string]interface{}, changes *[]Change) {
	for key, oldVal := range old {
		path := key
		if prefix != "" {
			path = prefix + "." + key
		}

		newVal, exists := new[key]
		if !exists {
			*changes = append(*changes, Change{
				Type:     ChangeRemoved,
				Path:     path,
				OldValue: oldVal,
			})
			continue
		}

		if !reflect.DeepEqual(oldVal, newVal) {
			oldMap, oldIsMap := oldVal.(map[string]interface{})
			newMap, newIsMap := newVal.(map[string]interface{})

			if oldIsMap && newIsMap {
				m.diffConfigRecursive(path, oldMap, newMap, changes)
			} else {
				*changes = append(*changes, Change{
					Type:     ChangeModified,
					Path:     path,
					OldValue: oldVal,
					NewValue: newVal,
				})
			}
		}
	}

	for key, newVal := range new {
		path := key
		if prefix != "" {
			path = prefix + "." + key
		}

		if _, exists := old[key]; !exists {
			*changes = append(*changes, Change{
				Type:     ChangeAdded,
				Path:     path,
				NewValue: newVal,
			})
		}
	}
}

func (m *Manager) notifyCallbacks(changes []Change, _ map[string]interface{}) {
	for _, callback := range m.callbacks {
		if err := callback(changes); err != nil {
			log.Warn("Callback error: %v", err)
		}
	}
}

func (m *Manager) backupConfig() {
	if err := os.MkdirAll(m.config.BackupDir, 0755); err != nil {
		log.Warn("Failed to create backup dir: %v", err)
		return
	}

	filename := fmt.Sprintf("config_%s.yaml", time.Now().Format("20060102_150405"))
	path := filepath.Join(m.config.BackupDir, filename)

	data, err := yaml.Marshal(m.current)
	if err != nil {
		log.Warn("Failed to marshal config for backup: %v", err)
		return
	}

	if err := os.WriteFile(path, data, 0644); err != nil {
		log.Warn("Failed to write backup: %v", err)
		return
	}

	m.cleanupBackups()
}

func (m *Manager) cleanupBackups() {
	entries, err := os.ReadDir(m.config.BackupDir)
	if err != nil {
		return
	}

	if len(entries) <= m.config.MaxBackups {
		return
	}
	toRemove := len(entries) - m.config.MaxBackups
	for i := 0; i < toRemove; i++ {
		path := filepath.Join(m.config.BackupDir, entries[i].Name())
		os.Remove(path)
	}
}

func (m *Manager) Get(path string) (interface{}, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	return m.getPathLocked(m.current, path)
}

func (m *Manager) getPathLocked(config map[string]interface{}, path string) (interface{}, bool) {
	parts := splitPath(path)
	current := interface{}(config)

	for _, part := range parts {
		switch v := current.(type) {
		case map[string]interface{}:
			val, ok := v[part]
			if !ok {
				return nil, false
			}
			current = val
		default:
			return nil, false
		}
	}

	return current, true
}

func (m *Manager) GetString(path string, defaultVal string) string {
	val, ok := m.Get(path)
	if !ok {
		return defaultVal
	}
	if s, ok := val.(string); ok {
		return s
	}
	return defaultVal
}

func (m *Manager) GetInt(path string, defaultVal int) int {
	val, ok := m.Get(path)
	if !ok {
		return defaultVal
	}
	switch v := val.(type) {
	case int:
		return v
	case float64:
		return int(v)
	case int64:
		return int(v)
	}
	return defaultVal
}

func (m *Manager) GetBool(path string, defaultVal bool) bool {
	val, ok := m.Get(path)
	if !ok {
		return defaultVal
	}
	if b, ok := val.(bool); ok {
		return b
	}
	return defaultVal
}

func (m *Manager) GetDuration(path string, defaultVal time.Duration) time.Duration {
	val, ok := m.Get(path)
	if !ok {
		return defaultVal
	}
	switch v := val.(type) {
	case string:
		d, err := time.ParseDuration(v)
		if err != nil {
			return defaultVal
		}
		return d
	case time.Duration:
		return v
	}
	return defaultVal
}

func (m *Manager) Set(path string, value interface{}) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.config.ValidateOnChange {
		tempConfig := deepCopyMap(m.current)
		setPath(tempConfig, path, value)
		for _, validator := range m.validators {
			if err := validator(tempConfig); err != nil {
				return fmt.Errorf("validation failed: %w", err)
			}
		}
	}

	oldValue, _ := m.getPathLocked(m.current, path)
	setPath(m.current, path, value)

	changes := []Change{{
		Type:     ChangeModified,
		Path:     path,
		OldValue: oldValue,
		NewValue: value,
	}}
	go m.notifyCallbacks(changes, nil)

	return nil
}

func (m *Manager) Save() error {
	m.mu.RLock()
	config := deepCopyMap(m.current)
	m.mu.RUnlock()

	var data []byte
	var err error
	ext := filepath.Ext(m.config.FilePath)

	switch ext {
	case ".yaml", ".yml":
		data, err = yaml.Marshal(config)
	case ".json":
		data, err = json.MarshalIndent(config, "", "  ")
	default:
		return fmt.Errorf("unsupported config format: %s", ext)
	}

	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	if m.config.AtomicLoad {
		tempPath := m.config.FilePath + ".tmp"
		if err := os.WriteFile(tempPath, data, 0644); err != nil {
			return fmt.Errorf("failed to write temp file: %w", err)
		}
		if err := os.Rename(tempPath, m.config.FilePath); err != nil {
			os.Remove(tempPath)
			return fmt.Errorf("failed to rename temp file: %w", err)
		}
	} else {
		if err := os.WriteFile(m.config.FilePath, data, 0644); err != nil {
			return fmt.Errorf("failed to write config: %w", err)
		}
	}

	return nil
}

func (m *Manager) AddValidator(validator func(map[string]interface{}) error) {
	m.mu.Lock()
	m.validators = append(m.validators, validator)
	m.mu.Unlock()
}

func (m *Manager) AddCallback(callback Callback) {
	m.mu.Lock()
	m.callbacks = append(m.callbacks, callback)
	m.mu.Unlock()
}

func (m *Manager) watchLoop() {
	defer m.wg.Done()

	ticker := time.NewTicker(m.config.WatchInterval)
	defer ticker.Stop()

	for {
		select {
		case <-m.stopCh:
			return
		case <-ticker.C:
			if err := m.Load(); err != nil {
				atomic.AddUint64(&m.reloadErrors, 1)
				m.mu.Lock()
				m.lastReloadErr = err.Error()
				m.mu.Unlock()
				log.Warn("Failed to reload config: %v", err)
			}
		}
	}
}

func splitPath(path string) []string {
	var parts []string
	current := ""
	for _, c := range path {
		if c == '.' {
			if current != "" {
				parts = append(parts, current)
				current = ""
			}
		} else {
			current += string(c)
		}
	}
	if current != "" {
		parts = append(parts, current)
	}
	return parts
}

func setPath(config map[string]interface{}, path string, value interface{}) {
	parts := splitPath(path)
	current := config

	for i, part := range parts {
		if i == len(parts)-1 {
			current[part] = value
			return
		}

		if next, ok := current[part].(map[string]interface{}); ok {
			current = next
		} else {
			newMap := make(map[string]interface{})
			current[part] = newMap
			current = newMap
		}
	}
}

func deepCopyMap(m map[string]interface{}) map[string]interface{} {
	result := make(map[string]interface{})
	for k, v := range m {
		if nested, ok := v.(map[string]interface{}); ok {
			result[k] = deepCopyMap(nested)
		} else {
			result[k] = v
		}
	}
	return result
}

func (m *Manager) Init(ctx context.Context) error {
	return m.Load()
}

func (m *Manager) Start(ctx context.Context) error {
	if m.config.WatchEnabled {
		m.wg.Add(1)
		go m.watchLoop()
	}
	return nil
}

func (m *Manager) Stop(ctx context.Context) error {
	close(m.stopCh)
	m.wg.Wait()
	return nil
}

func (m *Manager) Stats() map[string]interface{} {
	m.mu.RLock()
	defer m.mu.RUnlock()

	return map[string]interface{}{
		"reload_count":    atomic.LoadUint64(&m.reloadCount),
		"reload_errors":   atomic.LoadUint64(&m.reloadErrors),
		"last_reload":     m.lastReload,
		"last_reload_err": m.lastReloadErr,
		"keys_count":      len(m.current),
	}
}
