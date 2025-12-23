package server

import (
	"context"
	"fmt"
	"log"
	"sync"
	"time"

	cfgpkg "whispera/internal/config"
	"whispera/internal/obfuscation"
	routingpkg "whispera/internal/routing"
	protopkg "whispera/internal/proto"
	xhttppkg "whispera/internal/xhttp"
)

// ServerRuntime управляет всеми runtime компонентами сервера
// и позволяет безопасно перезагружать конфигурацию без полного рестарта
type ServerRuntime struct {
	mu sync.RWMutex

	// Конфигурация
	config *cfgpkg.ServerConfig

	// Core компоненты
	sessionMgr     *SessionManager
	routingEngine  *routingpkg.Engine
	metadataRouter *xhttppkg.MetadataRouter

	// Obfuscation
	coreIM *obfuscation.IntegrationManager

	// XHTTP
	xhttpConfig *xhttppkg.XHTTPConfig

	// STREAM‑мультиплексор (TUN → STREAM), чтобы можно было менять padding в рантайме
	mux *protopkg.ConcurrentStreamMultiplexer

	// Callbacks для интеграции с внешним (cmd/server) кодом
	dnsUpstreamCallback  func(oldVal, newVal string)
	xhttpTargetCallback  func(oldVal, newVal string)
	hsLimiterCallback    func(rate float64, burst int)
	mtuCallback          func(newMTU int)
	xhttpMaxConcurrencyCallback func(newMaxConcurrency int)
	chaffCallback        func(sec int, dist string, alpha, xm float64, sizeMin, sizeMax, dutyOn, dutyOff int)
	ampCallback          func(maxRatio float64, maxBytes int)

	// Geo updater
	geoUpdater *routingpkg.GeoUpdater

	// State
	running bool
	ctx     context.Context
	cancel  context.CancelFunc
}

// NewServerRuntime создает новый ServerRuntime с начальной конфигурацией
func NewServerRuntime(cfg *cfgpkg.ServerConfig) *ServerRuntime {
	ctx, cancel := context.WithCancel(context.Background())

	rt := &ServerRuntime{
		config:  cfg,
		ctx:     ctx,
		cancel:  cancel,
		running: false,
	}

	// Инициализируем компоненты
	rt.initializeComponents()

	return rt
}

// initializeComponents инициализирует все runtime компоненты
func (rt *ServerRuntime) initializeComponents() {
	rt.mu.Lock()
	defer rt.mu.Unlock()

	// Вычисляем таймаут сессий на основе конфигурации.
	// Базовый дефолт — 30 минут, но если задан keepalive, делаем timeout кратным ему.
	sessionTimeout := 30 * time.Minute
	if rt.config != nil && rt.config.KeepaliveSec > 0 {
		// Сессия живет минимум 4 keepalive‑интервала (но не меньше 5 минут и не больше 2 часов).
		t := time.Duration(rt.config.KeepaliveSec*4) * time.Second
		if t < 5*time.Minute {
			t = 5 * time.Minute
		}
		if t > 2*time.Hour {
			t = 2 * time.Hour
		}
		sessionTimeout = t
	}

	// SessionManager
	rt.sessionMgr = NewSessionManager(sessionTimeout)

	// Routing Engine
	rt.routingEngine = routingpkg.NewEngine()

	// MetadataRouter
	rt.metadataRouter = xhttppkg.NewMetadataRouter(nil)
	rt.metadataRouter.SetEngine(rt.routingEngine)
	xhttppkg.SetDefaultMetadataRouter(rt.metadataRouter)

	// Устанавливаем callback для удаления outbound tag при удалении сессии
	rt.sessionMgr.SetSessionRemovedCallback(func(sessionID uint32, outboundTag string) {
		if rt.routingEngine != nil {
			rt.routingEngine.GetOutboundManager().UnregisterOutbound(sessionID)
		}
	})
}

// Start запускает runtime компоненты
func (rt *ServerRuntime) Start() error {
	rt.mu.Lock()
	defer rt.mu.Unlock()

	if rt.running {
		return fmt.Errorf("runtime is already running")
	}

	// Запускаем subscriptions если они есть
	if rt.routingEngine != nil {
		rt.routingEngine.StartSubscriptions()
	}

	rt.running = true
	log.Printf("[Runtime] ServerRuntime started")
	return nil
}

// Stop останавливает runtime компоненты
func (rt *ServerRuntime) Stop() error {
	rt.mu.Lock()
	defer rt.mu.Unlock()

	if !rt.running {
		return nil
	}

	// Останавливаем subscriptions
	if rt.routingEngine != nil {
		rt.routingEngine.StopSubscriptions()
	}

	// Отменяем контекст
	if rt.cancel != nil {
		rt.cancel()
	}

	rt.running = false
	log.Printf("[Runtime] ServerRuntime stopped")
	return nil
}

// Reload безопасно перезагружает конфигурацию
// Возвращает список измененных полей и ошибку
func (rt *ServerRuntime) Reload(newCfg *cfgpkg.ServerConfig) ([]string, error) {
	rt.mu.Lock()
	defer rt.mu.Unlock()

	if !rt.running {
		return nil, fmt.Errorf("runtime is not running, cannot reload")
	}

	changes := []string{}
	oldCfg := rt.config

	// Сравниваем конфигурации и определяем изменения
	if oldCfg.DNSUpstream != newCfg.DNSUpstream {
		changes = append(changes, "dns_upstream")
		// DNS upstream можно обновить без рестарта (если есть DNS resolver)
		log.Printf("[Runtime] DNS upstream changed: %s -> %s", oldCfg.DNSUpstream, newCfg.DNSUpstream)

		// Уведомляем внешний код (cmd/server) через callback
		if rt.dnsUpstreamCallback != nil {
			rt.dnsUpstreamCallback(oldCfg.DNSUpstream, newCfg.DNSUpstream)
		}
	}

	if oldCfg.KeepaliveSec != newCfg.KeepaliveSec {
		changes = append(changes, "keepalive")
		log.Printf("[Runtime] Keepalive changed: %d -> %d", oldCfg.KeepaliveSec, newCfg.KeepaliveSec)

		// Привязываем KeepaliveSec к таймауту сессий/потоков (live‑reload).
		if rt.sessionMgr != nil {
			newTimeout := time.Duration(newCfg.KeepaliveSec*4) * time.Second
			if newTimeout < 5*time.Minute {
				newTimeout = 5 * time.Minute
			}
			if newTimeout > 2*time.Hour {
				newTimeout = 2 * time.Hour
			}
			rt.sessionMgr.SetTimeout(newTimeout)
			log.Printf("[Runtime] SessionManager timeout updated to %v based on keepalive=%d", newTimeout, newCfg.KeepaliveSec)
		}
	}

	if oldCfg.MTU != newCfg.MTU {
		changes = append(changes, "mtu")
		log.Printf("[Runtime] MTU changed: %d -> %d", oldCfg.MTU, newCfg.MTU)

		// Применяем новый MTU через callback (обновляет maxUDPPacket и глобальный флаг)
		if rt.mtuCallback != nil {
			rt.mtuCallback(newCfg.MTU)
		}
	}

	// Handshake rate/ burst limits
	if oldCfg.HSRate != newCfg.HSRate || oldCfg.HSBurst != newCfg.HSBurst {
		changes = append(changes, "hs_limits")
		log.Printf("[Runtime] Handshake limits changed: rate=%.2f->%.2f, burst=%d->%d",
			oldCfg.HSRate, newCfg.HSRate, oldCfg.HSBurst, newCfg.HSBurst)

		if rt.hsLimiterCallback != nil {
			rt.hsLimiterCallback(newCfg.HSRate, newCfg.HSBurst)
		}
	}

	// Obfuscation settings
	if oldCfg.PadMin != newCfg.PadMin || oldCfg.PadMax != newCfg.PadMax {
		changes = append(changes, "padding")
		log.Printf("[Runtime] Padding changed: [%d-%d] -> [%d-%d]",
			oldCfg.PadMin, oldCfg.PadMax, newCfg.PadMin, newCfg.PadMax)

		// Если есть зарегистрированный mux, обновляем его конфигурацию padding на лету
		if rt.mux != nil {
			enabled := newCfg.PadMin > 0 || newCfg.PadMax > 0
			pcfg := &protopkg.MuxPaddingConfig{
				Enabled: enabled,
				MinSize: newCfg.PadMin,
				MaxSize: newCfg.PadMax,
			}
			rt.mux.SetPaddingConfig(pcfg)
			log.Printf("[Runtime] Updated mux padding config: enabled=%v, min=%d, max=%d", enabled, newCfg.PadMin, newCfg.PadMax)
		}
	}

	if oldCfg.ObfsPreset != newCfg.ObfsPreset {
		changes = append(changes, "obfs_preset")
		log.Printf("[Runtime] Obfs preset changed: %s -> %s", oldCfg.ObfsPreset, newCfg.ObfsPreset)

		// Если используется Marionette, пробуем переключить профиль на лету.
		// Предполагаем, что ObfsPreset соответствует имени профиля (или алиасу),
		// в противном случае Marionette вернет ошибку, которую просто залогируем.
		if rt.coreIM != nil && newCfg.ObfsPreset != "" {
			if err := rt.coreIM.SetProfile(newCfg.ObfsPreset); err != nil {
				log.Printf("[Runtime] Failed to switch Marionette profile to %q: %v", newCfg.ObfsPreset, err)
			} else {
				log.Printf("[Runtime] Marionette profile switched to %q via ObfsPreset", newCfg.ObfsPreset)
			}
		}
	}

	// Chaff (server-originated keepalive padding)
	if oldCfg.ChaffSec != newCfg.ChaffSec ||
		oldCfg.ChaffDist != newCfg.ChaffDist ||
		oldCfg.ChaffAlpha != newCfg.ChaffAlpha ||
		oldCfg.ChaffXm != newCfg.ChaffXm ||
		oldCfg.ChaffSizeMin != newCfg.ChaffSizeMin ||
		oldCfg.ChaffSizeMax != newCfg.ChaffSizeMax ||
		oldCfg.ChaffDutyOn != newCfg.ChaffDutyOn ||
		oldCfg.ChaffDutyOff != newCfg.ChaffDutyOff {
		changes = append(changes, "chaff")
		log.Printf("[Runtime] Chaff config changed: sec=%d->%d dist=%s->%s alpha=%.2f->%.2f xm=%.2f->%.2f size=[%d-%d]->[%d-%d] duty_on=%d->%d duty_off=%d->%d",
			oldCfg.ChaffSec, newCfg.ChaffSec,
			oldCfg.ChaffDist, newCfg.ChaffDist,
			oldCfg.ChaffAlpha, newCfg.ChaffAlpha,
			oldCfg.ChaffXm, newCfg.ChaffXm,
			oldCfg.ChaffSizeMin, oldCfg.ChaffSizeMax,
			newCfg.ChaffSizeMin, newCfg.ChaffSizeMax,
			oldCfg.ChaffDutyOn, newCfg.ChaffDutyOn,
			oldCfg.ChaffDutyOff, newCfg.ChaffDutyOff,
		)

		if rt.chaffCallback != nil {
			rt.chaffCallback(
				newCfg.ChaffSec,
				newCfg.ChaffDist,
				newCfg.ChaffAlpha,
				newCfg.ChaffXm,
				newCfg.ChaffSizeMin,
				newCfg.ChaffSizeMax,
				newCfg.ChaffDutyOn,
				newCfg.ChaffDutyOff,
			)
		}
	}

	// XHTTP settings
	if oldCfg.XHTTPTarget != newCfg.XHTTPTarget {
		changes = append(changes, "xhttp_target")
		log.Printf("[Runtime] XHTTP target changed: %s -> %s", oldCfg.XHTTPTarget, newCfg.XHTTPTarget)

		// Уведомляем внешний код (cmd/server), чтобы он обновил свои флаги/состояние
		if rt.xhttpTargetCallback != nil {
			rt.xhttpTargetCallback(oldCfg.XHTTPTarget, newCfg.XHTTPTarget)
		}
	}

	if oldCfg.XHTTPMaxConcurrency != newCfg.XHTTPMaxConcurrency {
		changes = append(changes, "xhttp_max_concurrency")
		log.Printf("[Runtime] XHTTP max concurrency changed: %d -> %d",
			oldCfg.XHTTPMaxConcurrency, newCfg.XHTTPMaxConcurrency)

		// Применяем новый max concurrency через callback (обновляет глобальный флаг и mux, если есть)
		if rt.xhttpMaxConcurrencyCallback != nil {
			rt.xhttpMaxConcurrencyCallback(newCfg.XHTTPMaxConcurrency)
		}
	}

	// Обновляем конфигурацию
	rt.config = newCfg

	if len(changes) > 0 {
		log.Printf("[Runtime] Configuration reloaded, %d fields changed: %v", len(changes), changes)
	} else {
		log.Printf("[Runtime] Configuration reloaded, no changes detected")
	}

	return changes, nil
}

// GetSessionManager возвращает SessionManager
func (rt *ServerRuntime) GetSessionManager() *SessionManager {
	rt.mu.RLock()
	defer rt.mu.RUnlock()
	return rt.sessionMgr
}

// GetRoutingEngine возвращает RoutingEngine
func (rt *ServerRuntime) GetRoutingEngine() *routingpkg.Engine {
	rt.mu.RLock()
	defer rt.mu.RUnlock()
	return rt.routingEngine
}

// GetMetadataRouter возвращает MetadataRouter
func (rt *ServerRuntime) GetMetadataRouter() *xhttppkg.MetadataRouter {
	rt.mu.RLock()
	defer rt.mu.RUnlock()
	return rt.metadataRouter
}

// GetConfig возвращает текущую конфигурацию
func (rt *ServerRuntime) GetConfig() *cfgpkg.ServerConfig {
	rt.mu.RLock()
	defer rt.mu.RUnlock()
	return rt.config
}

// SetGeoUpdater устанавливает GeoUpdater
func (rt *ServerRuntime) SetGeoUpdater(updater *routingpkg.GeoUpdater) {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	rt.geoUpdater = updater
	if rt.routingEngine != nil {
		rt.routingEngine.SetGeoUpdater(updater)
	}
}

// SetCoreIM устанавливает IntegrationManager
func (rt *ServerRuntime) SetCoreIM(im *obfuscation.IntegrationManager) {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	rt.coreIM = im
}

// SetXHTTPConfig устанавливает XHTTP конфигурацию
func (rt *ServerRuntime) SetXHTTPConfig(cfg *xhttppkg.XHTTPConfig) {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	rt.xhttpConfig = cfg
}

// SetMux регистрирует ConcurrentStreamMultiplexer для управления padding в рантайме
func (rt *ServerRuntime) SetMux(mux *protopkg.ConcurrentStreamMultiplexer) {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	rt.mux = mux
}

// GetMux возвращает зарегистрированный ConcurrentStreamMultiplexer
func (rt *ServerRuntime) GetMux() *protopkg.ConcurrentStreamMultiplexer {
	rt.mu.RLock()
	defer rt.mu.RUnlock()
	return rt.mux
}

// SetDNSUpstreamCallback регистрирует callback для изменения DNS upstream
func (rt *ServerRuntime) SetDNSUpstreamCallback(cb func(oldVal, newVal string)) {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	rt.dnsUpstreamCallback = cb
}

// SetXHTTPTargetCallback регистрирует callback для изменения XHTTP target
func (rt *ServerRuntime) SetXHTTPTargetCallback(cb func(oldVal, newVal string)) {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	rt.xhttpTargetCallback = cb
}

// SetHandshakeLimiterCallback регистрирует callback для изменения лимитов handshake
func (rt *ServerRuntime) SetHandshakeLimiterCallback(cb func(rate float64, burst int)) {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	rt.hsLimiterCallback = cb
}

// SetMTUCallback регистрирует callback для изменения MTU
func (rt *ServerRuntime) SetMTUCallback(cb func(newMTU int)) {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	rt.mtuCallback = cb
}

// SetXHTTPMaxConcurrencyCallback регистрирует callback для изменения XHTTP max concurrency
func (rt *ServerRuntime) SetXHTTPMaxConcurrencyCallback(cb func(newMaxConcurrency int)) {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	rt.xhttpMaxConcurrencyCallback = cb
}

// SetChaffCallback регистрирует callback для изменения chaff-конфига
func (rt *ServerRuntime) SetChaffCallback(cb func(sec int, dist string, alpha, xm float64, sizeMin, sizeMax, dutyOn, dutyOff int)) {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	rt.chaffCallback = cb
}

// SetAmpCallback регистрирует callback для изменения anti-amplification лимитов
func (rt *ServerRuntime) SetAmpCallback(cb func(maxRatio float64, maxBytes int)) {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	rt.ampCallback = cb
}

