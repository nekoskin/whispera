package main

import (
	"log"
	"sync"

	apipkg "whispera/internal/api"
	routingpkg "whispera/internal/routing"
)

var routingRulesMu sync.RWMutex

// loadRoutingRulesFromAPI загружает routing rules из API сервера
func loadRoutingRulesFromAPI(apiServer *apipkg.APIServer) {
	if apiServer == nil || routingEngine == nil {
		return
	}

	// Получаем ManagementAPI из APIServer
	managementAPI := apiServer.GetManagementAPI()
	if managementAPI == nil {
		return
	}

	// Получаем routing manager
	routingMgr := managementAPI.GetRoutingManager()
	if routingMgr == nil {
		return
	}

	// Загружаем правила в routing engine
	routingRulesMu.Lock()
	defer routingRulesMu.Unlock()

	// Конвертируем API правила в формат routing engine
	apiRulesList := routingMgr.GetRules()
	apiRules := make([]routingpkg.APIRule, 0, len(apiRulesList))
	for _, apiRule := range apiRulesList {
		apiRules = append(apiRules, routingpkg.APIRule{
			Type:        apiRule.Type,
			Domain:      apiRule.Domain,
			IP:          apiRule.IP,
			Port:        apiRule.Port,
			Network:     apiRule.Network,
			Source:      apiRule.Source,
			OutboundTag: apiRule.OutboundTag,
			BalancerTag: apiRule.BalancerTag,
			Enabled:     apiRule.Enabled,
			Priority:    0, // По умолчанию
		})
	}

	if err := routingEngine.LoadRules(apiRules); err != nil {
		log.Printf("[ROUTING] Failed to load rules from API: %v", err)
		return
	}

	rules := routingEngine.GetRules()
	log.Printf("[ROUTING] Loaded %d routing rules from API", len(rules))
}

// GetRoutingEngine возвращает глобальный routing engine (для использования в других пакетах)
func GetRoutingEngine() *routingpkg.Engine {
	return routingEngine
}

