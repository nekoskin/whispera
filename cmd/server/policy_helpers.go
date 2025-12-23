package main

import (
	"net"
	"sync"
	"time"

	apipkg "whispera/internal/api"
	srvpkg "whispera/internal/server"
)

var (
	globalManagementAPI *apipkg.ManagementAPI
	globalManagementAPIMu sync.RWMutex
)

// setGlobalManagementAPI устанавливает глобальный managementAPI для доступа из других пакетов
func setGlobalManagementAPI(api *apipkg.ManagementAPI) {
	globalManagementAPIMu.Lock()
	defer globalManagementAPIMu.Unlock()
	globalManagementAPI = api
}

// getGlobalManagementAPI возвращает глобальный managementAPI
func getGlobalManagementAPI() *apipkg.ManagementAPI {
	globalManagementAPIMu.RLock()
	defer globalManagementAPIMu.RUnlock()
	return globalManagementAPI
}

// checkPolicyBandwidth проверяет bandwidth limits для пользователя
func checkPolicyBandwidth(userID string, uploadBytes, downloadBytes int64) (uploadAllowed, downloadAllowed bool) {
	api := getGlobalManagementAPI()
	if api == nil {
		return true, true // Нет API - разрешено
	}
	
	// Получаем bandwidth enforcer через рефлексию или добавим метод GetBandwidthEnforcer
	// Пока используем прямой доступ через структуру (если поля экспортированы)
	// Для безопасности лучше добавить метод GetBandwidthEnforcer в ManagementAPI
	
	// Проверяем upload
	if !api.GetBandwidthEnforcer().RecordUpload(userID, uploadBytes) {
		return false, true
	}
	
	// Проверяем download
	if !api.GetBandwidthEnforcer().RecordDownload(userID, downloadBytes) {
		return true, false
	}
	
	return true, true
}

// checkPolicyConnection проверяет connection limits для пользователя
func checkPolicyConnection(userID, ipAddr string) bool {
	api := getGlobalManagementAPI()
	if api == nil {
		return true // Нет API - разрешено
	}
	
	return api.GetConnectionEnforcer().CheckConnection(userID, ipAddr)
}

// checkPolicyTimeBased проверяет time-based policies для пользователя
func checkPolicyTimeBased(userID string, now time.Time) bool {
	api := getGlobalManagementAPI()
	if api == nil {
		return true // Нет API - разрешено
	}
	
	return api.GetTimeBasedEnforcer().CheckTimeBasedPolicy(userID, now)
}

// getUserIDFromSession извлекает userID из сессии
func getUserIDFromSession(session *srvpkg.SessionState) string {
	if session == nil {
		return ""
	}
	session.Mu.RLock()
	defer session.Mu.RUnlock()
	return session.UserID
}

// getIPFromAddr извлекает IP адрес из net.Addr
func getIPFromAddr(addr net.Addr) string {
	if addr == nil {
		return ""
	}
	switch v := addr.(type) {
	case *net.UDPAddr:
		return v.IP.String()
	case *net.TCPAddr:
		return v.IP.String()
	default:
		return addr.String()
	}
}

// resolveUserID определяет userID для сессии
// Сначала пытается найти пользователя по IP адресу через API
// Если не найдено, использует IP адрес как временный идентификатор
func resolveUserID(ipAddr string, publicKeyHex string) string {
	api := getGlobalManagementAPI()
	if api == nil {
		// Нет API - используем IP адрес как идентификатор
		return "ip:" + ipAddr
	}
	
	// Пытаемся найти пользователя по публичному ключу (если передан)
	if publicKeyHex != "" {
		if userID := api.GetUserByPublicKey(publicKeyHex); userID != "" {
			return userID
		}
	}
	
	// Пытаемся найти пользователя по IP адресу
	if userID := api.GetUserByIP(ipAddr); userID != "" {
		return userID
	}
	
	// Не найдено - используем IP адрес как временный идентификатор
	// Это позволит применять политики на основе IP адреса
	return "ip:" + ipAddr
}

