package stats

import (
	"sync"
	"time"
)

// DetailedStats - детальная статистика по протоколам и транспортам
type DetailedStats struct {
	mu sync.RWMutex
	
	// Статистика по протоколам (TCP, UDP, ICMP)
	Protocols map[string]*ProtocolStats
	
	// Статистика по транспортам (tcp, udp, websocket, websocket2, grpc, quic, http2)
	Transports map[string]*TransportStats
	
	// Общая статистика
	Total *TotalStats
	
	// Время последнего обновления
	LastUpdate time.Time
}

// ProtocolStats - статистика по протоколу
type ProtocolStats struct {
	Protocol string
	
	// Пакеты
	PacketsRx int64
	PacketsTx int64
	PacketsDropped int64
	
	// Байты
	BytesRx int64
	BytesTx int64
	
	// Соединения
	ConnectionsActive int
	ConnectionsTotal int64
	ConnectionsClosed int64
	
	// Ошибки
	Errors int64
	
	// Время последнего обновления
	LastUpdate time.Time
}

// TransportStats - статистика по транспорту
type TransportStats struct {
	Transport string
	
	// Пакеты
	PacketsRx int64
	PacketsTx int64
	PacketsDropped int64
	
	// Байты
	BytesRx int64
	BytesTx int64
	
	// Соединения
	ConnectionsActive int
	ConnectionsTotal int64
	ConnectionsClosed int64
	
	// Handshakes
	HandshakesSuccess int64
	HandshakesFailed int64
	
	// Latency
	LatencyMin time.Duration
	LatencyMax time.Duration
	LatencyAvg time.Duration
	LatencySamples int64
	
	// Ошибки
	Errors int64
	
	// Время последнего обновления
	LastUpdate time.Time
}

// TotalStats - общая статистика
type TotalStats struct {
	// Пакеты
	PacketsRx int64
	PacketsTx int64
	PacketsDropped int64
	
	// Байты
	BytesRx int64
	BytesTx int64
	
	// Соединения
	ConnectionsActive int
	ConnectionsTotal int64
	ConnectionsClosed int64
	
	// Время последнего обновления
	LastUpdate time.Time
}

// NewDetailedStats создает новый сборщик детальной статистики
func NewDetailedStats() *DetailedStats {
	return &DetailedStats{
		Protocols: make(map[string]*ProtocolStats),
		Transports: make(map[string]*TransportStats),
		Total: &TotalStats{},
		LastUpdate: time.Now(),
	}
}

// RecordPacketRx записывает полученный пакет
func (ds *DetailedStats) RecordPacketRx(protocol, transport string, bytes int64) {
	ds.mu.Lock()
	defer ds.mu.Unlock()
	
	// Обновляем общую статистику
	ds.Total.PacketsRx++
	ds.Total.BytesRx += bytes
	
	// Обновляем статистику по протоколу
	if ds.Protocols[protocol] == nil {
		ds.Protocols[protocol] = &ProtocolStats{
			Protocol: protocol,
			LastUpdate: time.Now(),
		}
	}
	ds.Protocols[protocol].PacketsRx++
	ds.Protocols[protocol].BytesRx += bytes
	ds.Protocols[protocol].LastUpdate = time.Now()
	
	// Обновляем статистику по транспорту
	if ds.Transports[transport] == nil {
		ds.Transports[transport] = &TransportStats{
			Transport: transport,
			LastUpdate: time.Now(),
		}
	}
	ds.Transports[transport].PacketsRx++
	ds.Transports[transport].BytesRx += bytes
	ds.Transports[transport].LastUpdate = time.Now()
	
	ds.LastUpdate = time.Now()
}

// RecordPacketTx записывает отправленный пакет
func (ds *DetailedStats) RecordPacketTx(protocol, transport string, bytes int64) {
	ds.mu.Lock()
	defer ds.mu.Unlock()
	
	// Обновляем общую статистику
	ds.Total.PacketsTx++
	ds.Total.BytesTx += bytes
	
	// Обновляем статистику по протоколу
	if ds.Protocols[protocol] == nil {
		ds.Protocols[protocol] = &ProtocolStats{
			Protocol: protocol,
			LastUpdate: time.Now(),
		}
	}
	ds.Protocols[protocol].PacketsTx++
	ds.Protocols[protocol].BytesTx += bytes
	ds.Protocols[protocol].LastUpdate = time.Now()
	
	// Обновляем статистику по транспорту
	if ds.Transports[transport] == nil {
		ds.Transports[transport] = &TransportStats{
			Transport: transport,
			LastUpdate: time.Now(),
		}
	}
	ds.Transports[transport].PacketsTx++
	ds.Transports[transport].BytesTx += bytes
	ds.Transports[transport].LastUpdate = time.Now()
	
	ds.LastUpdate = time.Now()
}

// RecordPacketDropped записывает отброшенный пакет
func (ds *DetailedStats) RecordPacketDropped(protocol, transport string) {
	ds.mu.Lock()
	defer ds.mu.Unlock()
	
	ds.Total.PacketsDropped++
	
	if ds.Protocols[protocol] != nil {
		ds.Protocols[protocol].PacketsDropped++
		ds.Protocols[protocol].LastUpdate = time.Now()
	}
	
	if ds.Transports[transport] != nil {
		ds.Transports[transport].PacketsDropped++
		ds.Transports[transport].LastUpdate = time.Now()
	}
	
	ds.LastUpdate = time.Now()
}

// RecordConnectionOpen записывает открытие соединения
func (ds *DetailedStats) RecordConnectionOpen(transport string) {
	ds.mu.Lock()
	defer ds.mu.Unlock()
	
	ds.Total.ConnectionsActive++
	ds.Total.ConnectionsTotal++
	
	if ds.Transports[transport] == nil {
		ds.Transports[transport] = &TransportStats{
			Transport: transport,
			LastUpdate: time.Now(),
		}
	}
	ds.Transports[transport].ConnectionsActive++
	ds.Transports[transport].ConnectionsTotal++
	ds.Transports[transport].LastUpdate = time.Now()
	
	ds.LastUpdate = time.Now()
}

// RecordConnectionClose записывает закрытие соединения
func (ds *DetailedStats) RecordConnectionClose(transport string) {
	ds.mu.Lock()
	defer ds.mu.Unlock()
	
	if ds.Total.ConnectionsActive > 0 {
		ds.Total.ConnectionsActive--
	}
	ds.Total.ConnectionsClosed++
	
	if ds.Transports[transport] != nil {
		if ds.Transports[transport].ConnectionsActive > 0 {
			ds.Transports[transport].ConnectionsActive--
		}
		ds.Transports[transport].ConnectionsClosed++
		ds.Transports[transport].LastUpdate = time.Now()
	}
	
	ds.LastUpdate = time.Now()
}

// RecordHandshakeSuccess записывает успешный handshake
func (ds *DetailedStats) RecordHandshakeSuccess(transport string) {
	ds.mu.Lock()
	defer ds.mu.Unlock()
	
	if ds.Transports[transport] == nil {
		ds.Transports[transport] = &TransportStats{
			Transport: transport,
			LastUpdate: time.Now(),
		}
	}
	ds.Transports[transport].HandshakesSuccess++
	ds.Transports[transport].LastUpdate = time.Now()
	
	ds.LastUpdate = time.Now()
}

// RecordHandshakeFailed записывает неудачный handshake
func (ds *DetailedStats) RecordHandshakeFailed(transport string) {
	ds.mu.Lock()
	defer ds.mu.Unlock()
	
	if ds.Transports[transport] == nil {
		ds.Transports[transport] = &TransportStats{
			Transport: transport,
			LastUpdate: time.Now(),
		}
	}
	ds.Transports[transport].HandshakesFailed++
	ds.Transports[transport].LastUpdate = time.Now()
	
	ds.LastUpdate = time.Now()
}

// RecordLatency записывает задержку
func (ds *DetailedStats) RecordLatency(transport string, latency time.Duration) {
	ds.mu.Lock()
	defer ds.mu.Unlock()
	
	if ds.Transports[transport] == nil {
		ds.Transports[transport] = &TransportStats{
			Transport: transport,
			LastUpdate: time.Now(),
		}
	}
	
	ts := ds.Transports[transport]
	
	// Обновляем минимальную задержку
	if ts.LatencyMin == 0 || latency < ts.LatencyMin {
		ts.LatencyMin = latency
	}
	
	// Обновляем максимальную задержку
	if latency > ts.LatencyMax {
		ts.LatencyMax = latency
	}
	
	// Вычисляем среднюю задержку
	if ts.LatencySamples == 0 {
		ts.LatencyAvg = latency
	} else {
		// Экспоненциальное скользящее среднее
		alpha := 0.1
		ts.LatencyAvg = time.Duration(float64(ts.LatencyAvg)*(1-alpha) + float64(latency)*alpha)
	}
	ts.LatencySamples++
	ts.LastUpdate = time.Now()
	
	ds.LastUpdate = time.Now()
}

// RecordError записывает ошибку
func (ds *DetailedStats) RecordError(protocol, transport string) {
	ds.mu.Lock()
	defer ds.mu.Unlock()
	
	if ds.Protocols[protocol] != nil {
		ds.Protocols[protocol].Errors++
		ds.Protocols[protocol].LastUpdate = time.Now()
	}
	
	if ds.Transports[transport] != nil {
		ds.Transports[transport].Errors++
		ds.Transports[transport].LastUpdate = time.Now()
	}
	
	ds.LastUpdate = time.Now()
}

// GetStats возвращает копию статистики
func (ds *DetailedStats) GetStats() *DetailedStats {
	ds.mu.RLock()
	defer ds.mu.RUnlock()
	
	// Создаем глубокую копию
	stats := &DetailedStats{
		Protocols: make(map[string]*ProtocolStats),
		Transports: make(map[string]*TransportStats),
		Total: &TotalStats{
			PacketsRx: ds.Total.PacketsRx,
			PacketsTx: ds.Total.PacketsTx,
			PacketsDropped: ds.Total.PacketsDropped,
			BytesRx: ds.Total.BytesRx,
			BytesTx: ds.Total.BytesTx,
			ConnectionsActive: ds.Total.ConnectionsActive,
			ConnectionsTotal: ds.Total.ConnectionsTotal,
			ConnectionsClosed: ds.Total.ConnectionsClosed,
			LastUpdate: ds.Total.LastUpdate,
		},
		LastUpdate: ds.LastUpdate,
	}
	
	// Копируем статистику по протоколам
	for k, v := range ds.Protocols {
		stats.Protocols[k] = &ProtocolStats{
			Protocol: v.Protocol,
			PacketsRx: v.PacketsRx,
			PacketsTx: v.PacketsTx,
			PacketsDropped: v.PacketsDropped,
			BytesRx: v.BytesRx,
			BytesTx: v.BytesTx,
			ConnectionsActive: v.ConnectionsActive,
			ConnectionsTotal: v.ConnectionsTotal,
			ConnectionsClosed: v.ConnectionsClosed,
			Errors: v.Errors,
			LastUpdate: v.LastUpdate,
		}
	}
	
	// Копируем статистику по транспортам
	for k, v := range ds.Transports {
		stats.Transports[k] = &TransportStats{
			Transport: v.Transport,
			PacketsRx: v.PacketsRx,
			PacketsTx: v.PacketsTx,
			PacketsDropped: v.PacketsDropped,
			BytesRx: v.BytesRx,
			BytesTx: v.BytesTx,
			ConnectionsActive: v.ConnectionsActive,
			ConnectionsTotal: v.ConnectionsTotal,
			ConnectionsClosed: v.ConnectionsClosed,
			HandshakesSuccess: v.HandshakesSuccess,
			HandshakesFailed: v.HandshakesFailed,
			LatencyMin: v.LatencyMin,
			LatencyMax: v.LatencyMax,
			LatencyAvg: v.LatencyAvg,
			LatencySamples: v.LatencySamples,
			Errors: v.Errors,
			LastUpdate: v.LastUpdate,
		}
	}
	
	return stats
}

// Reset сбрасывает статистику
func (ds *DetailedStats) Reset() {
	ds.mu.Lock()
	defer ds.mu.Unlock()
	
	ds.Protocols = make(map[string]*ProtocolStats)
	ds.Transports = make(map[string]*TransportStats)
	ds.Total = &TotalStats{}
	ds.LastUpdate = time.Now()
}

