//go:build !windows

package tun

import (
	"context"
	"fmt"
	"log"
	"sync"
	"sync/atomic"
	"time"

	"whispera/internal/obfuscation"
	"whispera/internal/obfuscation/core/types"

	"github.com/songgao/water"
)

const (
	// maxMLWorkers ограничивает количество параллельных горутин для ML обработки
	// Предотвращает утечку горутин при высокой нагрузке
	maxMLWorkers = 10
	// defaultMTU стандартный MTU для TUN интерфейса
	defaultMTU = 1420
)

// Interface представляет TUN/TAP интерфейс с улучшенной обработкой
type Interface struct {
	dev        *water.Interface
	deviceType DeviceType // Тип устройства (TUN или TAP)
	mlSystem   *obfuscation.UnifiedMLSystem
	mlWorkers  chan struct{} // Semaphore для ограничения количества горутин
	ctx        context.Context
	cancel     context.CancelFunc
	closed     int32 // Atomic flag для проверки закрытия
	mu         sync.RWMutex
	
	// Метрики производительности
	packetsRead    int64
	packetsWritten int64
	bytesRead      int64
	bytesWritten   int64
	mlSkipped      int64 // Пропущено ML обработок из-за переполнения
}

// DeviceType тип устройства (TUN или TAP)
type DeviceType int

const (
	DeviceTUN DeviceType = iota // TUN - только IP пакеты (L3)
	DeviceTAP                   // TAP - Ethernet фреймы (L2)
)

// OpenOptions опции для открытия TUN/TAP интерфейса
type OpenOptions struct {
	Name          string      // Имя интерфейса
	DeviceType    DeviceType  // Тип устройства (TUN или TAP, по умолчанию TUN)
	EnableML      bool        // Включить ML обработку (по умолчанию true)
	MLWorkers     int         // Количество ML воркеров (по умолчанию maxMLWorkers)
	Context       context.Context // Контекст для отмены операций
}

func Open(name string) (*Interface, error) {
	return OpenWithOptions(OpenOptions{Name: name, DeviceType: DeviceTUN, EnableML: true})
}

// OpenTAP открывает TAP интерфейс
func OpenTAP(name string) (*Interface, error) {
	return OpenWithOptions(OpenOptions{Name: name, DeviceType: DeviceTAP, EnableML: true})
}

// OpenWithOptions открывает TUN/TAP интерфейс с опциями
func OpenWithOptions(opts OpenOptions) (*Interface, error) {
	// Определяем тип устройства
	deviceType := opts.DeviceType
	if deviceType == 0 { // По умолчанию TUN
		deviceType = DeviceTUN
	}
	
	var waterDeviceType water.DeviceType
	if deviceType == DeviceTAP {
		waterDeviceType = water.TAP
	} else {
		waterDeviceType = water.TUN
	}
	
	cfg := water.Config{DeviceType: waterDeviceType}
	if opts.Name != "" {
		cfg.Name = opts.Name
	}
	
	dev, err := water.New(cfg)
	if err != nil {
		deviceTypeStr := "TUN"
		if deviceType == DeviceTAP {
			deviceTypeStr = "TAP"
		}
		return nil, fmt.Errorf("open %s: %w", deviceTypeStr, err)
	}

	ctx := opts.Context
	if ctx == nil {
		ctx = context.Background()
	}
	ctx, cancel := context.WithCancel(ctx)

	mlWorkers := opts.MLWorkers
	if mlWorkers <= 0 {
		mlWorkers = maxMLWorkers
	}

	var mlSystem *obfuscation.UnifiedMLSystem
	if opts.EnableML {
		mlSystem = obfuscation.NewUnifiedMLSystem()
	}

	return &Interface{
		dev:        dev,
		deviceType: deviceType,
		mlSystem:   mlSystem,
		mlWorkers:  make(chan struct{}, mlWorkers),
		ctx:        ctx,
		cancel:     cancel,
		closed:     0,
	}, nil
}

// IsTAP проверяет, является ли интерфейс TAP
func (i *Interface) IsTAP() bool {
	return i.deviceType == DeviceTAP
}

// IsTUN проверяет, является ли интерфейс TUN
func (i *Interface) IsTUN() bool {
	return i.deviceType == DeviceTUN
}

// Name возвращает имя интерфейса
func (i *Interface) Name() string {
	if i.dev == nil {
		return ""
	}
	return i.dev.Name()
}

// Close закрывает TUN интерфейс с graceful shutdown
func (i *Interface) Close() error {
	// Атомарно устанавливаем флаг закрытия
	if !atomic.CompareAndSwapInt32(&i.closed, 0, 1) {
		return nil // Уже закрыт
	}

	// Отменяем контекст для остановки всех операций
	if i.cancel != nil {
		i.cancel()
	}

	// Ждем завершения всех ML операций (с таймаутом)
	done := make(chan struct{})
	go func() {
		// Освобождаем все слоты в worker pool
		for j := 0; j < cap(i.mlWorkers); j++ {
			select {
			case <-i.mlWorkers:
			default:
			}
		}
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		log.Printf("[TUN] Warning: ML workers did not finish within timeout")
	}

	// Закрываем устройство
	if i.dev != nil {
		return i.dev.Close()
	}
	return nil
}

// IsClosed проверяет, закрыт ли интерфейс
func (i *Interface) IsClosed() bool {
	return atomic.LoadInt32(&i.closed) == 1
}

// Read читает пакет из TUN интерфейса
// ИСПРАВЛЕНО: Read это outbound (из системы в VPN)
func (i *Interface) Read(p []byte) (int, error) {
	if i.IsClosed() {
		return 0, fmt.Errorf("TUN interface is closed")
	}

	if i.dev == nil {
		return 0, fmt.Errorf("TUN device is nil")
	}

	n, err := i.dev.Read(p)
	if err != nil {
		return n, err
	}

	if n > 0 {
		atomic.AddInt64(&i.packetsRead, 1)
		atomic.AddInt64(&i.bytesRead, int64(n))
	}

	// ML анализ outbound трафика (из системы в VPN) - опционально
	if err == nil && n > 0 && i.mlSystem != nil && !i.IsClosed() {
		// Копируем данные перед передачей в горутину
		dataCopy := make([]byte, n)
		copy(dataCopy, p[:n])
		
		// ML анализ с ограничением через worker pool
		select {
		case i.mlWorkers <- struct{}{}:
			go func(data []byte, size int) {
				defer func() { <-i.mlWorkers }()
				
				// Проверяем контекст перед обработкой
				select {
				case <-i.ctx.Done():
					return
				default:
				}
				
				context := &types.UnifiedTrafficContext{
					Direction: "outbound", // ИСПРАВЛЕНО: Read это outbound
					Protocol:  "TUN",
					Size:      size,
					Timestamp: time.Now(),
				}
				if _, err := i.mlSystem.ProcessTraffic(data[:size], context); err != nil {
					log.Printf("[TUN] Error processing outbound traffic: %v", err)
				}
			}(dataCopy, n)
		default:
			// Worker pool переполнен - пропускаем ML обработку
			atomic.AddInt64(&i.mlSkipped, 1)
		}
	}

	return n, err
}

// Write записывает пакет в TUN интерфейс
// ИСПРАВЛЕНО: Write это inbound (из VPN в систему)
func (i *Interface) Write(p []byte) (int, error) {
	if i.IsClosed() {
		return 0, fmt.Errorf("TUN interface is closed")
	}

	if i.dev == nil {
		return 0, fmt.Errorf("TUN device is nil")
	}

	n, err := i.dev.Write(p)
	if err != nil {
		return n, err
	}

	if n > 0 {
		atomic.AddInt64(&i.packetsWritten, 1)
		atomic.AddInt64(&i.bytesWritten, int64(n))
	}

	// ML анализ inbound трафика (из VPN в систему) - опционально
	if err == nil && n > 0 && i.mlSystem != nil && !i.IsClosed() {
		// Копируем данные перед передачей в горутину
		dataCopy := make([]byte, n)
		copy(dataCopy, p[:n])
		
		// ML анализ с ограничением через worker pool
		select {
		case i.mlWorkers <- struct{}{}:
			go func(data []byte, size int) {
				defer func() { <-i.mlWorkers }()
				
				// Проверяем контекст перед обработкой
				select {
				case <-i.ctx.Done():
					return
				default:
				}
				
				context := &types.UnifiedTrafficContext{
					Direction: "inbound", // ИСПРАВЛЕНО: Write это inbound
					Protocol:  "TUN",
					Size:      size,
					Timestamp: time.Now(),
				}
				if _, err := i.mlSystem.ProcessTraffic(data[:size], context); err != nil {
					log.Printf("[TUN] Error processing inbound traffic: %v", err)
				}
			}(dataCopy, n)
		default:
			// Worker pool переполнен - пропускаем ML обработку
			atomic.AddInt64(&i.mlSkipped, 1)
		}
	}

	return n, err
}

// Stats возвращает статистику интерфейса
type Stats struct {
	PacketsRead    int64
	PacketsWritten int64
	BytesRead      int64
	BytesWritten   int64
	MLSkipped      int64
	IsClosed       bool
}

// GetStats возвращает текущую статистику
func (i *Interface) GetStats() Stats {
	return Stats{
		PacketsRead:    atomic.LoadInt64(&i.packetsRead),
		PacketsWritten: atomic.LoadInt64(&i.packetsWritten),
		BytesRead:      atomic.LoadInt64(&i.bytesRead),
		BytesWritten:   atomic.LoadInt64(&i.bytesWritten),
		MLSkipped:      atomic.LoadInt64(&i.mlSkipped),
		IsClosed:       i.IsClosed(),
	}
}
