//go:build windows
// +build windows

package tun

import (
	"context"
	"fmt"
	"log"
	"os/exec"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"whispera/internal/obfuscation"
	"whispera/internal/obfuscation/core/types"

	"golang.zx2c4.com/wintun"
)

// wintunWrapper обертка для wintun интерфейса, совместимая с Interface
type wintunWrapper struct {
	adapter     *wintun.Adapter
	session     wintun.Session
	adapterName string
	deviceType  DeviceType // Всегда DeviceTUN для wintun
	mlSystem    *obfuscation.UnifiedMLSystem
	mlWorkers   chan struct{}
	ctx         context.Context
	cancel      context.CancelFunc
	closed      int32
	mu          sync.RWMutex
	
	// Метрики производительности
	packetsRead    int64
	packetsWritten int64
	bytesRead      int64
	bytesWritten   int64
	mlSkipped      int64
}

// removeOldWintunAdapters удаляет старые wintun адаптеры перед созданием нового
// Это необходимо, чтобы избежать переиспользования старых адаптеров с неправильным именем/описанием
func removeOldWintunAdapters(newName string) {
	log.Printf("[TUN] Checking for old wintun adapters to remove...")
	
	// Удаляем старые адаптеры через PowerShell
	psScript := fmt.Sprintf(`
$ErrorActionPreference = "SilentlyContinue"
$adapters = Get-NetAdapter | Where-Object { 
    ($_.Name -like "*whispera*" -or $_.Name -eq "whispera0") -and 
    ($_.InterfaceDescription -like "*Whispera VPN*" -or $_.InterfaceDescription -like "*wintun*" -or $_.InterfaceDescription -like "*Meta Tunnel*")
}
if ($adapters) {
    foreach ($adapter in $adapters) {
        if ($adapter.Name -ne "%s") {
            Write-Output ("Removing old adapter: " + $adapter.Name)
            Remove-NetAdapter -Name $adapter.Name -Confirm:$false -ErrorAction SilentlyContinue | Out-Null
        }
    }
    Start-Sleep -Milliseconds 500
}
`, newName)
	
	cmd := exec.Command("powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", psScript)
	if output, err := cmd.CombinedOutput(); err == nil {
		outStr := strings.TrimSpace(string(output))
		if outStr != "" {
			log.Printf("[TUN] Old adapters cleanup: %s", outStr)
		}
	}
}

// tryWintun пытается создать TUN интерфейс используя wintun
func tryWintun(name string) (*Interface, error) {
	if name == "" {
		name = "Whispera" // Имя адаптера, как у Prizrak-Box (отображается в ncpa.cpl)
	}

	// Удаляем старые адаптеры перед созданием нового
	// Это гарантирует, что будет создан новый адаптер с правильным именем и описанием
	removeOldWintunAdapters(name)

	// Убеждаемся, что wintun.dll доступен
	log.Printf("[TUN] Checking for wintun.dll...")
	if err := ensureWintunDLL(); err != nil {
		log.Printf("[TUN] ❌ wintun.dll not available: %v", err)
		return nil, fmt.Errorf("wintun.dll not available: %w", err)
	}
	log.Printf("[TUN] ✅ wintun.dll found and loaded")

	// Создаем адаптер wintun
	// name - имя адаптера (отображается в ncpa.cpl как "Whispera")
	// "Meta" - описание/тип адаптера (wintun автоматически добавляет "Tunnel", получится "Meta Tunnel")
	log.Printf("[TUN] Creating wintun adapter: name=%q, type=%q", name, "Meta")
	adapter, err := wintun.CreateAdapter(name, "Meta", nil)
	if err != nil {
		log.Printf("[TUN] ❌ Failed to create wintun adapter: %v", err)
		return nil, fmt.Errorf("failed to create wintun adapter: %w", err)
	}
	log.Printf("[TUN] ✅ Wintun adapter created successfully")

	// Проверяем, что адаптер действительно создан (как в Prizrak-Box)
	// Небольшая задержка, чтобы Windows успел зарегистрировать адаптер
	time.Sleep(500 * time.Millisecond)
	
	// Проверяем через PowerShell, что адаптер появился в системе и активируем его (как в Prizrak-Box)
	psCheck := fmt.Sprintf(`
$ErrorActionPreference = "Stop"
$adapter = Get-NetAdapter | Where-Object {
    $_.InterfaceDescription -like "*Meta Tunnel*" -or
    $_.InterfaceDescription -like "*wintun*" -or
    $_.Name -eq "%s"
} | Select-Object -First 1
if ($adapter) {
    Write-Output ("Adapter found: " + $adapter.Name + " (" + $adapter.InterfaceDescription + ")")
    # Активируем адаптер (если он не активен)
    if ($adapter.Status -ne "Up") {
        Enable-NetAdapter -Name $adapter.Name -Confirm:$false -ErrorAction SilentlyContinue
        Write-Output ("Adapter enabled: " + $adapter.Name)
    }
} else {
    Write-Output "Adapter NOT found in system"
    exit 1
}
`, name)
	cmd := exec.Command("powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", psCheck)
	if output, err := cmd.CombinedOutput(); err == nil {
		outStr := strings.TrimSpace(string(output))
		if outStr != "" {
			log.Printf("[TUN] System check: %s", outStr)
		}
	} else {
		log.Printf("[TUN] ⚠️ PowerShell check failed: %v (output: %s)", err, string(output))
	}

	// Создаем сессию (возвращает Session, не указатель)
	log.Printf("[TUN] Starting wintun session (buffer: 8MB)...")
	session, err := adapter.StartSession(0x800000) // 8MB buffer
	if err != nil {
		log.Printf("[TUN] ❌ Failed to start wintun session: %v", err)
		adapter.Close()
		return nil, fmt.Errorf("failed to start wintun session: %w", err)
	}
	log.Printf("[TUN] ✅ Wintun session started successfully")

	ctx, cancel := context.WithCancel(context.Background())
	mlSystem := obfuscation.NewUnifiedMLSystem()

	wt := &wintunWrapper{
		adapter:     adapter,
		session:     session,
		adapterName: name,
		deviceType:  DeviceTUN, // wintun всегда TUN
		mlSystem:    mlSystem,
		mlWorkers:   make(chan struct{}, maxMLWorkers),
		ctx:         ctx,
		cancel:      cancel,
		closed:      0,
	}

	// Создаем обертку Interface с wintunWrapper
	return &Interface{
		dev:        nil, // wintun не использует water.Interface
		wintun:     wt,  // Сохраняем wintun обертку
		deviceType: DeviceTUN, // wintun всегда TUN
		mlSystem:   mlSystem,
		mlWorkers:  make(chan struct{}, maxMLWorkers),
		ctx:        ctx,
		cancel:     cancel,
		closed:     0,
	}, nil
}

// Name возвращает имя интерфейса
func (wt *wintunWrapper) Name() string {
	return wt.adapterName
}

// Close закрывает wintun интерфейс
func (wt *wintunWrapper) Close() error {
	if !atomic.CompareAndSwapInt32(&wt.closed, 0, 1) {
		return nil
	}

	if wt.cancel != nil {
		wt.cancel()
	}

	// Session.End() не требует проверки на nil, это метод значения
	wt.session.End()

	if wt.adapter != nil {
		wt.adapter.Close()
		wt.adapter = nil
	}

	return nil
}

// Read читает пакет из wintun интерфейса
func (wt *wintunWrapper) Read(p []byte) (int, error) {
	if atomic.LoadInt32(&wt.closed) == 1 {
		return 0, fmt.Errorf("wintun interface is closed")
	}

	// Читаем пакет из wintun
	packet, err := wt.session.ReceivePacket()
	if err != nil {
		return 0, err
	}

	n := copy(p, packet)
	wt.session.ReleaseReceivePacket(packet)

	if n > 0 {
		atomic.AddInt64(&wt.packetsRead, 1)
		atomic.AddInt64(&wt.bytesRead, int64(n))
	}

	// ML анализ outbound трафика
	if n > 0 && wt.mlSystem != nil && atomic.LoadInt32(&wt.closed) == 0 {
		dataCopy := make([]byte, n)
		copy(dataCopy, p[:n])
		
		select {
		case wt.mlWorkers <- struct{}{}:
			go func(data []byte, size int) {
				defer func() { <-wt.mlWorkers }()
				
				select {
				case <-wt.ctx.Done():
					return
				default:
				}
				
				context := &types.UnifiedTrafficContext{
					Direction: "outbound",
					Protocol:  "TUN",
					Size:      size,
					Timestamp: time.Now(),
				}
				if _, err := wt.mlSystem.ProcessTraffic(data[:size], context); err != nil {
					log.Printf("[TUN] Error processing outbound traffic: %v", err)
				}
			}(dataCopy, n)
		default:
			atomic.AddInt64(&wt.mlSkipped, 1)
		}
	}

	return n, nil
}

// Write записывает пакет в wintun интерфейс
func (wt *wintunWrapper) Write(p []byte) (int, error) {
	if atomic.LoadInt32(&wt.closed) == 1 {
		return 0, fmt.Errorf("wintun interface is closed")
	}

	// Выделяем буфер для пакета (возвращает []byte и error)
	packet, err := wt.session.AllocateSendPacket(len(p))
	if err != nil {
		return 0, fmt.Errorf("failed to allocate send packet: %w", err)
	}
	copy(packet, p)
	
	// Отправляем пакет
	wt.session.SendPacket(packet)

	if len(p) > 0 {
		atomic.AddInt64(&wt.packetsWritten, 1)
		atomic.AddInt64(&wt.bytesWritten, int64(len(p)))
	}

	// ML анализ inbound трафика
	if len(p) > 0 && wt.mlSystem != nil && atomic.LoadInt32(&wt.closed) == 0 {
		dataCopy := make([]byte, len(p))
		copy(dataCopy, p)
		
		select {
		case wt.mlWorkers <- struct{}{}:
			go func(data []byte, size int) {
				defer func() { <-wt.mlWorkers }()
				
				select {
				case <-wt.ctx.Done():
					return
				default:
				}
				
				context := &types.UnifiedTrafficContext{
					Direction: "inbound",
					Protocol:  "TUN",
					Size:      size,
					Timestamp: time.Now(),
				}
				if _, err := wt.mlSystem.ProcessTraffic(data[:size], context); err != nil {
					log.Printf("[TUN] Error processing inbound traffic: %v", err)
				}
			}(dataCopy, len(p))
		default:
			atomic.AddInt64(&wt.mlSkipped, 1)
		}
	}

	return len(p), nil
}

