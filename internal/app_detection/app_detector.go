package app_detection //nolint:revive // Package name matches directory structure

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"
)

// ProcessInfo содержит информацию о процессе
type ProcessInfo struct {
	PID        int    `json:"pid"`
	Name       string `json:"name"`
	Path       string `json:"path"`
	Executable string `json:"executable"`
	StartTime  int64  `json:"start_time"`
}

// AppDetector детектирует запущенные приложения
type AppDetector struct {
	processes map[int]*ProcessInfo
	mu        sync.RWMutex
	scanning  bool
	stopCh    chan struct{}
}

// NewAppDetector создает новый детектор приложений
func NewAppDetector() *AppDetector {
	return &AppDetector{
		processes: make(map[int]*ProcessInfo),
		stopCh:    make(chan struct{}),
	}
}

// StartScanning начинает сканирование процессов
func (ad *AppDetector) StartScanning(interval time.Duration) {
	ad.mu.Lock()
	if ad.scanning {
		ad.mu.Unlock()
		return
	}
	ad.scanning = true
	ad.mu.Unlock()

	go ad.scanLoop(interval)
}

// StopScanning останавливает сканирование
func (ad *AppDetector) StopScanning() {
	ad.mu.Lock()
	if !ad.scanning {
		ad.mu.Unlock()
		return
	}
	ad.scanning = false
	close(ad.stopCh)
	ad.mu.Unlock()
}

// scanLoop основной цикл сканирования
func (ad *AppDetector) scanLoop(interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			ad.scanProcesses()
		case <-ad.stopCh:
			return
		}
	}
}

// scanProcesses сканирует все запущенные процессы
func (ad *AppDetector) scanProcesses() {
	ad.mu.Lock()
	defer ad.mu.Unlock()

	// Очищаем старые процессы
	ad.processes = make(map[int]*ProcessInfo)

	// Получаем список процессов в зависимости от ОС
	if runtime.GOOS == "windows" {
		ad.scanWindowsProcesses()
	} else {
		ad.scanUnixProcesses()
	}
}

// scanWindowsProcesses сканирует процессы в Windows
func (ad *AppDetector) scanWindowsProcesses() {
	// Используем wmic для получения списка процессов
	// Это упрощенная версия, в реальности нужно использовать Windows API
	ad.scanProcessesFromDir("/proc")
}

// scanUnixProcesses сканирует процессы в Unix-системах
func (ad *AppDetector) scanUnixProcesses() {
	ad.scanProcessesFromDir("/proc")
}

// scanProcessesFromDir сканирует процессы из директории /proc
func (ad *AppDetector) scanProcessesFromDir(_ string) {
	// Упрощенная реализация для демонстрации
	// В реальности нужно парсить /proc/[pid]/stat и /proc/[pid]/exe

	// Добавляем текущий процесс как пример
	ad.addProcess(os.Getpid(), os.Args[0], filepath.Base(os.Args[0]))
}

// addProcess добавляет процесс в список
func (ad *AppDetector) addProcess(pid int, path, name string) {
	executable := filepath.Base(path)

	ad.processes[pid] = &ProcessInfo{
		PID:        pid,
		Name:       name,
		Path:       path,
		Executable: executable,
		StartTime:  time.Now().Unix(),
	}
}

// GetProcesses возвращает список всех процессов
func (ad *AppDetector) GetProcesses() map[int]*ProcessInfo {
	ad.mu.RLock()
	defer ad.mu.RUnlock()

	result := make(map[int]*ProcessInfo)
	for pid, proc := range ad.processes {
		result[pid] = proc
	}
	return result
}

// GetProcessesByExecutable возвращает процессы по имени исполняемого файла
func (ad *AppDetector) GetProcessesByExecutable(executable string) []*ProcessInfo {
	ad.mu.RLock()
	defer ad.mu.RUnlock()

	var result []*ProcessInfo
	for _, proc := range ad.processes {
		if strings.EqualFold(proc.Executable, executable) {
			result = append(result, proc)
		}
	}
	return result
}

// GetProcessesByPattern возвращает процессы по паттерну имени
func (ad *AppDetector) GetProcessesByPattern(pattern string) []*ProcessInfo {
	ad.mu.RLock()
	defer ad.mu.RUnlock()

	var result []*ProcessInfo
	for _, proc := range ad.processes {
		if strings.Contains(strings.ToLower(proc.Executable), strings.ToLower(pattern)) {
			result = append(result, proc)
		}
	}
	return result
}

// IsProcessRunning проверяет, запущен ли процесс
func (ad *AppDetector) IsProcessRunning(executable string) bool {
	ad.mu.RLock()
	defer ad.mu.RUnlock()

	for _, proc := range ad.processes {
		if strings.EqualFold(proc.Executable, executable) {
			return true
		}
	}
	return false
}

// GetExecutableList возвращает список уникальных исполняемых файлов
func (ad *AppDetector) GetExecutableList() []string {
	ad.mu.RLock()
	defer ad.mu.RUnlock()

	seen := make(map[string]bool)
	var result []string

	for _, proc := range ad.processes {
		if !seen[proc.Executable] {
			seen[proc.Executable] = true
			result = append(result, proc.Executable)
		}
	}
	return result
}

// GetProcessInfo возвращает информацию о конкретном процессе
func (ad *AppDetector) GetProcessInfo(pid int) (*ProcessInfo, bool) {
	ad.mu.RLock()
	defer ad.mu.RUnlock()

	proc, exists := ad.processes[pid]
	return proc, exists
}

// MatchProcess проверяет, соответствует ли процесс правилу
func (ad *AppDetector) MatchProcess(ruleValue string, process *ProcessInfo) bool {
	// Точное совпадение
	if strings.EqualFold(process.Executable, ruleValue) {
		return true
	}

	// Совпадение по паттерну (содержит)
	if strings.Contains(strings.ToLower(process.Executable), strings.ToLower(ruleValue)) {
		return true
	}

	// Совпадение по пути
	if strings.Contains(strings.ToLower(process.Path), strings.ToLower(ruleValue)) {
		return true
	}

	return false
}

// GetProcessesForRule возвращает все процессы, соответствующие правилу
func (ad *AppDetector) GetProcessesForRule(ruleValue string) []*ProcessInfo {
	ad.mu.RLock()
	defer ad.mu.RUnlock()

	var result []*ProcessInfo
	for _, proc := range ad.processes {
		if ad.MatchProcess(ruleValue, proc) {
			result = append(result, proc)
		}
	}
	return result
}

// GetProcessStats возвращает статистику процессов
func (ad *AppDetector) GetProcessStats() map[string]interface{} {
	ad.mu.RLock()
	defer ad.mu.RUnlock()

	stats := map[string]interface{}{
		"total_processes":    len(ad.processes),
		"unique_executables": len(ad.GetExecutableList()),
		"scanning":           ad.scanning,
	}

	return stats
}

// Дополнительные методы для работы с приложениями
func (ad *AppDetector) GetPopularApplications() []string {
	// Список популярных приложений для быстрого выбора
	popularApps := []string{
		"chrome.exe",
		"firefox.exe",
		"edge.exe",
		"notepad.exe",
		"explorer.exe",
		"cmd.exe",
		"powershell.exe",
		"code.exe",
		"devenv.exe",
		"steam.exe",
		"discord.exe",
		"telegram.exe",
		"whatsapp.exe",
		"spotify.exe",
		"vlc.exe",
	}

	return popularApps
}

func (ad *AppDetector) GetSystemApplications() []string {
	// Системные приложения, которые обычно не нужно туннелировать
	systemApps := []string{
		"explorer.exe",
		"dwm.exe",
		"winlogon.exe",
		"csrss.exe",
		"smss.exe",
		"services.exe",
		"lsass.exe",
		"svchost.exe",
		"wininit.exe",
		"conhost.exe",
	}

	return systemApps
}

// Методы для работы с правилами
func (ad *AppDetector) ValidateAppRule(ruleValue string) error {
	if ruleValue == "" {
		return fmt.Errorf("empty rule value")
	}

	// Проверяем, что это валидное имя файла
	if strings.ContainsAny(ruleValue, `<>:"|?*`) {
		return fmt.Errorf("invalid characters in rule value")
	}

	return nil
}

func (ad *AppDetector) SuggestAppRules() []string {
	// Предложения правил на основе запущенных процессов
	ad.mu.RLock()
	defer ad.mu.RUnlock()

	var suggestions []string
	seen := make(map[string]bool)

	for _, proc := range ad.processes {
		if !seen[proc.Executable] && proc.Executable != "" {
			seen[proc.Executable] = true
			suggestions = append(suggestions, proc.Executable)
		}
	}

	return suggestions
}
