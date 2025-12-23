package main

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"runtime/debug"
	"time"
)

// Global flag variables are defined in flags.go

// initFlags is defined in flags.go

// setupLogging configures logging to stderr for GUI compatibility
func setupLogging() {
	log.SetOutput(os.Stderr)
	log.SetFlags(log.LstdFlags | log.Lmicroseconds)
	os.Stderr.Sync()
}

// createDebugFile creates debug log file in current directory and AppData
func createDebugFile() (*os.File, error) {
	wd, _ := os.Getwd()

	// Try to create in current directory first
	debugFile, err := os.Create("whispera-debug.log")
	if debugFile == nil {
		// If failed, try AppData
		appData := os.Getenv("APPDATA")
		if appData != "" {
			debugPath := filepath.Join(appData, "com.whispera.client", "whispera-debug.log")
			os.MkdirAll(filepath.Dir(debugPath), 0755)
			debugFile, _ = os.Create(debugPath)
			if debugFile != nil {
				log.Printf("[INIT] Debug file created in AppData: %s", debugPath)
			}
		}
		if debugFile == nil {
			log.Printf("[WARN] Failed to create debug file (err: %v)", err)
		}
	} else {
		log.Printf("[INIT] Debug file created: %s/whispera-debug.log", wd)
	}

	if debugFile != nil {
		fmt.Fprintf(debugFile, "[DEBUG] Go client main() started at %s\n", time.Now().Format(time.RFC3339))
		fmt.Fprintf(debugFile, "[DEBUG] Working directory: %s\n", wd)
		fmt.Fprintf(debugFile, "[DEBUG] PID: %d\n", os.Getpid())
		fmt.Fprintf(debugFile, "[DEBUG] Args: %v\n", os.Args)
		debugFile.Sync()
	}

	return debugFile, nil
}

// logStartupInfo logs initial startup information
func logStartupInfo() {
	log.Printf("[INFO] ========================================")
	log.Printf("[INFO] Whispera Go Client Starting")
	log.Printf("[INFO] ========================================")
	log.Printf("[INFO] PID: %d", os.Getpid())
	if wd, err := os.Getwd(); err == nil {
		log.Printf("[INFO] Working directory: %s", wd)
	}
	log.Printf("[INFO] ========================================")
}

// init выполняется ДО main() - это самое раннее место для вывода
func init() {
	// Пробуем вывести в stderr сразу при загрузке - МНОЖЕСТВЕННЫЕ попытки
	for i := 0; i < 5; i++ {
		os.Stderr.Write([]byte(fmt.Sprintf("=== INIT %d ===\n", i)))
		os.Stderr.Sync()
		time.Sleep(10 * time.Millisecond) // Небольшая задержка
	}

	// Также пробуем создать файл сразу
	if f, err := os.Create("whispera-init.log"); err == nil {
		fmt.Fprintf(f, "[INIT] Go client init() called at %s\n", time.Now().Format(time.RFC3339))
		fmt.Fprintf(f, "[INIT] PID: %d\n", os.Getpid())
		fmt.Fprintf(f, "[INIT] Args: %v\n", os.Args)
		f.Sync()
		f.Close()
		// Выводим в stderr, что файл создан
		os.Stderr.Write([]byte("[INIT] Debug file created\n"))
		os.Stderr.Sync()
	} else {
		os.Stderr.Write([]byte(fmt.Sprintf("[INIT] Failed to create debug file: %v\n", err)))
		os.Stderr.Sync()
	}
}

// handlePanic sets up panic recovery for diagnostics
func handlePanic() {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("[FATAL] Panic recovered: %v", r)
			debug.PrintStack()
			os.Exit(1)
		}
	}()
}
