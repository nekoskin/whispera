//go:build windows
// +build windows

package tun

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
)

const (
	wintunDLLURL = "https://github.com/WireGuard/wintun/releases/download/v0.14.1/wintun-x64.dll"
	wintunDLLName = "wintun.dll"
)

// ensureWintunDLL проверяет наличие wintun.dll и скачивает его при необходимости
func ensureWintunDLL() error {
	// Получаем директорию исполняемого файла
	exePath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("failed to get executable path: %w", err)
	}
	exeDir := filepath.Dir(exePath)
	
	// Получаем рабочую директорию для поиска в dev режиме
	workDir, _ := os.Getwd()
	
	// Список мест для поиска wintun.dll
	searchPaths := []string{
		// 1. Рядом с Go клиентом (в app_data_dir) - приоритет
		filepath.Join(exeDir, wintunDLLName),
		// 2. В родительской директории
		filepath.Join(filepath.Dir(exeDir), wintunDLLName),
		// 3. В папке wintun/bin/amd64/ рядом с exe
		filepath.Join(exeDir, "wintun", "bin", "amd64", wintunDLLName),
		filepath.Join(filepath.Dir(exeDir), "wintun", "bin", "amd64", wintunDLLName),
		// 4. В рабочей директории и её подпапках (для dev режима)
		filepath.Join(workDir, wintunDLLName),
		filepath.Join(workDir, "resources", "wintun", "bin", "amd64", wintunDLLName),
		filepath.Join(workDir, "src-tauri", "resources", "wintun", "bin", "amd64", wintunDLLName),
		filepath.Join(workDir, "src-tauri", "resources", wintunDLLName),
		filepath.Join(workDir, "client-package-tauri", "src-tauri", "resources", "wintun", "bin", "amd64", wintunDLLName),
		filepath.Join(workDir, "client-package-tauri", "src-tauri", "resources", wintunDLLName),
	}

	// Проверяем все пути
	for _, searchPath := range searchPaths {
		// Преобразуем в абсолютный путь
		absPath, err := filepath.Abs(searchPath)
		if err != nil {
			continue
		}
		
		if _, err := os.Stat(absPath); err == nil {
			// Если нашли в папке wintun, копируем рядом с exe
			if filepath.Base(filepath.Dir(filepath.Dir(filepath.Dir(absPath)))) == "wintun" {
				targetPath := filepath.Join(exeDir, wintunDLLName)
				if err := copyFile(absPath, targetPath); err == nil {
					log.Printf("[TUN] wintun.dll copied from %s to %s", absPath, targetPath)
					return nil
				}
			}
			// Если нашли не рядом с exe, копируем туда
			if absPath != filepath.Join(exeDir, wintunDLLName) {
				targetPath := filepath.Join(exeDir, wintunDLLName)
				if err := copyFile(absPath, targetPath); err == nil {
					log.Printf("[TUN] wintun.dll copied from %s to %s", absPath, targetPath)
					return nil
				}
			}
			log.Printf("[TUN] wintun.dll found at: %s", absPath)
			return nil
		}
	}

	// Пробуем найти в системных директориях
	systemPaths := []string{
		filepath.Join(os.Getenv("SYSTEMROOT"), "System32"),
		filepath.Join(os.Getenv("SYSTEMROOT"), "SysWOW64"),
	}
	for _, sysPath := range systemPaths {
		sysDllPath := filepath.Join(sysPath, wintunDLLName)
		if _, err := os.Stat(sysDllPath); err == nil {
			log.Printf("[TUN] wintun.dll found in system directory: %s", sysDllPath)
			return nil
		}
	}

	// Если не найден, пытаемся скачать
	log.Printf("[TUN] wintun.dll not found, attempting to download...")
	
	// Определяем архитектуру
	arch := "x64"
	if runtime.GOARCH == "386" {
		arch = "x86"
	} else if runtime.GOARCH == "arm64" {
		arch = "arm64"
	}
	
	// Формируем URL для нужной архитектуры
	url := fmt.Sprintf("https://github.com/WireGuard/wintun/releases/download/v0.14.1/wintun-%s.dll", arch)
	
	// Скачиваем DLL
	resp, err := http.Get(url)
	if err != nil {
		return fmt.Errorf("failed to download wintun.dll: %w (you can download it manually from https://www.wintun.net/)", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to download wintun.dll: HTTP %d", resp.StatusCode)
	}

	// Создаем файл рядом с exe
	dllPath := filepath.Join(exeDir, wintunDLLName)
	out, err := os.Create(dllPath)
	if err != nil {
		// Если не можем создать в директории exe, пробуем текущую директорию
		dllPath = wintunDLLName
		out, err = os.Create(dllPath)
		if err != nil {
			return fmt.Errorf("failed to create wintun.dll file: %w", err)
		}
	}
	defer out.Close()

	// Копируем данные
	_, err = io.Copy(out, resp.Body)
	if err != nil {
		os.Remove(dllPath) // Удаляем частично скачанный файл
		return fmt.Errorf("failed to write wintun.dll: %w", err)
	}

	log.Printf("[TUN] ✅ wintun.dll downloaded successfully to: %s", dllPath)
	return nil
}

// copyFile копирует файл из источника в назначение
func copyFile(src, dst string) error {
	sourceFile, err := os.Open(src)
	if err != nil {
		return err
	}
	defer sourceFile.Close()

	destFile, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer destFile.Close()

	_, err = io.Copy(destFile, sourceFile)
	if err != nil {
		return err
	}

	return destFile.Sync()
}

