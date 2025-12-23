package sniffing

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"strings"
)

// ExtractHTTPHost извлекает Host header из HTTP запроса
// Возвращает домен и ошибку (если есть)
func ExtractHTTPHost(conn net.Conn) (string, error) {
	// Используем bufio.Reader для чтения строк
	reader := bufio.NewReader(conn)

	// Читаем первую строку (Request-Line)
	requestLine, _, err := reader.ReadLine()
	if err != nil {
		return "", fmt.Errorf("failed to read request line: %w", err)
	}

	// Проверяем, что это HTTP запрос
	if !strings.HasPrefix(string(requestLine), "GET ") &&
		!strings.HasPrefix(string(requestLine), "POST ") &&
		!strings.HasPrefix(string(requestLine), "PUT ") &&
		!strings.HasPrefix(string(requestLine), "DELETE ") &&
		!strings.HasPrefix(string(requestLine), "HEAD ") &&
		!strings.HasPrefix(string(requestLine), "OPTIONS ") &&
		!strings.HasPrefix(string(requestLine), "PATCH ") {
		return "", fmt.Errorf("not an HTTP request")
	}

	// Читаем заголовки
	for {
		line, _, err := reader.ReadLine()
		if err != nil {
			return "", fmt.Errorf("failed to read header: %w", err)
		}

		// Пустая строка означает конец заголовков
		if len(line) == 0 {
			break
		}

		// Ищем Host header
		header := string(line)
		if strings.HasPrefix(strings.ToLower(header), "host:") {
			// Извлекаем значение Host
			parts := strings.SplitN(header, ":", 2)
			if len(parts) == 2 {
				host := strings.TrimSpace(parts[1])
				// Убираем порт если есть
				if idx := strings.Index(host, ":"); idx != -1 {
					host = host[:idx]
				}
				return host, nil
			}
		}
	}

	return "", fmt.Errorf("Host header not found")
}

// PeekHTTPHost пытается извлечь Host header без чтения данных из соединения
// Использует Peek для чтения без удаления из буфера
func PeekHTTPHost(peekData []byte) (string, error) {
	// Создаем reader из peekData
	reader := bufio.NewReader(strings.NewReader(string(peekData)))

	// Читаем первую строку (Request-Line)
	requestLine, _, err := reader.ReadLine()
	if err != nil {
		return "", fmt.Errorf("failed to read request line: %w", err)
	}

	// Проверяем, что это HTTP запрос
	if !strings.HasPrefix(string(requestLine), "GET ") &&
		!strings.HasPrefix(string(requestLine), "POST ") &&
		!strings.HasPrefix(string(requestLine), "PUT ") &&
		!strings.HasPrefix(string(requestLine), "DELETE ") &&
		!strings.HasPrefix(string(requestLine), "HEAD ") &&
		!strings.HasPrefix(string(requestLine), "OPTIONS ") &&
		!strings.HasPrefix(string(requestLine), "PATCH ") {
		return "", fmt.Errorf("not an HTTP request")
	}

	// Читаем заголовки
	for {
		line, _, err := reader.ReadLine()
		if err != nil {
			if err == io.EOF {
				break
			}
			return "", fmt.Errorf("failed to read header: %w", err)
		}

		// Пустая строка означает конец заголовков
		if len(line) == 0 {
			break
		}

		// Ищем Host header
		header := string(line)
		if strings.HasPrefix(strings.ToLower(header), "host:") {
			// Извлекаем значение Host
			parts := strings.SplitN(header, ":", 2)
			if len(parts) == 2 {
				host := strings.TrimSpace(parts[1])
				// Убираем порт если есть
				if idx := strings.Index(host, ":"); idx != -1 {
					host = host[:idx]
				}
				return host, nil
			}
		}
	}

	return "", fmt.Errorf("Host header not found")
}

// IsHTTPRequest проверяет, является ли данные началом HTTP запроса
func IsHTTPRequest(data []byte) bool {
	if len(data) < 4 {
		return false
	}
	dataStr := string(data)
	return strings.HasPrefix(dataStr, "GET ") ||
		strings.HasPrefix(dataStr, "POST ") ||
		strings.HasPrefix(dataStr, "PUT ") ||
		strings.HasPrefix(dataStr, "DELETE ") ||
		strings.HasPrefix(dataStr, "HEAD ") ||
		strings.HasPrefix(dataStr, "OPTIONS ") ||
		strings.HasPrefix(dataStr, "PATCH ")
}

// ExtractHostFromRequest извлекает Host из HTTP Request (для использования в HTTP handlers)
func ExtractHostFromRequest(requestLine string, headers map[string]string) string {
	// Сначала проверяем заголовки
	if host, ok := headers["Host"]; ok {
		// Убираем порт если есть
		if idx := strings.Index(host, ":"); idx != -1 {
			return host[:idx]
		}
		return host
	}
	if host, ok := headers["host"]; ok {
		if idx := strings.Index(host, ":"); idx != -1 {
			return host[:idx]
		}
		return host
	}
	return ""
}

