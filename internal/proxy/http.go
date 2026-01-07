package proxy

import (
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"whispera/internal/logger"
)

// HTTPServer представляет HTTP прокси сервер
type HTTPServer struct {
	listenAddr  string
	handler     func(*http.Request, http.ResponseWriter) error
	authHandler func(username, password string) bool // Обработчик аутентификации
	log         *logger.Logger
}

// NewHTTPServer создает новый HTTP прокси сервер
func NewHTTPServer(addr string, handler func(*http.Request, http.ResponseWriter) error) *HTTPServer {
	return &HTTPServer{
		listenAddr: addr,
		handler:    handler,
		log:        logger.Module("http-proxy"),
	}
}

// SetAuthHandler устанавливает обработчик аутентификации
func (s *HTTPServer) SetAuthHandler(handler func(username, password string) bool) {
	s.authHandler = handler
}

// ListenAndServe запускает HTTP прокси сервер
func (s *HTTPServer) ListenAndServe() error {
	httpServer := &http.Server{
		Addr:         s.listenAddr,
		Handler:      http.HandlerFunc(s.handleRequest),
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	s.log.Info("✅ Server listening on %s - ready to accept connections", s.listenAddr)
	return httpServer.ListenAndServe()
}

// handleRequest обрабатывает HTTP запрос
func (s *HTTPServer) handleRequest(w http.ResponseWriter, r *http.Request) {
	// Проверяем аутентификацию если требуется
	if s.authHandler != nil {
		if !s.checkAuth(r) {
			w.Header().Set("Proxy-Authenticate", "Basic realm=\"Proxy\"")
			w.WriteHeader(http.StatusProxyAuthRequired)
			return
		}
	}

	// Обрабатываем CONNECT метод (для HTTPS)
	if r.Method == http.MethodConnect {
		s.handleCONNECT(w, r)
		return
	}

	// Обрабатываем обычные HTTP запросы
	if err := s.handler(r, w); err != nil {
		s.log.Error("Handler error: %v", err)
		http.Error(w, err.Error(), http.StatusBadGateway)
	}
}

// checkAuth проверяет аутентификацию
func (s *HTTPServer) checkAuth(r *http.Request) bool {
	if s.authHandler == nil {
		return true
	}

	auth := r.Header.Get("Proxy-Authorization")
	if auth == "" {
		return false
	}

	// Парсим Basic auth
	if !strings.HasPrefix(auth, "Basic ") {
		return false
	}

	// Декодируем base64
	encoded := auth[6:] // Убираем "Basic "
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return false
	}

	// Парсим username:password
	parts := strings.SplitN(string(decoded), ":", 2)
	if len(parts) != 2 {
		return false
	}

	return s.authHandler(parts[0], parts[1])
}

// handleCONNECT обрабатывает CONNECT метод (для HTTPS туннелирования)
func (s *HTTPServer) handleCONNECT(w http.ResponseWriter, r *http.Request) {
	// Извлекаем целевой адрес из запроса
	targetAddr := r.Host
	if targetAddr == "" {
		targetAddr = r.URL.Host
	}

	// Подключаемся к целевому серверу
	targetConn, err := net.DialTimeout("tcp", targetAddr, 10*time.Second)
	if err != nil {
		s.log.Error("Failed to connect to %s: %v", targetAddr, err)
		http.Error(w, "Failed to connect to target", http.StatusBadGateway)
		return
	}
	defer targetConn.Close()

	// Отправляем успешный ответ клиенту
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "Hijacking not supported", http.StatusInternalServerError)
		return
	}

	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		http.Error(w, "Failed to hijack connection", http.StatusInternalServerError)
		return
	}
	defer clientConn.Close()

	// Отправляем 200 Connection Established
	response := "HTTP/1.1 200 Connection Established\r\n\r\n"
	if _, err := clientConn.Write([]byte(response)); err != nil {
		s.log.Error("Failed to send response: %v", err)
		return
	}

	// Проксируем данные в обе стороны
	go func() {
		io.Copy(targetConn, clientConn)
		targetConn.Close()
	}()
	io.Copy(clientConn, targetConn)
}

// HandleHTTPRequest обрабатывает обычный HTTP запрос (не CONNECT)
func HandleHTTPRequest(r *http.Request, w http.ResponseWriter, targetURL string) error {
	// Парсим целевой URL
	parsedURL, err := url.Parse(targetURL)
	if err != nil {
		return fmt.Errorf("invalid target URL: %w", err)
	}

	// Создаем новый запрос к целевому серверу
	targetReq := r.Clone(r.Context())
	targetReq.URL = parsedURL
	targetReq.Host = parsedURL.Host
	targetReq.RequestURI = ""

	// Удаляем заголовки прокси
	targetReq.Header.Del("Proxy-Connection")
	targetReq.Header.Del("Proxy-Authorization")
	targetReq.Header.Del("Connection")

	// Создаем HTTP клиент
	client := &http.Client{
		Timeout: 30 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			// Следуем редиректам
			return nil
		},
	}

	// Выполняем запрос
	resp, err := client.Do(targetReq)
	if err != nil {
		return fmt.Errorf("failed to execute request: %w", err)
	}
	defer resp.Body.Close()

	// Копируем заголовки ответа
	for key, values := range resp.Header {
		for _, value := range values {
			w.Header().Add(key, value)
		}
	}

	// Устанавливаем статус код
	w.WriteHeader(resp.StatusCode)

	// Копируем тело ответа
	_, err = io.Copy(w, resp.Body)
	return err
}

// SimpleHTTPProxyHandler создает простой обработчик HTTP прокси
func SimpleHTTPProxyHandler() func(*http.Request, http.ResponseWriter) error {
	return func(r *http.Request, w http.ResponseWriter) error {
		// Для обычных HTTP запросов используем URL из запроса
		targetURL := r.URL.String()
		if !strings.HasPrefix(targetURL, "http://") && !strings.HasPrefix(targetURL, "https://") {
			// Если URL относительный, добавляем схему
			targetURL = "http://" + r.Host + targetURL
		}

		return HandleHTTPRequest(r, w, targetURL)
	}
}

// ForwardHTTPProxyHandler создает обработчик для форвардинга через другой прокси
func ForwardHTTPProxyHandler(proxyURL string) func(*http.Request, http.ResponseWriter) error {
	return func(r *http.Request, w http.ResponseWriter) error {
		// Используем указанный прокси URL
		return HandleHTTPRequest(r, w, proxyURL)
	}
}
