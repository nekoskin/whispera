package adblock

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

// HTTPSHandler обрабатывает HTTPS запросы с блокировкой рекламы
type HTTPSHandler struct {
	adBlocker *AdBlocker
	transport *http.Transport
}

// NewHTTPSHandler создает новый HTTPS handler
func NewHTTPSHandler(adBlocker *AdBlocker) *HTTPSHandler {
	return &HTTPSHandler{
		adBlocker: adBlocker,
		transport: &http.Transport{
			DialContext: (&net.Dialer{
				Timeout:   30 * time.Second,
				KeepAlive: 30 * time.Second,
			}).DialContext,
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: false,
			},
			MaxIdleConns:          100,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
		},
	}
}

// HandleRequest обрабатывает HTTP/HTTPS запрос
func (hh *HTTPSHandler) HandleRequest(w http.ResponseWriter, r *http.Request) {
	urlStr := r.URL.String()
	if !strings.HasPrefix(urlStr, "http") {
		urlStr = r.URL.Scheme + "://" + r.Host + urlStr
	}
	
	// Читаем тело запроса для анализа
	var bodyBytes []byte
	if r.Body != nil {
		bodyBytes, _ = io.ReadAll(r.Body)
		r.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
	}
	
	// Проверяем нужно ли блокировать
	if hh.adBlocker.ShouldBlockHTTPS(urlStr, r.Header, bodyBytes) {
		hh.adBlocker.BlockHTTPS(urlStr, "adblock")
		
		// Возвращаем блокирующий ответ
		w.WriteHeader(http.StatusForbidden)
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write([]byte(`<!DOCTYPE html>
<html>
<head>
<title>Blocked</title>
<style>
body { font-family: Arial, sans-serif; text-align: center; padding: 50px; }
h1 { color: #dc2626; }
</style>
</head>
<body>
<h1>🚫 Реклама заблокирована</h1>
<p>Этот запрос был заблокирован блокировщиком рекламы Whispera</p>
</body>
</html>`))
		return
	}
	
	// Создаем новый запрос к целевому серверу
	req, err := http.NewRequest(r.Method, urlStr, r.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	
	// Копируем заголовки
	for key, values := range r.Header {
		for _, value := range values {
			req.Header.Add(key, value)
		}
	}
	
	// Выполняем запрос
	client := &http.Client{
		Transport: hh.transport,
		Timeout:   30 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			// Проверяем редиректы на рекламу
			if hh.adBlocker.ShouldBlockHTTPS(req.URL.String(), req.Header, nil) {
				return fmt.Errorf("redirect blocked")
			}
			return nil
		},
	}
	
	resp, err := client.Do(req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	
	// Копируем заголовки ответа
	for key, values := range resp.Header {
		for _, value := range values {
			w.Header().Add(key, value)
		}
	}
	
	w.WriteHeader(resp.StatusCode)
	
	// Копируем тело ответа
	io.Copy(w, resp.Body)
}

// ServeHTTP реализует http.Handler
func (hh *HTTPSHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	hh.HandleRequest(w, r)
}

