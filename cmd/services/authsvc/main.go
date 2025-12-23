package main

import (
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	srvpkg "whispera/internal/server"
	authsvc "whispera/internal/services/authsvc"
)

type jsonSessionOpenResponse struct {
	SessionID  string `json:"session_id"`
	AEADKey    string `json:"aead_key"`
	Seed       string `json:"seed"`
	InitialSeq uint32 `json:"initial_seq"`
	ExpiresAt  string `json:"expires_at"`
}

type jsonSessionRefreshResponse struct {
	Renewed    bool   `json:"renewed"`
	ExpiresAt  string `json:"expires_at"`
	NewAEADKey string `json:"new_aead_key,omitempty"`
	NewSeq     uint32 `json:"new_seq"`
}

type jsonSessionCloseResponse struct {
	Closed bool `json:"closed"`
}

func main() {
	var (
		listenAddr = flag.String("listen", ":9090", "HTTP listen address")
		sessionTTL = flag.Duration("session-ttl", time.Hour, "session lifetime duration")
		timeout    = flag.Duration("session-timeout", 2*time.Hour, "session manager inactivity timeout")
	)
	flag.Parse()

	logger := log.New(os.Stdout, "[authsvc] ", log.LstdFlags|log.Lmicroseconds)
	sessionMgr := srvpkg.NewSessionManager(*timeout)
	service := authsvc.NewService(sessionMgr, authsvc.AllowAllValidator{}, *sessionTTL)

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	})

	mux.HandleFunc("/v1/sessions:open", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			httpError(w, http.StatusMethodNotAllowed, "POST required")
			return
		}
		var req authsvc.SessionOpenRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			httpError(w, http.StatusBadRequest, fmt.Sprintf("invalid json: %v", err))
			return
		}
		resp, err := service.OpenSession(r.Context(), req)
		if err != nil {
			logger.Printf("open session error: %v", err)
			httpError(w, http.StatusBadRequest, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, jsonSessionOpenResponse{
			SessionID:  resp.SessionID,
			AEADKey:    base64.StdEncoding.EncodeToString(resp.AEADKey),
			Seed:       base64.StdEncoding.EncodeToString(resp.Seed),
			InitialSeq: resp.InitialSeq,
			ExpiresAt:  resp.ExpiresAt.UTC().Format(time.RFC3339Nano),
		})
	})

	mux.HandleFunc("/v1/sessions:refresh", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			httpError(w, http.StatusMethodNotAllowed, "POST required")
			return
		}
		var req authsvc.SessionRefreshRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			httpError(w, http.StatusBadRequest, fmt.Sprintf("invalid json: %v", err))
			return
		}
		resp, err := service.RefreshSession(r.Context(), req)
		if err != nil {
			logger.Printf("refresh session error: %v", err)
			httpError(w, http.StatusBadRequest, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, jsonSessionRefreshResponse{
			Renewed:    resp.Renewed,
			ExpiresAt:  resp.ExpiresAt.UTC().Format(time.RFC3339Nano),
			NewAEADKey: base64.StdEncoding.EncodeToString(resp.NewAEADKey),
			NewSeq:     resp.NewSeq,
		})
	})

	mux.HandleFunc("/v1/sessions:close", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			httpError(w, http.StatusMethodNotAllowed, "POST required")
			return
		}
		var req authsvc.SessionCloseRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			httpError(w, http.StatusBadRequest, fmt.Sprintf("invalid json: %v", err))
			return
		}
		resp, err := service.CloseSession(r.Context(), req)
		if err != nil {
			logger.Printf("close session error: %v", err)
			httpError(w, http.StatusBadRequest, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, jsonSessionCloseResponse{
			Closed: resp.Closed,
		})
	})

	mux.HandleFunc("/v1/sessions/events", func(w http.ResponseWriter, r *http.Request) {
		sessionID := r.URL.Query().Get("session_id")
		if sessionID == "" {
			httpError(w, http.StatusBadRequest, "session_id required")
			return
		}
		flusher, ok := w.(http.Flusher)
		if !ok {
			httpError(w, http.StatusInternalServerError, "streaming unsupported")
			return
		}

		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("Connection", "keep-alive")

		events, cancel := service.SubscribeSessionEvents(sessionID)
		defer cancel()

		for {
			select {
			case <-r.Context().Done():
				return
			case evt, ok := <-events:
				if !ok {
					return
				}
				payload := map[string]interface{}{
					"type":       evt.Type,
					"session_id": evt.SessionID,
					"seq":        evt.Seq,
					"timestamp":  evt.Timestamp.UTC().Format(time.RFC3339Nano),
				}
				if len(evt.AEADKey) > 0 {
					payload["aead_key"] = base64.StdEncoding.EncodeToString(evt.AEADKey)
				}
				if evt.Reason != "" {
					payload["reason"] = evt.Reason
				}
				data, err := json.Marshal(payload)
				if err != nil {
					logger.Printf("event encode error: %v", err)
					continue
				}
				if _, err := fmt.Fprintf(w, "data: %s\n\n", data); err != nil {
					logger.Printf("event stream write error: %v", err)
					return
				}
				flusher.Flush()
			}
		}
	})

	logger.Printf("listening on %s", *listenAddr)
	server := &http.Server{
		Addr:              *listenAddr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}
	if err := server.ListenAndServe(); err != nil {
		logger.Fatalf("server exited: %v", err)
	}
}

func writeJSON(w http.ResponseWriter, status int, payload interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(payload); err != nil {
		log.Printf("write json error: %v", err)
	}
}

func httpError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]string{
		"error": message,
	})
}
