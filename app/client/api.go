package client

import (
	"context"
	"encoding/json"
	stdlog "log"
	"net/http"

	"github.com/nekoskin/whispera/core/protocol"
)

func startControlServer(ctx context.Context) {
	mux := http.NewServeMux()

	mux.HandleFunc("/connections", handleConnections)
	mux.HandleFunc("/dns", handleDNS)
	mux.HandleFunc("/camo", handleCamo)
	mux.HandleFunc("/wake", handleWake)
	mux.HandleFunc("/policy", handlePolicy)
	mux.HandleFunc("/patterns", handlePatterns)

	limitBody := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
			next.ServeHTTP(w, r)
		})
	}

	srv := &http.Server{Addr: controlAddr, Handler: limitBody(mux)}
	go func() {
		<-ctx.Done()
		srv.Close()
	}()
	go func() {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			stdlog.Printf("Control server error: %v", err)
		}
	}()
	stdlog.Printf("Control server listening on %s", controlAddr)
}

func handleWake(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	n := 0
	if reconnectEntry != nil {
		for _, e := range pool.List() {
			e.mu.Lock()
			enabled, mgr := e.Enabled, e.mgr
			e.mu.Unlock()
			if enabled && (mgr == nil || !mgr.IsConnected()) {
				go reconnectEntry(e)
				n++
			}
		}
	}
	json.NewEncoder(w).Encode(map[string]int{"reconnecting": n})
}

func handlePolicy(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(protocol.PolicyScoreSnapshot())
}

func handlePatterns(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(protocol.BlockPatterns())
}

func handleConnections(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	entries := pool.List()
	views := make([]entryView, 0, len(entries))
	for _, e := range entries {
		views = append(views, toView(e))
	}
	json.NewEncoder(w).Encode(views)
}

func handleDNS(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if globalDNS == nil {
		http.Error(w, "dns not available", http.StatusServiceUnavailable)
		return
	}
	if r.Method == http.MethodPost {
		var body struct {
			Upstream string `json:"upstream"`
		}
		json.NewDecoder(r.Body).Decode(&body)
		globalDNS.SetUpstream(body.Upstream)
		json.NewEncoder(w).Encode(map[string]string{"upstream": globalDNS.GetUpstream()})
		return
	}
	json.NewEncoder(w).Encode(map[string]string{"upstream": globalDNS.GetUpstream()})
}

func camoState() map[string]int {
	records, min, max := protocol.Shape.Get()
	fillIdle, fillInterval, fillMin, fillMax := protocol.Shape.Filler()
	chunkMin, chunkMax := protocol.Shape.Chunk()
	return map[string]int{
		"pad_records":        records,
		"pad_min":            min,
		"pad_max":            max,
		"filler_idle_ms":     fillIdle,
		"filler_interval_ms": fillInterval,
		"filler_min":         fillMin,
		"filler_max":         fillMax,
		"chunk_min":          chunkMin,
		"chunk_max":          chunkMax,
	}
}

func handleCamo(w http.ResponseWriter, r *http.Request) {
	records, min, max := protocol.Shape.Get()
	fillIdle, fillInterval, fillMin, fillMax := protocol.Shape.Filler()
	chunkMin, chunkMax := protocol.Shape.Chunk()
	if r.Method == http.MethodGet {
		json.NewEncoder(w).Encode(camoState())
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "GET or POST required", http.StatusMethodNotAllowed)
		return
	}
	body := struct {
		PadRecords       *int `json:"pad_records"`
		PadMin           *int `json:"pad_min"`
		PadMax           *int `json:"pad_max"`
		FillerIdleMs     *int `json:"filler_idle_ms"`
		FillerIntervalMs *int `json:"filler_interval_ms"`
		FillerMin        *int `json:"filler_min"`
		FillerMax        *int `json:"filler_max"`
		ChunkMin         *int `json:"chunk_min"`
		ChunkMax         *int `json:"chunk_max"`
	}{}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "bad json", http.StatusBadRequest)
		return
	}
	if body.PadRecords != nil {
		records = *body.PadRecords
	}
	if body.PadMin != nil {
		min = *body.PadMin
	}
	if body.PadMax != nil {
		max = *body.PadMax
	}
	if body.FillerIdleMs != nil {
		fillIdle = *body.FillerIdleMs
	}
	if body.FillerIntervalMs != nil {
		fillInterval = *body.FillerIntervalMs
	}
	if body.FillerMin != nil {
		fillMin = *body.FillerMin
	}
	if body.FillerMax != nil {
		fillMax = *body.FillerMax
	}
	if body.ChunkMin != nil {
		chunkMin = *body.ChunkMin
	}
	if body.ChunkMax != nil {
		chunkMax = *body.ChunkMax
	}
	if err := protocol.Shape.Set(records, min, max); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err := protocol.Shape.SetFiller(fillIdle, fillInterval, fillMin, fillMax); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err := protocol.Shape.SetChunk(chunkMin, chunkMax); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	json.NewEncoder(w).Encode(camoState())
}
