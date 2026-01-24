package apiserver

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	"whispera/internal/modules/config"
)

// handleGetInbounds returns the list of configured inbounds
func (s *Server) handleGetInbounds(w http.ResponseWriter, r *http.Request) {
	if s.registry == nil {
		s.jsonError(w, http.StatusInternalServerError, "Registry not available")
		return
	}

	module, ok := s.registry.Get("config.provider")
	if !ok {
		s.jsonError(w, http.StatusInternalServerError, "Config provider not found")
		return
	}
	cfgProvider := module.(*config.Provider)
	cfg := cfgProvider.GetConfig()

	// Wrap in a response structure compatible with frontend expectations
	s.jsonOK(w, map[string]interface{}{
		"success":  true,
		"inbounds": cfg.Inbounds,
		"count":    len(cfg.Inbounds),
	})
}

// handleAddInbound adds a new inbound configuration
func (s *Server) handleAddInbound(w http.ResponseWriter, r *http.Request) {
	var req config.InboundConfig
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		log.Printf("[API] Failed to decode inbound request: %v", err)
		s.jsonError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	log.Printf("[API] Received inbound add request: tag=%s, port=%d, security=%s",
		req.Tag, req.Port, req.StreamSettings.Security)

	// Enforce Whispera defaults if not set
	if req.Protocol == "" {
		req.Protocol = "whispera"
	}
	if req.Tag == "" {
		req.Tag = fmt.Sprintf("inbound-%d", time.Now().Unix())
	}
	if req.Listen == "" {
		req.Listen = "0.0.0.0"
	}
	// Force Phantom/TCP for now as it's the main mode
	if req.StreamSettings.Network == "" {
		req.StreamSettings.Network = "tcp"
	}
	if req.StreamSettings.Security == "" {
		req.StreamSettings.Security = "phantom"
	}

	log.Printf("[API] Normalized inbound config: tag=%s, port=%d, network=%s, security=%s, has_phantom_key=%v",
		req.Tag, req.Port, req.StreamSettings.Network, req.StreamSettings.Security,
		req.StreamSettings.Phantom.PrivateKey != "")

	module, ok := s.registry.Get("config.provider")
	if !ok {
		log.Printf("[API] Config provider not found in registry")
		s.jsonError(w, http.StatusInternalServerError, "Config provider not found")
		return
	}
	cfgProvider := module.(*config.Provider)

	err := cfgProvider.Update(func(cfg *config.ServerConfig) {
		// Dedup check by port
		for _, in := range cfg.Inbounds {
			if in.Port == req.Port {
				log.Printf("[API] Port %d already in use by inbound %s", req.Port, in.Tag)
				// Error or overwrite? Let's error for safety
				return // TODO: Return error properly
			}
		}
		cfg.Inbounds = append(cfg.Inbounds, req)
		log.Printf("[API] ✓ Added inbound %s (port %d) to config. Total inbounds: %d",
			req.Tag, req.Port, len(cfg.Inbounds))
	})

	if err != nil {
		log.Printf("[API] Failed to update config: %v", err)
		s.jsonError(w, http.StatusInternalServerError, "Failed to update config: "+err.Error())
		return
	}

	log.Printf("[API] ✓ Inbound %s saved to config.yaml successfully", req.Tag)

	s.jsonOK(w, map[string]interface{}{
		"success": true,
		"message": "Inbound added",
		"inbound": req,
	})
}

// handleUpdateInbound updates an existing inbound
func (s *Server) handleUpdateInbound(w http.ResponseWriter, r *http.Request) {
	var req config.InboundConfig
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.jsonError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	if req.Tag == "" {
		s.jsonError(w, http.StatusBadRequest, "Tag required for update")
		return
	}

	module, ok := s.registry.Get("config.provider")
	if !ok {
		s.jsonError(w, http.StatusInternalServerError, "Config provider not found")
		return
	}
	cfgProvider := module.(*config.Provider)

	err := cfgProvider.Update(func(cfg *config.ServerConfig) {
		for i, in := range cfg.Inbounds {
			if in.Tag == req.Tag {
				// Update fields. Protocol/Tag usually static, but Port/Settings mutable
				cfg.Inbounds[i] = req
				break
			}
		}
	})

	if err != nil {
		s.jsonError(w, http.StatusInternalServerError, "Failed to update config: "+err.Error())
		return
	}

	s.jsonOK(w, map[string]string{"message": "Inbound updated"})
}

// handleDeleteInbound deletes an inbound
func (s *Server) handleDeleteInbound(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Tag string `json:"tag"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.jsonError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	module, ok := s.registry.Get("config.provider")
	if !ok {
		s.jsonError(w, http.StatusInternalServerError, "Config provider not found")
		return
	}
	cfgProvider := module.(*config.Provider)

	err := cfgProvider.Update(func(cfg *config.ServerConfig) {
		newInbounds := make([]config.InboundConfig, 0)
		for _, in := range cfg.Inbounds {
			if in.Tag != req.Tag {
				newInbounds = append(newInbounds, in)
			}
		}
		cfg.Inbounds = newInbounds
	})

	if err != nil {
		s.jsonError(w, http.StatusInternalServerError, "Failed to update config: "+err.Error())
		return
	}

	s.jsonOK(w, map[string]string{"message": "Inbound deleted"})
}
