package handlers

import (
	"encoding/json"
	"net/http"
	"strings"

	"whispera/internal/auth"
	"whispera/internal/logger"
)

var log = logger.Module("api.mfa")

type MFAHandler struct {
	mfaManager *auth.MFAManager
}

func NewMFAHandler(manager *auth.MFAManager) *MFAHandler {
	return &MFAHandler{
		mfaManager: manager,
	}
}

type SetupResponse struct {
	Secret    string `json:"secret"`
	QRCodeURL string `json:"qr_code_url"`
}

type VerifyRequest struct {
	Code string `json:"code"`
}
type VerifyResponse struct {
	Status        string   `json:"status"`
	RecoveryCodes []string `json:"recovery_codes,omitempty"`
}

func getUserID(r *http.Request) string {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		return ""
	}
	token := strings.TrimPrefix(authHeader, "Bearer ")
	if token == "" || token == authHeader {
		return ""
	}
	if len(token) > 16 {
		return "admin-" + token[:16]
	}
	return "admin-" + token
}

func (h *MFAHandler) Setup(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	userID := getUserID(r)
	if userID == "" {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	secret, qrURL, err := h.mfaManager.EnableMFA(userID)
	if err != nil {
		log.Error("Failed to enable MFA for user %s: %v", userID, err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(SetupResponse{
		Secret:    secret,
		QRCodeURL: qrURL,
	})
}

func (h *MFAHandler) Verify(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req VerifyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	userID := getUserID(r)
	if userID == "" {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	recoveryCodes, err := h.mfaManager.VerifyAndActivate(userID, req.Code)
	if err != nil {
		http.Error(w, "Invalid code or setup not initiated", http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(VerifyResponse{
		Status:        "activated",
		RecoveryCodes: recoveryCodes,
	})
}

func (h *MFAHandler) Validate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req VerifyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	userID := getUserID(r)
	if userID == "" {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	valid, err := h.mfaManager.ValidateLogin(userID, req.Code)
	if err != nil {
		log.Error("MFA validation error: %v", err)
		http.Error(w, "Validation failed", http.StatusInternalServerError)
		return
	}

	if !valid {
		http.Error(w, "Invalid code", http.StatusUnauthorized)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"status":"success"}`))
}

func (h *MFAHandler) Disable(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req VerifyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	userID := getUserID(r)
	if userID == "" {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	valid, _ := h.mfaManager.ValidateLogin(userID, req.Code)
	if !valid {
		http.Error(w, "Invalid code", http.StatusUnauthorized)
		return
	}

	h.mfaManager.DisableMFA(userID)

	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"status":"disabled"}`))
}
