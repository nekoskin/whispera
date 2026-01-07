package handlers

import (
	"encoding/json"
	"net/http"

	"whispera/internal/auth"
	"whispera/internal/logger"
)

var log = logger.Module("api.mfa")

// MFAHandler handles MFA related requests
type MFAHandler struct {
	mfaManager *auth.MFAManager
}

// NewMFAHandler creates a new MFA handler
func NewMFAHandler(manager *auth.MFAManager) *MFAHandler {
	return &MFAHandler{
		mfaManager: manager,
	}
}

// SetupResponse is the response for setup endpoint
type SetupResponse struct {
	Secret    string `json:"secret"`
	QRCodeURL string `json:"qr_code_url"`
}

// VerifyRequest is the request for verification
type VerifyRequest struct {
	Code string `json:"code"`
}

// VerifyResponse contains recovery codes
type VerifyResponse struct {
	Status        string   `json:"status"`
	RecoveryCodes []string `json:"recovery_codes,omitempty"`
}

// SetupHandler handles MFA setup initiation
func (h *MFAHandler) Setup(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// TODO: Get user ID from context/session
	// userID := r.Context().Value("user_id").(string)
	userID := "test-user" // Placeholder until auth middleware is fully integrated

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

// VerifyHandler handles MFA code verification and activation
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

	// TODO: Get user ID from context
	userID := "test-user"

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

// ValidateHandler handles checking code during login (step 2)
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

	userID := "test-user" // Should come from temp session/token

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

// DisableHandler disables MFA
func (h *MFAHandler) Disable(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Require code verification even to disable
	var req VerifyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	userID := "test-user"

	// Verify code first
	valid, _ := h.mfaManager.ValidateLogin(userID, req.Code)
	if !valid {
		http.Error(w, "Invalid code", http.StatusUnauthorized)
		return
	}

	h.mfaManager.DisableMFA(userID)

	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"status":"disabled"}`))
}
