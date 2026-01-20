package core

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/google/uuid"
)

type Server struct {
	authService *AuthService
	config      *Config
}

func NewServer(authService *AuthService, config *Config) *Server {
	return &Server{
		authService: authService,
		config:      config,
	}
}

func (s *Server) HandleLogin(w http.ResponseWriter, r *http.Request) {
	if !validateMethod(w, r, http.MethodPost) {
		return
	}

	var req struct {
		Provider string `json:"provider"`
		Code     string `json:"code"`
	}

	if !decodeJSON(w, r, &req) {
		return
	}

	ctx := r.Context()
	provider := Provider(req.Provider)
	loginResp, err := s.authService.Login(ctx, provider, req.Code)
	if err != nil {
		if err == ErrUnsupportedProvider {
			respondError(w, http.StatusBadRequest, "invalid_provider", "Unsupported provider")
			return
		}
		respondError(w, http.StatusUnauthorized, "login_failed", "Authentication failed")
		return
	}

	respondJSON(w, http.StatusOK, loginResp)
}

func (s *Server) HandleRefresh(w http.ResponseWriter, r *http.Request) {
	if !validateMethod(w, r, http.MethodPost) {
		return
	}

	var req struct {
		RefreshToken string `json:"refresh_token"`
	}

	if !decodeJSON(w, r, &req) {
		return
	}

	if req.RefreshToken == "" {
		respondError(w, http.StatusBadRequest, "invalid_request", "refresh_token is required")
		return
	}

	ctx := r.Context()
	accessToken, err := s.authService.Refresh(ctx, req.RefreshToken)
	if err != nil {
		if err == ErrInvalidToken || err == ErrExpiredToken {
			respondError(w, http.StatusUnauthorized, "invalid_token", "Invalid or expired refresh token")
			return
		}
		respondError(w, http.StatusInternalServerError, "internal_error", "Failed to refresh token")
		return
	}

	respondJSON(w, http.StatusOK, map[string]string{
		"access_token": accessToken,
	})
}

func (s *Server) HandleLogout(w http.ResponseWriter, r *http.Request) {
	if !validateMethod(w, r, http.MethodPost) {
		return
	}

	var req struct {
		RefreshToken string `json:"refresh_token"`
	}

	if !decodeJSON(w, r, &req) {
		return
	}

	if req.RefreshToken == "" {
		respondError(w, http.StatusBadRequest, "invalid_request", "refresh_token is required")
		return
	}

	ctx := r.Context()
	if err := s.authService.Logout(ctx, req.RefreshToken); err != nil {
		respondError(w, http.StatusInternalServerError, "internal_error", "Failed to logout")
		return
	}

	respondJSON(w, http.StatusOK, map[string]string{
		"status": "logged_out",
	})
}

func (s *Server) HandleLogoutAll(w http.ResponseWriter, r *http.Request) {
	if !validateMethod(w, r, http.MethodPost) {
		return
	}

	userID, err := s.extractUserIDFromJWT(r)
	if err != nil {
		respondError(w, http.StatusUnauthorized, "invalid_token", "Invalid or missing authorization token")
		return
	}

	ctx := r.Context()
	if err := s.authService.LogoutAll(ctx, userID); err != nil {
		respondError(w, http.StatusInternalServerError, "internal_error", "Failed to logout from all devices")
		return
	}

	respondJSON(w, http.StatusOK, map[string]string{
		"status": "logged_out_all_devices",
	})
}

func (s *Server) HandleUserInfo(w http.ResponseWriter, r *http.Request) {
	if !validateMethod(w, r, http.MethodGet) {
		return
	}

	userID, err := s.extractUserIDFromJWT(r)
	if err != nil {
		respondError(w, http.StatusUnauthorized, "invalid_token", "Invalid or missing authorization token")
		return
	}

	ctx := r.Context()
	userInfo, err := s.authService.GetUserInfo(ctx, userID)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "internal_error", "Failed to get user info")
		return
	}

	respondJSON(w, http.StatusOK, userInfo)
}

func (s *Server) HandleHealth(w http.ResponseWriter, r *http.Request) {
	respondJSON(w, http.StatusOK, map[string]string{
		"status": "ok",
	})
}

// Helper functions

func (s *Server) extractUserIDFromJWT(r *http.Request) (uuid.UUID, error) {
	token, err := extractBearerToken(r)
	if err != nil {
		return uuid.Nil, err
	}

	userID, err := ValidateAccessToken(token, s.config)
	if err != nil {
		return uuid.Nil, fmt.Errorf("invalid token: %w", err)
	}

	return userID, nil
}

func validateMethod(w http.ResponseWriter, r *http.Request, method string) bool {
	if r.Method != method {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return false
	}
	return true
}

func decodeJSON(w http.ResponseWriter, r *http.Request, dest interface{}) bool {
	if err := json.NewDecoder(r.Body).Decode(dest); err != nil {
		respondError(w, http.StatusBadRequest, "invalid_request", "Invalid request body")
		return false
	}
	return true
}

func extractBearerToken(r *http.Request) (string, error) {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		return "", fmt.Errorf("missing authorization header")
	}

	parts := strings.Split(authHeader, " ")
	if len(parts) != 2 || parts[0] != "Bearer" {
		return "", fmt.Errorf("invalid authorization header format")
	}

	return parts[1], nil
}

func respondJSON(w http.ResponseWriter, statusCode int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	json.NewEncoder(w).Encode(data)
}

func respondError(w http.ResponseWriter, statusCode int, errorCode, message string) {
	respondJSON(w, statusCode, map[string]string{
		"error":   errorCode,
		"message": message,
	})
}
