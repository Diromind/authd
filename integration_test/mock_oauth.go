package integration_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
)

type mockUser struct {
	ID      string `json:"id"`
	Email   string `json:"email"`
	Name    string `json:"name"`
	Picture string `json:"picture"`
}

var mockUsers = map[string]mockUser{
	"valid_code_1": {
		ID:      "mock_user_1",
		Email:   "user1@example.com",
		Name:    "Test User 1",
		Picture: "https://example.com/avatar1.jpg",
	},
	"valid_code_2": {
		ID:      "mock_user_1",
		Email:   "user1@example.com",
		Name:    "Test User 1",
		Picture: "https://example.com/avatar1.jpg",
	},
	"valid_code_3": {
		ID:      "mock_user_1",
		Email:   "user1@example.com",
		Name:    "Test User 1",
		Picture: "https://example.com/avatar1.jpg",
	},
	"another_user_code_1": {
		ID:      "mock_user_2",
		Email:   "user2@example.com",
		Name:    "Test User 2",
		Picture: "https://example.com/avatar2.jpg",
	},
	"another_user_code_2": {
		ID:      "mock_user_2",
		Email:   "user2@example.com",
		Name:    "Test User 2",
		Picture: "https://example.com/avatar2.jpg",
	},
}

type MockOAuthServer struct {
	server        *httptest.Server
	refreshTokens map[string]mockUser
	mu            sync.Mutex
}

func NewMockOAuthServer() *MockOAuthServer {
	m := &MockOAuthServer{
		refreshTokens: make(map[string]mockUser),
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/token", m.handleToken)
	mux.HandleFunc("/userinfo", m.handleUserInfo)
	mux.HandleFunc("/oauth2/v2/userinfo", m.handleUserInfo)

	m.server = httptest.NewServer(mux)
	return m
}

func (m *MockOAuthServer) URL() string {
	return m.server.URL
}

func (m *MockOAuthServer) Close() {
	m.server.Close()
}

func (m *MockOAuthServer) handleToken(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	body := make([]byte, r.ContentLength)
	r.Body.Read(body)
	params, _ := url.ParseQuery(string(body))

	grantType := params.Get("grant_type")

	if grantType == "authorization_code" {
		code := params.Get("code")
		if user, ok := mockUsers[code]; ok {
			refreshToken := "refresh_" + code
			m.mu.Lock()
			m.refreshTokens[refreshToken] = user
			m.mu.Unlock()

			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"access_token":  "access_" + code,
				"refresh_token": refreshToken,
				"expires_in":    3600,
				"token_type":    "Bearer",
			})
			return
		}
	} else if grantType == "refresh_token" {
		refreshToken := params.Get("refresh_token")
		m.mu.Lock()
		_, ok := m.refreshTokens[refreshToken]
		m.mu.Unlock()

		if ok {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"access_token":  "access_refreshed_" + refreshToken,
				"refresh_token": refreshToken,
				"expires_in":    3600,
				"token_type":    "Bearer",
			})
			return
		}
	}

	w.WriteHeader(http.StatusBadRequest)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"error": "invalid_grant"})
}

func (m *MockOAuthServer) handleUserInfo(w http.ResponseWriter, r *http.Request) {
	auth := r.Header.Get("Authorization")
	if !strings.HasPrefix(auth, "Bearer ") {
		w.WriteHeader(http.StatusUnauthorized)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"error": "invalid_token"})
		return
	}

	token := auth[7:]

	for code, user := range mockUsers {
		if token == "access_"+code || token == "access_refreshed_refresh_"+code {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"id":             user.ID,
				"email":          user.Email,
				"name":           user.Name,
				"picture":        user.Picture,
				"verified_email": true,
			})
			return
		}
	}

	w.WriteHeader(http.StatusUnauthorized)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"error": "invalid_token"})
}
