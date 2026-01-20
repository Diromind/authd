package core_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"authd/core"
	"authd/core/providers"
	"authd/storage"

	"github.com/stretchr/testify/assert"
)

func setupTestServer() (*core.Server, *core.Config) {
	config := &core.Config{
		JWTSecret:            "test-secret-key-for-testing-purposes-only",
		AccessTokenDuration:  1800,
		RefreshTokenDuration: 2592000,
	}
	repo := storage.NewMockRepository()
	providerMap := map[core.Provider]core.AuthProvider{
		providers.ProviderMock: providers.NewMockProvider(),
	}
	authService := core.NewAuthService(repo, config, providerMap)
	return core.NewServer(authService, config), config
}

func makeRequest(method, path string, body interface{}) (*http.Request, *httptest.ResponseRecorder) {
	var bodyReader *bytes.Reader

	switch v := body.(type) {
	case string:
		bodyReader = bytes.NewReader([]byte(v))
	case nil:
		bodyReader = bytes.NewReader([]byte{})
	default:
		jsonBody, _ := json.Marshal(body)
		bodyReader = bytes.NewReader(jsonBody)
	}

	req := httptest.NewRequest(method, path, bodyReader)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	w := httptest.NewRecorder()
	return req, w
}

func TestHandleLogin_Success(t *testing.T) {
	server, _ := setupTestServer()

	reqBody := map[string]string{
		"provider": "mock",
		"code":     providers.ValidCode1,
	}
	req, w := makeRequest(http.MethodPost, "/login", reqBody)

	server.HandleLogin(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp core.LoginResponse
	err := json.NewDecoder(w.Body).Decode(&resp)
	assert.NoError(t, err)
	assert.NotEmpty(t, resp.AccessToken)
	assert.NotEmpty(t, resp.RefreshToken)
	assert.NotEmpty(t, resp.UserID)
}

func TestHandleLogin_AnotherUser(t *testing.T) {
	server, _ := setupTestServer()

	reqBody := map[string]string{
		"provider": "mock",
		"code":     providers.ValidCode2,
	}
	req, w := makeRequest(http.MethodPost, "/login", reqBody)

	server.HandleLogin(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp core.LoginResponse
	err := json.NewDecoder(w.Body).Decode(&resp)
	assert.NoError(t, err)
	assert.NotEmpty(t, resp.AccessToken)
}

func TestHandleLogin_InvalidProvider(t *testing.T) {
	server, _ := setupTestServer()

	reqBody := map[string]string{
		"provider": "invalid_provider",
		"code":     "some_code",
	}
	req, w := makeRequest(http.MethodPost, "/login", reqBody)

	server.HandleLogin(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)

	var resp map[string]string
	json.NewDecoder(w.Body).Decode(&resp)
	assert.Equal(t, "invalid_provider", resp["error"])
}

func TestHandleLogin_InvalidCode(t *testing.T) {
	server, _ := setupTestServer()

	reqBody := map[string]string{
		"provider": "mock",
		"code":     "invalid_code",
	}
	body, _ := json.Marshal(reqBody)

	req := httptest.NewRequest(http.MethodPost, "/login", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	server.HandleLogin(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)

	var resp map[string]string
	json.NewDecoder(w.Body).Decode(&resp)
	assert.Equal(t, "login_failed", resp["error"])
}

func TestHandleLogin_InvalidJSON(t *testing.T) {
	server, _ := setupTestServer()

	req, w := makeRequest(http.MethodPost, "/login", "invalid json")

	server.HandleLogin(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestHandleLogin_MethodNotAllowed(t *testing.T) {
	server, _ := setupTestServer()

	req, w := makeRequest(http.MethodGet, "/login", nil)

	server.HandleLogin(w, req)

	assert.Equal(t, http.StatusMethodNotAllowed, w.Code)
}

func TestHandleRefresh_Success(t *testing.T) {
	server, _ := setupTestServer()

	reqBody := map[string]string{
		"refresh_token": storage.Token1.Token,
	}
	body, _ := json.Marshal(reqBody)

	req := httptest.NewRequest(http.MethodPost, "/refresh", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	server.HandleRefresh(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp map[string]string
	err := json.NewDecoder(w.Body).Decode(&resp)
	assert.NoError(t, err)
	assert.NotEmpty(t, resp["access_token"])
}

func TestHandleRefresh_InvalidToken(t *testing.T) {
	server, _ := setupTestServer()

	reqBody := map[string]string{
		"refresh_token": "invalid_token",
	}
	body, _ := json.Marshal(reqBody)

	req := httptest.NewRequest(http.MethodPost, "/refresh", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	server.HandleRefresh(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)

	var resp map[string]string
	json.NewDecoder(w.Body).Decode(&resp)
	assert.Equal(t, "invalid_token", resp["error"])
}

func TestHandleRefresh_ExpiredToken(t *testing.T) {
	server, _ := setupTestServer()

	reqBody := map[string]string{
		"refresh_token": storage.Token3.Token,
	}
	body, _ := json.Marshal(reqBody)

	req := httptest.NewRequest(http.MethodPost, "/refresh", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	server.HandleRefresh(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)

	var resp map[string]string
	json.NewDecoder(w.Body).Decode(&resp)
	assert.Equal(t, "invalid_token", resp["error"])
}

func TestHandleRefresh_MissingToken(t *testing.T) {
	server, _ := setupTestServer()

	reqBody := map[string]string{
		"refresh_token": "",
	}
	body, _ := json.Marshal(reqBody)

	req := httptest.NewRequest(http.MethodPost, "/refresh", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	server.HandleRefresh(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestHandleRefresh_MethodNotAllowed(t *testing.T) {
	server, _ := setupTestServer()

	req, w := makeRequest(http.MethodGet, "/refresh", nil)

	server.HandleRefresh(w, req)

	assert.Equal(t, http.StatusMethodNotAllowed, w.Code)
}

func TestHandleRefresh_InvalidJSON(t *testing.T) {
	server, _ := setupTestServer()

	req, w := makeRequest(http.MethodPost, "/refresh", "invalid json")

	server.HandleRefresh(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestHandleLogout_Success(t *testing.T) {
	server, _ := setupTestServer()

	reqBody := map[string]string{
		"refresh_token": storage.Token1.Token,
	}
	body, _ := json.Marshal(reqBody)

	req := httptest.NewRequest(http.MethodPost, "/logout", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	server.HandleLogout(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp map[string]string
	json.NewDecoder(w.Body).Decode(&resp)
	assert.Equal(t, "logged_out", resp["status"])
}

func TestHandleLogout_NonExistentToken(t *testing.T) {
	server, _ := setupTestServer()

	reqBody := map[string]string{
		"refresh_token": "non_existent_token",
	}
	body, _ := json.Marshal(reqBody)

	req := httptest.NewRequest(http.MethodPost, "/logout", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	server.HandleLogout(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestHandleLogout_MethodNotAllowed(t *testing.T) {
	server, _ := setupTestServer()

	req, w := makeRequest(http.MethodGet, "/logout", nil)

	server.HandleLogout(w, req)

	assert.Equal(t, http.StatusMethodNotAllowed, w.Code)
}

func TestHandleLogout_InvalidJSON(t *testing.T) {
	server, _ := setupTestServer()

	req, w := makeRequest(http.MethodPost, "/logout", "invalid json")

	server.HandleLogout(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestHandleLogout_MissingToken(t *testing.T) {
	server, _ := setupTestServer()

	reqBody := map[string]string{
		"refresh_token": "",
	}
	body, _ := json.Marshal(reqBody)

	req := httptest.NewRequest(http.MethodPost, "/logout", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	server.HandleLogout(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)

	var resp map[string]string
	json.NewDecoder(w.Body).Decode(&resp)
	assert.Equal(t, "invalid_request", resp["error"])
}

func TestHandleLogoutAll_Success(t *testing.T) {
	server, config := setupTestServer()

	accessToken, err := core.GenerateAccessToken(storage.User1.ID, config)
	assert.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, "/logout-all", nil)
	req.Header.Set("Authorization", "Bearer "+accessToken)
	w := httptest.NewRecorder()

	server.HandleLogoutAll(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp map[string]string
	json.NewDecoder(w.Body).Decode(&resp)
	assert.Equal(t, "logged_out_all_devices", resp["status"])
}

func TestHandleLogoutAll_MissingAuth(t *testing.T) {
	server, _ := setupTestServer()

	req, w := makeRequest(http.MethodPost, "/logout-all", nil)

	server.HandleLogoutAll(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestHandleLogoutAll_InvalidToken(t *testing.T) {
	server, _ := setupTestServer()

	req := httptest.NewRequest(http.MethodPost, "/logout-all", nil)
	req.Header.Set("Authorization", "Bearer invalid_jwt_token")
	w := httptest.NewRecorder()

	server.HandleLogoutAll(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestHandleLogoutAll_MethodNotAllowed(t *testing.T) {
	server, _ := setupTestServer()

	req, w := makeRequest(http.MethodGet, "/logout-all", nil)

	server.HandleLogoutAll(w, req)

	assert.Equal(t, http.StatusMethodNotAllowed, w.Code)
}

func TestHandleLogoutAll_MalformedAuthHeader(t *testing.T) {
	server, _ := setupTestServer()

	req := httptest.NewRequest(http.MethodPost, "/logout-all", nil)
	req.Header.Set("Authorization", "InvalidFormat")
	w := httptest.NewRecorder()

	server.HandleLogoutAll(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)

	var resp map[string]string
	json.NewDecoder(w.Body).Decode(&resp)
	assert.Equal(t, "invalid_token", resp["error"])
}

func TestHandleUserInfo_Success(t *testing.T) {
	server, config := setupTestServer()

	accessToken, err := core.GenerateAccessToken(storage.User1.ID, config)
	assert.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/userinfo", nil)
	req.Header.Set("Authorization", "Bearer "+accessToken)
	w := httptest.NewRecorder()

	server.HandleUserInfo(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp core.UserInfo
	err = json.NewDecoder(w.Body).Decode(&resp)
	assert.NoError(t, err)
	assert.NotEmpty(t, resp.Email)
	assert.NotEmpty(t, resp.Name)
}

func TestHandleUserInfo_MissingAuth(t *testing.T) {
	server, _ := setupTestServer()

	req, w := makeRequest(http.MethodGet, "/userinfo", nil)

	server.HandleUserInfo(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestHandleUserInfo_InvalidToken(t *testing.T) {
	server, _ := setupTestServer()

	req := httptest.NewRequest(http.MethodGet, "/userinfo", nil)
	req.Header.Set("Authorization", "Bearer invalid_jwt_token")
	w := httptest.NewRecorder()

	server.HandleUserInfo(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestHandleUserInfo_MethodNotAllowed(t *testing.T) {
	server, _ := setupTestServer()

	req, w := makeRequest(http.MethodPost, "/userinfo", nil)

	server.HandleUserInfo(w, req)

	assert.Equal(t, http.StatusMethodNotAllowed, w.Code)
}

func TestHandleUserInfo_MalformedAuthHeader(t *testing.T) {
	server, _ := setupTestServer()

	req := httptest.NewRequest(http.MethodGet, "/userinfo", nil)
	req.Header.Set("Authorization", "InvalidFormat")
	w := httptest.NewRecorder()

	server.HandleUserInfo(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)

	var resp map[string]string
	json.NewDecoder(w.Body).Decode(&resp)
	assert.Equal(t, "invalid_token", resp["error"])
}

func TestHandleUserInfo_UserNotFound(t *testing.T) {
	server, config := setupTestServer()

	nonExistentUserID := storage.User1.ID
	nonExistentUserID[0] = 0xFF

	accessToken, err := core.GenerateAccessToken(nonExistentUserID, config)
	assert.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/userinfo", nil)
	req.Header.Set("Authorization", "Bearer "+accessToken)
	w := httptest.NewRecorder()

	server.HandleUserInfo(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)

	var resp map[string]string
	json.NewDecoder(w.Body).Decode(&resp)
	assert.Equal(t, "internal_error", resp["error"])
}

func TestHandleHealth(t *testing.T) {
	server, _ := setupTestServer()

	req, w := makeRequest(http.MethodGet, "/health", nil)

	server.HandleHealth(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp map[string]string
	json.NewDecoder(w.Body).Decode(&resp)
	assert.Equal(t, "ok", resp["status"])
}
