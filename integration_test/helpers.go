package integration_test

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	_ "modernc.org/sqlite"
)

type LoginResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	UserID       string `json:"user_id"`
}

type UserInfoResponse struct {
	ProviderUserID string `json:"ProviderUserID"`
	Email          string `json:"Email"`
	Name           string `json:"Name"`
	Picture        string `json:"Picture"`
}

type RefreshResponse struct {
	AccessToken string `json:"access_token"`
}

type StatusResponse struct {
	Status string `json:"status"`
}

func login(baseURL, code string) (*http.Response, error) {
	body := map[string]string{
		"provider": "google",
		"code":     code,
	}
	jsonBody, _ := json.Marshal(body)

	client := &http.Client{Timeout: 5 * time.Second}
	return client.Post(baseURL+"/login", "application/json", bytes.NewReader(jsonBody))
}

func getUserInfo(baseURL, accessToken string) (*http.Response, error) {
	client := &http.Client{Timeout: 5 * time.Second}
	req, _ := http.NewRequest("GET", baseURL+"/userinfo", nil)
	req.Header.Set("Authorization", "Bearer "+accessToken)
	return client.Do(req)
}

func refreshToken(baseURL, refreshToken string) (*http.Response, error) {
	body := map[string]string{
		"refresh_token": refreshToken,
	}
	jsonBody, _ := json.Marshal(body)

	client := &http.Client{Timeout: 5 * time.Second}
	return client.Post(baseURL+"/refresh", "application/json", bytes.NewReader(jsonBody))
}

func logout(baseURL, refreshToken string) (*http.Response, error) {
	body := map[string]string{
		"refresh_token": refreshToken,
	}
	jsonBody, _ := json.Marshal(body)

	client := &http.Client{Timeout: 5 * time.Second}
	return client.Post(baseURL+"/logout", "application/json", bytes.NewReader(jsonBody))
}

func logoutAll(baseURL, accessToken string) (*http.Response, error) {
	client := &http.Client{Timeout: 5 * time.Second}
	req, _ := http.NewRequest("POST", baseURL+"/logout-all", nil)
	req.Header.Set("Authorization", "Bearer "+accessToken)
	return client.Do(req)
}

func countSessions(dbPath string) (int, error) {
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return 0, err
	}
	defer db.Close()

	var count int
	err = db.QueryRow("SELECT COUNT(*) FROM refresh_tokens").Scan(&count)
	return count, err
}

func countUsers(dbPath string) (int, error) {
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return 0, err
	}
	defer db.Close()

	var count int
	err = db.QueryRow("SELECT COUNT(*) FROM users").Scan(&count)
	return count, err
}

func getUserSessions(dbPath, userID string) ([]string, error) {
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, err
	}
	defer db.Close()

	rows, err := db.Query("SELECT token_id FROM refresh_tokens WHERE user_id = ?", userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var tokens []string
	for rows.Next() {
		var token string
		if err := rows.Scan(&token); err != nil {
			return nil, err
		}
		tokens = append(tokens, token)
	}

	return tokens, nil
}

func cleanDatabase(dbPath string) error {
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return err
	}
	defer db.Close()

	_, err = db.Exec("DELETE FROM refresh_tokens")
	if err != nil {
		return err
	}
	_, err = db.Exec("DELETE FROM user_providers")
	if err != nil {
		return err
	}
	_, err = db.Exec("DELETE FROM users")
	return err
}

func parseLoginResponse(resp *http.Response) (*LoginResponse, error) {
	var result LoginResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}
	return &result, nil
}

func parseUserInfoResponse(resp *http.Response) (*UserInfoResponse, error) {
	var result UserInfoResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}
	return &result, nil
}

func parseRefreshResponse(resp *http.Response) (*RefreshResponse, error) {
	var result RefreshResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}
	return &result, nil
}

func parseStatusResponse(resp *http.Response) (*StatusResponse, error) {
	var result StatusResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}
	return &result, nil
}

func extractTokenID(refreshToken string) string {
	parts := bytes.Split([]byte(refreshToken), []byte("."))
	if len(parts) != 2 {
		return ""
	}
	id := string(parts[0])
	if len(id) > 5 && id[:5] == "ADRT_" {
		return id[5:]
	}
	return id
}

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

func waitForServer(baseURL string, maxAttempts int) error {
	client := &http.Client{Timeout: 1 * time.Second}
	for i := 0; i < maxAttempts; i++ {
		resp, err := client.Get(baseURL + "/health")
		if err == nil && resp.StatusCode == 200 {
			resp.Body.Close()
			return nil
		}
		time.Sleep(500 * time.Millisecond)
	}
	return fmt.Errorf("server failed to start after %d attempts", maxAttempts)
}
