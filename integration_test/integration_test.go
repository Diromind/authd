package integration_test

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/suite"
)

type IntegrationTestSuite struct {
	suite.Suite
	mockOAuth  *MockOAuthServer
	serverProc *exec.Cmd
	baseURL    string
	dbPath     string
	binaryPath string
	configPath string
}

func (s *IntegrationTestSuite) SetupSuite() {
	projectRoot, _ := filepath.Abs("..")
	s.binaryPath = filepath.Join(projectRoot, "authd-integration-test")
	s.configPath = filepath.Join(projectRoot, "integration_test", "config.test.yaml")
	s.dbPath = "/tmp/authd-integration-test.db"
	s.baseURL = "http://localhost:8082"

	s.mockOAuth = NewMockOAuthServer()

	if err := s.createTestConfig(); err != nil {
		s.T().Fatalf("Failed to create test config: %v", err)
	}

	if err := s.buildServer(); err != nil {
		s.T().Fatalf("Failed to build server: %v", err)
	}

	if err := s.startServer(); err != nil {
		s.T().Fatalf("Failed to start server: %v", err)
	}

	if err := waitForServer(s.baseURL, 10); err != nil {
		s.T().Fatalf("Server failed to start: %v", err)
	}
}

func (s *IntegrationTestSuite) TearDownSuite() {
	if s.serverProc != nil {
		s.serverProc.Process.Kill()
		s.serverProc.Wait()
	}

	if s.mockOAuth != nil {
		s.mockOAuth.Close()
	}

	os.Remove(s.dbPath)
	os.Remove(s.binaryPath)
	os.Remove(s.configPath)
}

func (s *IntegrationTestSuite) SetupTest() {
	if err := cleanDatabase(s.dbPath); err != nil {
		s.T().Fatalf("Failed to clean database: %v", err)
	}
}

func (s *IntegrationTestSuite) createTestConfig() error {
	config := fmt.Sprintf(`port: "8082"

db:
  type: "sqlite"
  sqlite_path: "%s"

jwt:
  secret: "test-secret-key-for-integration-tests"
  access_token_duration: 1800
  refresh_token_duration: 2592000

crypto:
  encryption_key: "12345678901234567890123456789012"

google:
  client_id: "mock_client_id"
  client_secret: "mock_client_secret"
  redirect_uri: "http://localhost:8082/callback"
  oauth_base_url: "%s"
  userinfo_base_url: "%s"
`, s.dbPath, s.mockOAuth.URL(), s.mockOAuth.URL())

	return os.WriteFile(s.configPath, []byte(config), 0644)
}

func (s *IntegrationTestSuite) buildServer() error {
	projectRoot, _ := filepath.Abs("..")
	cmd := exec.Command("go", "build", "-o", s.binaryPath, "./cmd/standalone")
	cmd.Dir = projectRoot
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("build failed: %v\n%s", err, output)
	}
	return nil
}

func (s *IntegrationTestSuite) startServer() error {
	s.serverProc = exec.Command(s.binaryPath)
	s.serverProc.Env = append(os.Environ(), "CONFIG_PATH="+s.configPath)
	s.serverProc.Stdout = io.Discard
	s.serverProc.Stderr = io.Discard

	if err := s.serverProc.Start(); err != nil {
		return err
	}

	time.Sleep(2 * time.Second)
	return nil
}

func (s *IntegrationTestSuite) TestHealthCheck() {
	resp, err := login(s.baseURL, "health_check")
	s.NoError(err)
	defer resp.Body.Close()

	resp, err = getUserInfo(s.baseURL, "fake")
	if resp != nil {
		resp.Body.Close()
	}

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()
	req, _ := exec.CommandContext(ctx, "curl", "-s", s.baseURL+"/health").Output()
	s.Contains(string(req), "ok")
}

func (s *IntegrationTestSuite) TestFullAuthFlow() {
	count, _ := countSessions(s.dbPath)
	s.Equal(0, count)

	loginResp, err := login(s.baseURL, "valid_code_1")
	s.NoError(err)
	s.Equal(200, loginResp.StatusCode)

	loginData, err := parseLoginResponse(loginResp)
	s.NoError(err)
	s.NotEmpty(loginData.AccessToken)
	s.NotEmpty(loginData.RefreshToken)
	s.NotEmpty(loginData.UserID)

	accessToken := loginData.AccessToken
	refreshTok := loginData.RefreshToken
	userID := loginData.UserID

	count, _ = countSessions(s.dbPath)
	s.Equal(1, count)
	userCount, _ := countUsers(s.dbPath)
	s.Equal(1, userCount)

	userInfoResp, err := getUserInfo(s.baseURL, accessToken)
	s.NoError(err)
	s.Equal(200, userInfoResp.StatusCode)

	userData, err := parseUserInfoResponse(userInfoResp)
	s.NoError(err)
	s.NotEmpty(userData.ProviderUserID)
	s.Equal("user1@example.com", userData.Email)

	time.Sleep(1 * time.Second)

	refreshResp, err := refreshToken(s.baseURL, refreshTok)
	s.NoError(err)
	s.Equal(200, refreshResp.StatusCode)

	newAccessData, err := parseRefreshResponse(refreshResp)
	s.NoError(err)
	newAccess := newAccessData.AccessToken
	s.NotEqual(accessToken, newAccess)

	userInfo2Resp, err := getUserInfo(s.baseURL, newAccess)
	s.NoError(err)
	s.Equal(200, userInfo2Resp.StatusCode)

	logoutResp, err := logout(s.baseURL, refreshTok)
	s.NoError(err)
	s.Equal(200, logoutResp.StatusCode)

	statusData, err := parseStatusResponse(logoutResp)
	s.NoError(err)
	s.Equal("logged_out", statusData.Status)

	count, _ = countSessions(s.dbPath)
	s.Equal(0, count)

	refreshAfterLogout, err := refreshToken(s.baseURL, refreshTok)
	s.NoError(err)
	s.Equal(401, refreshAfterLogout.StatusCode)

	_ = userID
}

func (s *IntegrationTestSuite) TestMultiSessionManagement() {
	session1Resp, _ := login(s.baseURL, "valid_code_1")
	session1, _ := parseLoginResponse(session1Resp)

	session2Resp, _ := login(s.baseURL, "valid_code_2")
	session2, _ := parseLoginResponse(session2Resp)

	session3Resp, _ := login(s.baseURL, "valid_code_3")
	session3, _ := parseLoginResponse(session3Resp)

	count, _ := countSessions(s.dbPath)
	s.Equal(3, count)
	s.Equal(session1.UserID, session2.UserID)
	s.Equal(session2.UserID, session3.UserID)

	userID := session1.UserID
	tokensBefore, _ := getUserSessions(s.dbPath, userID)
	s.Equal(3, len(tokensBefore))

	logoutResp, _ := logout(s.baseURL, session2.RefreshToken)
	s.Equal(200, logoutResp.StatusCode)

	count, _ = countSessions(s.dbPath)
	s.Equal(2, count)
	tokensAfter, _ := getUserSessions(s.dbPath, userID)
	s.Equal(2, len(tokensAfter))

	token1ID := extractTokenID(session1.RefreshToken)
	token2ID := extractTokenID(session2.RefreshToken)
	token3ID := extractTokenID(session3.RefreshToken)

	s.False(contains(tokensAfter, token2ID))
	s.True(contains(tokensAfter, token1ID))
	s.True(contains(tokensAfter, token3ID))

	refresh1, _ := refreshToken(s.baseURL, session1.RefreshToken)
	s.Equal(200, refresh1.StatusCode)

	refresh2, _ := refreshToken(s.baseURL, session2.RefreshToken)
	s.Equal(401, refresh2.StatusCode)

	logoutAllResp, _ := logoutAll(s.baseURL, session3.AccessToken)
	s.Equal(200, logoutAllResp.StatusCode)

	statusData, _ := parseStatusResponse(logoutAllResp)
	s.Equal("logged_out_all_devices", statusData.Status)

	count, _ = countSessions(s.dbPath)
	s.Equal(0, count)
}

func (s *IntegrationTestSuite) TestSessionIsolationBetweenUsers() {
	user1Resp, _ := login(s.baseURL, "valid_code_1")
	user1Session, _ := parseLoginResponse(user1Resp)

	time.Sleep(1 * time.Second)

	user2Resp, _ := login(s.baseURL, "another_user_code_1")
	user2Session, _ := parseLoginResponse(user2Resp)

	count, _ := countSessions(s.dbPath)
	s.Equal(2, count)
	userCount, _ := countUsers(s.dbPath)
	s.Equal(2, userCount)
	s.NotEqual(user1Session.UserID, user2Session.UserID)

	user1InfoResp, _ := getUserInfo(s.baseURL, user1Session.AccessToken)
	user1Info, _ := parseUserInfoResponse(user1InfoResp)

	user2InfoResp, _ := getUserInfo(s.baseURL, user2Session.AccessToken)
	user2Info, _ := parseUserInfoResponse(user2InfoResp)

	s.Equal("user1@example.com", user1Info.Email)
	s.Equal("user2@example.com", user2Info.Email)

	logout(s.baseURL, user1Session.RefreshToken)
	count, _ = countSessions(s.dbPath)
	s.Equal(1, count)

	user2Refresh, _ := refreshToken(s.baseURL, user2Session.RefreshToken)
	s.Equal(200, user2Refresh.StatusCode)
}

func (s *IntegrationTestSuite) TestMultiRefreshFlow() {
	loginResp, _ := login(s.baseURL, "valid_code_1")
	loginData, _ := parseLoginResponse(loginResp)
	refreshTok := loginData.RefreshToken

	tokens := []string{loginData.AccessToken}

	for i := 0; i < 3; i++ {
		time.Sleep(1 * time.Second)
		resp, err := refreshToken(s.baseURL, refreshTok)
		s.NoError(err)
		s.Equal(200, resp.StatusCode)

		newTokenData, _ := parseRefreshResponse(resp)
		newToken := newTokenData.AccessToken
		s.NotContains(tokens, newToken)
		tokens = append(tokens, newToken)
	}

	for _, token := range tokens {
		userInfoResp, _ := getUserInfo(s.baseURL, token)
		s.Equal(200, userInfoResp.StatusCode)
	}

	logoutAllResp, _ := logoutAll(s.baseURL, tokens[len(tokens)-1])
	s.Equal(200, logoutAllResp.StatusCode)
	count, _ := countSessions(s.dbPath)
	s.Equal(0, count)
}

func (s *IntegrationTestSuite) TestLoginCreatesNewSessionForExistingUser() {
	firstLoginResp, _ := login(s.baseURL, "valid_code_1")
	firstLogin, _ := parseLoginResponse(firstLoginResp)
	userID1 := firstLogin.UserID

	userCount, _ := countUsers(s.dbPath)
	s.Equal(1, userCount)
	sessionCount, _ := countSessions(s.dbPath)
	s.Equal(1, sessionCount)

	secondLoginResp, _ := login(s.baseURL, "valid_code_1")
	secondLogin, _ := parseLoginResponse(secondLoginResp)
	userID2 := secondLogin.UserID

	s.Equal(userID1, userID2)
	userCount, _ = countUsers(s.dbPath)
	s.Equal(1, userCount)
	sessionCount, _ = countSessions(s.dbPath)
	s.Equal(2, sessionCount)

	s.NotEqual(firstLogin.RefreshToken, secondLogin.RefreshToken)
}

func (s *IntegrationTestSuite) TestInvalidOperations() {
	invalidLogin, _ := login(s.baseURL, "invalid_code")
	s.Equal(401, invalidLogin.StatusCode)

	invalidRefresh, _ := refreshToken(s.baseURL, "not-a-real-token")
	s.Equal(401, invalidRefresh.StatusCode)

	invalidUserInfo, _ := getUserInfo(s.baseURL, "fake-jwt-token")
	s.Equal(401, invalidUserInfo.StatusCode)

	invalidLogoutAll, _ := logoutAll(s.baseURL, "bad-token")
	s.Equal(401, invalidLogoutAll.StatusCode)
}

func (s *IntegrationTestSuite) TestLogoutNonexistentToken() {
	resp, _ := logout(s.baseURL, "ADRT_nonexistent_id.nonexistent_key")
	s.Equal(200, resp.StatusCode)
}

func (s *IntegrationTestSuite) TestConcurrentSessionsIndependence() {
	s1Resp, _ := login(s.baseURL, "valid_code_1")
	s1, _ := parseLoginResponse(s1Resp)

	s2Resp, _ := login(s.baseURL, "valid_code_2")
	s2, _ := parseLoginResponse(s2Resp)

	s3Resp, _ := login(s.baseURL, "valid_code_3")
	s3, _ := parseLoginResponse(s3Resp)

	sessions := []*LoginResponse{s1, s2, s3}

	for _, session := range sessions {
		info, _ := getUserInfo(s.baseURL, session.AccessToken)
		s.Equal(200, info.StatusCode)
	}

	logout(s.baseURL, s2.RefreshToken)

	info1, _ := getUserInfo(s.baseURL, s1.AccessToken)
	s.Equal(200, info1.StatusCode)
	info3, _ := getUserInfo(s.baseURL, s3.AccessToken)
	s.Equal(200, info3.StatusCode)

	refresh1, _ := refreshToken(s.baseURL, s1.RefreshToken)
	s.Equal(200, refresh1.StatusCode)
	refresh2, _ := refreshToken(s.baseURL, s2.RefreshToken)
	s.Equal(401, refresh2.StatusCode)
	refresh3, _ := refreshToken(s.baseURL, s3.RefreshToken)
	s.Equal(200, refresh3.StatusCode)
}

func TestIntegrationSuite(t *testing.T) {
	suite.Run(t, new(IntegrationTestSuite))
}
