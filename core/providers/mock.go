package providers

import (
	"context"

	"authd/core"
)

const (
	ProviderMock core.Provider = "mock"
)

// Predefined test authorization codes
const (
	ValidCode1 = "mock_auth_code_1"
	ValidCode2 = "mock_auth_code_2"
	ValidCode3 = "mock_auth_code_3"
)

// Predefined test OAuth tokens
var (
	Tokens1 = &core.OAuthTokens{
		AccessToken:  "mock_access_token_1",
		RefreshToken: "mock_refresh_token_1",
		ExpiresIn:    3600,
	}

	Tokens2 = &core.OAuthTokens{
		AccessToken:  "mock_access_token_2",
		RefreshToken: "mock_refresh_token_2",
		ExpiresIn:    3600,
	}

	Tokens3 = &core.OAuthTokens{
		AccessToken:  "mock_access_token_3",
		RefreshToken: "mock_refresh_token_3",
		ExpiresIn:    3600,
	}

	Tokens1Refreshed = &core.OAuthTokens{
		AccessToken:  "mock_access_token_1_refreshed",
		RefreshToken: "mock_refresh_token_1", // Same refresh token
		ExpiresIn:    3600,
	}

	Tokens2Refreshed = &core.OAuthTokens{
		AccessToken:  "mock_access_token_2_refreshed",
		RefreshToken: "mock_refresh_token_2", // Same refresh token
		ExpiresIn:    3600,
	}

	Tokens3Refreshed = &core.OAuthTokens{
		AccessToken:  "mock_access_token_3_refreshed",
		RefreshToken: "mock_refresh_token_3", // Same refresh token
		ExpiresIn:    3600,
	}
)

// Predefined test user info
var (
	User1 = &core.UserInfo{
		ProviderUserID: "mock_user_1",
		Email:          "user1@mock.test",
		Name:           "Mock User One",
		Picture:        "https://mock.test/avatar1.jpg",
	}

	User2 = &core.UserInfo{
		ProviderUserID: "mock_user_2",
		Email:          "user2@mock.test",
		Name:           "Mock User Two",
		Picture:        "https://mock.test/avatar2.jpg",
	}

	User3 = &core.UserInfo{
		ProviderUserID: "mock_user_3",
		Email:          "user3@mock.test",
		Name:           "Mock User Three",
		Picture:        "https://mock.test/avatar3.jpg",
	}
)

// MockProvider is a test implementation of AuthProvider
type MockProvider struct {
	codeToTokens     map[string]*core.OAuthTokens
	accessToUserInfo map[string]*core.UserInfo
	refreshToTokens  map[string]*core.OAuthTokens

	// track method calls for verification
	ExchangeCodeCalls       int
	GetUserInfoCalls        int
	RefreshAccessTokenCalls int
}

func NewMockProvider() *MockProvider {
	return &MockProvider{
		codeToTokens: map[string]*core.OAuthTokens{
			ValidCode1: Tokens1,
			ValidCode2: Tokens2,
			ValidCode3: Tokens3,
		},

		accessToUserInfo: map[string]*core.UserInfo{
			Tokens1.AccessToken:          User1,
			Tokens1Refreshed.AccessToken: User1,
			Tokens2.AccessToken:          User2,
			Tokens2Refreshed.AccessToken: User2,
			Tokens3.AccessToken:          User3,
		},

		refreshToTokens: map[string]*core.OAuthTokens{
			Tokens1.RefreshToken: Tokens1Refreshed,
			Tokens2.RefreshToken: Tokens2Refreshed,
			Tokens3.RefreshToken: Tokens3Refreshed,
		},
	}
}

func (m *MockProvider) ExchangeCode(ctx context.Context, code string) (*core.OAuthTokens, error) {
	m.ExchangeCodeCalls++

	tokens, ok := m.codeToTokens[code]
	if !ok {
		return nil, core.ErrInvalidToken
	}

	return tokens, nil
}

func (m *MockProvider) GetUserInfo(ctx context.Context, accessToken string) (*core.UserInfo, error) {
	m.GetUserInfoCalls++

	userInfo, ok := m.accessToUserInfo[accessToken]
	if !ok {
		return nil, core.ErrInvalidToken
	}

	return userInfo, nil
}

func (m *MockProvider) RefreshAccessToken(ctx context.Context, refreshToken string) (*core.OAuthTokens, error) {
	m.RefreshAccessTokenCalls++

	tokens, ok := m.refreshToTokens[refreshToken]
	if !ok {
		return nil, core.ErrInvalidToken
	}

	return tokens, nil
}

func (m *MockProvider) Provider() core.Provider {
	return ProviderMock
}
