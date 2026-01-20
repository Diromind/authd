package core

import (
	"context"
	"errors"
)

var (
	ErrProviderTokenExchange = errors.New("provider token exchange failed")
	ErrProviderUserInfo = errors.New("provider user info request failed")
	ErrProviderRefreshToken = errors.New("provider token refresh failed")
)

// OAuthTokens represents the tokens returned by an OAuth provider
type OAuthTokens struct {
	AccessToken  string
	RefreshToken string
	ExpiresIn    int
}

// UserInfo represents user information returned by an OAuth provider
type UserInfo struct {
	ProviderUserID string
	Email          string
	Name           string
	Picture        string
}

type AuthProvider interface {
	ExchangeCode(ctx context.Context, code string) (*OAuthTokens, error)

	GetUserInfo(ctx context.Context, accessToken string) (*UserInfo, error)

	RefreshAccessToken(ctx context.Context, refreshToken string) (*OAuthTokens, error)

	Provider() Provider
}
