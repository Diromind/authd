package core

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
)

type LoginResponse struct {
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token"`
	UserID       uuid.UUID `json:"user_id"`
}

type AuthService struct {
	repo      Repository
	config    *Config
	providers map[Provider]AuthProvider
}

func NewAuthService(repo Repository, config *Config, providers map[Provider]AuthProvider) *AuthService {
	return &AuthService{
		repo:      repo,
		config:    config,
		providers: providers,
	}
}

func setProviderFields(user *User, provider Provider, providerUserID string, refreshToken string) error {
	switch provider {
	case ProviderGoogle:
		user.GoogleID = &providerUserID
		user.GoogleRefreshToken = &refreshToken
	case ProviderYandex:
		user.YandexID = &providerUserID
		user.YandexRefreshToken = &refreshToken
	default:
		return ErrUnsupportedProvider
	}
	return nil
}

func (s *AuthService) Login(ctx context.Context, provider Provider, code string) (*LoginResponse, error) {
	// 1. Get the provider implementation
	authProvider, ok := s.providers[provider]
	if !ok {
		return nil, ErrUnsupportedProvider
	}

	// 2. Exchange authorization code for OAuth tokens
	oauthTokens, err := authProvider.ExchangeCode(ctx, code)
	if err != nil {
		return nil, fmt.Errorf("failed to exchange code: %w", err)
	}

	// 3. Get user info from provider
	userInfo, err := authProvider.GetUserInfo(ctx, oauthTokens.AccessToken)
	if err != nil {
		return nil, fmt.Errorf("failed to get user info: %w", err)
	}

	// 4. Find or create user in our database
	user, err := s.repo.FindByProviderID(ctx, userInfo.ProviderUserID, provider)
	if err != nil {
		if err == ErrNotFound {
			// Create new user
			now := time.Now()
			user = &User{
				ID:        uuid.New(),
				CreatedAt: now,
				UpdatedAt: now,
			}

			if err := setProviderFields(user, provider, userInfo.ProviderUserID, oauthTokens.RefreshToken); err != nil {
				return nil, err
			}

			if err := s.repo.CreateUser(ctx, user); err != nil {
				return nil, fmt.Errorf("failed to create user: %w", err)
			}
		} else {
			return nil, fmt.Errorf("failed to find user: %w", err)
		}
	} else {
		// User exists - update OAuth refresh token (in case it changed)
		if err := s.repo.UpdateProviderRefreshToken(ctx, user.ID, oauthTokens.RefreshToken, provider); err != nil {
			return nil, fmt.Errorf("failed to update refresh token: %w", err)
		}
	}

	// 5. Generate authd's refresh token
	refreshToken := &RefreshToken{
		Token:     uuid.New().String(),
		UserID:    user.ID,
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(time.Duration(s.config.RefreshTokenDuration) * time.Second),
	}

	if err := s.repo.CreateRefreshToken(ctx, refreshToken); err != nil {
		return nil, fmt.Errorf("failed to create refresh token: %w", err)
	}

	// 6. Generate JWT access token
	accessToken, err := GenerateAccessToken(user.ID, s.config)
	if err != nil {
		return nil, fmt.Errorf("failed to generate access token: %w", err)
	}

	return &LoginResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken.Token,
		UserID:       user.ID,
	}, nil
}

func (s *AuthService) Refresh(ctx context.Context, refreshTokenStr string) (string, error) {
	// 1. Find refresh token in database
	refreshToken, err := s.repo.FindRefreshToken(ctx, refreshTokenStr)
	if err != nil {
		if err == ErrNotFound {
			return "", ErrInvalidToken
		}
		return "", fmt.Errorf("failed to find refresh token: %w", err)
	}

	// 2. Check if token is expired
	if time.Now().After(refreshToken.ExpiresAt) {
		_ = s.repo.DeleteRefreshToken(ctx, refreshTokenStr)
		return "", ErrExpiredToken
	}

	// 3. Generate new access token
	accessToken, err := GenerateAccessToken(refreshToken.UserID, s.config)
	if err != nil {
		return "", fmt.Errorf("failed to generate access token: %w", err)
	}

	return accessToken, nil
}

func (s *AuthService) Logout(ctx context.Context, refreshTokenStr string) error {
	if err := s.repo.DeleteRefreshToken(ctx, refreshTokenStr); err != nil {
		if err == ErrNotFound {
			// Token already deleted or never existed - consider it a success
			return nil
		}
		return fmt.Errorf("failed to delete refresh token: %w", err)
	}
	return nil
}

func (s *AuthService) LogoutAll(ctx context.Context, userID uuid.UUID) error {
	if err := s.repo.DeleteAllUserRefreshTokens(ctx, userID); err != nil {
		return fmt.Errorf("failed to delete user refresh tokens: %w", err)
	}
	return nil
}

func (s *AuthService) GetUserInfo(ctx context.Context, userID uuid.UUID) (*UserInfo, error) {
	// 1. Get user from database
	user, err := s.repo.FindByID(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to find user: %w", err)
	}

	// 2. Determine which provider to use (prefer Google, fallback to Yandex)
	var provider Provider
	var oauthRefreshToken string

	if user.GoogleRefreshToken != nil {
		provider = ProviderGoogle
		oauthRefreshToken = *user.GoogleRefreshToken
	} else if user.YandexRefreshToken != nil {
		provider = ProviderYandex
		oauthRefreshToken = *user.YandexRefreshToken
	} else {
		return nil, fmt.Errorf("user has no linked OAuth accounts")
	}

	// 3. Get provider implementation
	authProvider, ok := s.providers[provider]
	if !ok {
		return nil, ErrUnsupportedProvider
	}

	// 4. Refresh OAuth access token
	oauthTokens, err := authProvider.RefreshAccessToken(ctx, oauthRefreshToken)
	if err != nil {
		return nil, fmt.Errorf("failed to refresh OAuth token: %w", err)
	}

	// 5. Update stored OAuth refresh token if provider returned a new one
	if oauthTokens.RefreshToken != "" && oauthTokens.RefreshToken != oauthRefreshToken {
		_ = s.repo.UpdateProviderRefreshToken(ctx, userID, oauthTokens.RefreshToken, provider)
	}

	// 6. Fetch fresh user info from provider
	userInfo, err := authProvider.GetUserInfo(ctx, oauthTokens.AccessToken)
	if err != nil {
		return nil, fmt.Errorf("failed to get user info: %w", err)
	}

	return userInfo, nil
}
