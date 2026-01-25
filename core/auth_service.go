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
	crypto    *CryptoService
	providers map[Provider]AuthProvider
}

func NewAuthService(repo Repository, config *Config, providers map[Provider]AuthProvider, crypto *CryptoService) *AuthService {
	return &AuthService{
		repo:      repo,
		config:    config,
		crypto:    crypto,
		providers: providers,
	}
}

func addOrUpdateProvider(user *User, provider Provider, providerUserID string, refreshToken string) {
	// Check if provider already exists, update it
	for i := range user.Providers {
		if user.Providers[i].Provider == provider {
			user.Providers[i].ProviderID = providerUserID
			user.Providers[i].RefreshToken = refreshToken
			return
		}
	}
	// Provider doesn't exist, add new entry
	user.Providers = append(user.Providers, ProviderAuthData{
		Provider:     provider,
		ProviderID:   providerUserID,
		RefreshToken: refreshToken,
	})
}

func getProviderData(user *User, provider Provider) *ProviderAuthData {
	for i := range user.Providers {
		if user.Providers[i].Provider == provider {
			return &user.Providers[i]
		}
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

	// 4. Encrypt OAuth provider refresh token
	encryptedRefreshToken, err := s.crypto.EncryptToken(oauthTokens.RefreshToken)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt refresh token: %w", err)
	}

	// 5. Find or create user in our database
	user, err := s.repo.FindByProviderID(ctx, userInfo.ProviderUserID, provider)
	if err != nil {
		if err == ErrNotFound {
			// Create new user
			now := time.Now()
			user = &User{
				ID:        uuid.New(),
				CreatedAt: now,
				UpdatedAt: now,
				Providers: []ProviderAuthData{
					{
						Provider:     provider,
						ProviderID:   userInfo.ProviderUserID,
						RefreshToken: encryptedRefreshToken,
					},
				},
			}

			if err := s.repo.CreateUser(ctx, user); err != nil {
				return nil, fmt.Errorf("failed to create user: %w", err)
			}
		} else {
			return nil, fmt.Errorf("failed to find user: %w", err)
		}
	} else {
		// User exists - update OAuth refresh token (in case it changed)
		if err := s.repo.UpdateProviderRefreshToken(ctx, user.ID, encryptedRefreshToken, provider); err != nil {
			return nil, fmt.Errorf("failed to update refresh token: %w", err)
		}
	}

	// 6. Generate authd's refresh token
	fullToken, tokenParts, err := GenerateRefreshToken()
	if err != nil {
		return nil, fmt.Errorf("failed to generate refresh token: %w", err)
	}

	keyHash, err := s.crypto.HashToken(tokenParts.Key)
	if err != nil {
		return nil, fmt.Errorf("failed to hash token key: %w", err)
	}

	refreshToken := &RefreshToken{
		TokenID:      tokenParts.ID,
		TokenKeyHash: keyHash,
		UserID:       user.ID,
		CreatedAt:    time.Now(),
		ExpiresAt:    time.Now().Add(time.Duration(s.config.JWT.RefreshTokenDuration) * time.Second),
	}

	if err := s.repo.CreateRefreshToken(ctx, refreshToken); err != nil {
		return nil, fmt.Errorf("failed to create refresh token: %w", err)
	}

	// 7. Generate JWT access token
	accessToken, err := GenerateAccessToken(user.ID, s.config)
	if err != nil {
		return nil, fmt.Errorf("failed to generate access token: %w", err)
	}

	return &LoginResponse{
		AccessToken:  accessToken,
		RefreshToken: fullToken,
		UserID:       user.ID,
	}, nil
}

func (s *AuthService) Refresh(ctx context.Context, refreshTokenStr string) (string, error) {
	// 1. Parse token to extract ID and Key
	tokenParts, err := ParseRefreshToken(refreshTokenStr)
	if err != nil {
		return "", ErrInvalidToken
	}

	// 2. Find refresh token in database by ID
	refreshToken, err := s.repo.FindRefreshTokenByID(ctx, tokenParts.ID)
	if err != nil {
		if err == ErrNotFound {
			return "", ErrInvalidToken
		}
		return "", fmt.Errorf("failed to find refresh token: %w", err)
	}

	// 3. Check if token is expired
	if time.Now().After(refreshToken.ExpiresAt) {
		_ = s.repo.DeleteRefreshTokenByID(ctx, tokenParts.ID)
		return "", ErrExpiredToken
	}

	// 4. Verify token key hash
	if !s.crypto.VerifyTokenHash(tokenParts.Key, refreshToken.TokenKeyHash) {
		return "", ErrInvalidToken
	}

	// 5. Generate new access token
	accessToken, err := GenerateAccessToken(refreshToken.UserID, s.config)
	if err != nil {
		return "", fmt.Errorf("failed to generate access token: %w", err)
	}

	return accessToken, nil
}

func (s *AuthService) Logout(ctx context.Context, refreshTokenStr string) error {
	tokenParts, err := ParseRefreshToken(refreshTokenStr)
	if err != nil {
		return ErrInvalidToken
	}

	if err := s.repo.DeleteRefreshTokenByID(ctx, tokenParts.ID); err != nil {
		if err == ErrNotFound {
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

	// 2. Determine which provider to use (use first available provider)
	if len(user.Providers) == 0 {
		return nil, fmt.Errorf("user has no linked OAuth accounts")
	}

	providerData := user.Providers[0]
	provider := providerData.Provider
	encryptedOAuthToken := providerData.RefreshToken

	// 3. Decrypt OAuth provider refresh token
	oauthRefreshToken, err := s.crypto.DecryptToken(encryptedOAuthToken)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt OAuth refresh token: %w", err)
	}

	// 4. Get provider implementation
	authProvider, ok := s.providers[provider]
	if !ok {
		return nil, ErrUnsupportedProvider
	}

	// 5. Refresh OAuth access token
	oauthTokens, err := authProvider.RefreshAccessToken(ctx, oauthRefreshToken)
	if err != nil {
		return nil, fmt.Errorf("failed to refresh OAuth token: %w", err)
	}

	// 6. Update stored OAuth refresh token if provider returned a new one
	if oauthTokens.RefreshToken != "" && oauthTokens.RefreshToken != oauthRefreshToken {
		newEncrypted, err := s.crypto.EncryptToken(oauthTokens.RefreshToken)
		if err != nil {
			return nil, fmt.Errorf("failed to encrypt new refresh token: %w", err)
		}
		_ = s.repo.UpdateProviderRefreshToken(ctx, userID, newEncrypted, provider)
	}

	// 6. Fetch fresh user info from provider
	userInfo, err := authProvider.GetUserInfo(ctx, oauthTokens.AccessToken)
	if err != nil {
		return nil, fmt.Errorf("failed to get user info: %w", err)
	}

	return userInfo, nil
}
