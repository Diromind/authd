package storage

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"io"
	"time"

	"authd/core"
	"authd/core/providers"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

func testEncrypt(plaintext string) string {
	key := []byte("12345678901234567890123456789012")
	block, _ := aes.NewCipher(key)
	gcm, _ := cipher.NewGCM(block)
	nonce := make([]byte, gcm.NonceSize())
	io.ReadFull(rand.Reader, nonce)
	ciphertext := gcm.Seal(nonce, nonce, []byte(plaintext), nil)
	return base64.StdEncoding.EncodeToString(ciphertext)
}

var (
	User1 = &core.User{
		ID:        uuid.MustParse("11111111-1111-1111-1111-111111111111"),
		CreatedAt: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		UpdatedAt: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		Providers: []core.ProviderAuthData{
			{
				Provider:     providers.ProviderMock,
				ProviderID:   "mock_user_1",
				RefreshToken: testEncrypt("mock_refresh_token_1"),
			},
		},
	}

	User2 = &core.User{
		ID:        uuid.MustParse("22222222-2222-2222-2222-222222222222"),
		CreatedAt: time.Date(2026, 1, 2, 0, 0, 0, 0, time.UTC),
		UpdatedAt: time.Date(2026, 1, 2, 0, 0, 0, 0, time.UTC),
		Providers: []core.ProviderAuthData{
			{
				Provider:     core.ProviderGoogle,
				ProviderID:   "mock_user_2",
				RefreshToken: testEncrypt("mock_refresh_token_2"),
			},
			{
				Provider:     core.ProviderYandex,
				ProviderID:   "mock_user_2",
				RefreshToken: testEncrypt("mock_refresh_token_2"),
			},
		},
	}

	User3 = &core.User{
		ID:        uuid.MustParse("33333333-3333-3333-3333-333333333333"),
		CreatedAt: time.Date(2026, 1, 3, 0, 0, 0, 0, time.UTC),
		UpdatedAt: time.Date(2026, 1, 3, 0, 0, 0, 0, time.UTC),
		Providers: []core.ProviderAuthData{
			{
				Provider:     providers.ProviderMock,
				ProviderID:   "mock_user_3",
				RefreshToken: testEncrypt("mock_refresh_token_1"),
			},
		},
	}

	AllUsers = []*core.User{User1, User2, User3}
)

const (
	Token1Key = "test_key_1"
	Token2Key = "test_key_2"
	Token3Key = "test_key_3"
	Token4Key = "test_key_4"
)

var (
	token_hash_1, _ = bcrypt.GenerateFromPassword([]byte(Token1Key), 12)
	token_hash_2, _ = bcrypt.GenerateFromPassword([]byte(Token2Key), 12)
	token_hash_3, _ = bcrypt.GenerateFromPassword([]byte(Token3Key), 12)
	token_hash_4, _ = bcrypt.GenerateFromPassword([]byte(Token4Key), 12)

	Token1 = &core.RefreshToken{
		TokenID:      "token_id_1",
		TokenKeyHash: string(token_hash_1),
		UserID:       User1.ID,
		CreatedAt:    time.Now().Add(-24 * time.Hour),
		ExpiresAt:    time.Now().Add(30 * 24 * time.Hour),
	}

	Token2 = &core.RefreshToken{
		TokenID:      "token_id_2",
		TokenKeyHash: string(token_hash_2),
		UserID:       User2.ID,
		CreatedAt:    time.Now().Add(-24 * time.Hour),
		ExpiresAt:    time.Now().Add(30 * 24 * time.Hour),
	}

	Token3 = &core.RefreshToken{
		TokenID:      "token_id_3_expired",
		TokenKeyHash: string(token_hash_3),
		UserID:       User3.ID,
		CreatedAt:    time.Date(2023, 1, 1, 0, 0, 0, 0, time.UTC),
		ExpiresAt:    time.Date(2023, 1, 31, 23, 59, 59, 0, time.UTC),
	}

	Token4 = &core.RefreshToken{
		TokenID:      "token_id_1_device2",
		TokenKeyHash: string(token_hash_4),
		UserID:       User1.ID,
		CreatedAt:    time.Now().Add(-12 * time.Hour),
		ExpiresAt:    time.Now().Add(30 * 24 * time.Hour),
	}

	Token1Full = "ADRT_token_id_1." + Token1Key
	Token2Full = "ADRT_token_id_2." + Token2Key
	Token3Full = "ADRT_token_id_3_expired." + Token3Key
	Token4Full = "ADRT_token_id_1_device2." + Token4Key

	AllTokens = []*core.RefreshToken{Token1, Token2, Token3, Token4}
)

type MockRepository struct {
	usersByID     map[uuid.UUID]*core.User
	providerUsers map[core.Provider]map[string]*core.User // provider -> provider_id -> user
	refreshTokens map[string]*core.RefreshToken

	// Track method calls for verification
	FindByIDCalls           int
	FindByProviderIDCalls   int
	CreateUserCalls         int
	CreateRefreshTokenCalls int
}

func NewMockRepository() *MockRepository {
	repo := &MockRepository{
		usersByID:     make(map[uuid.UUID]*core.User),
		providerUsers: make(map[core.Provider]map[string]*core.User),
		refreshTokens: make(map[string]*core.RefreshToken),
	}

	// Build users by ID map
	for _, user := range AllUsers {
		repo.usersByID[user.ID] = user

		// Build provider maps (abstract over all providers)
		for _, providerData := range user.Providers {
			if repo.providerUsers[providerData.Provider] == nil {
				repo.providerUsers[providerData.Provider] = make(map[string]*core.User)
			}
			repo.providerUsers[providerData.Provider][providerData.ProviderID] = user
		}
	}

	// Build refresh tokens map (keyed by TokenID)
	for _, token := range AllTokens {
		repo.refreshTokens[token.TokenID] = token
	}

	return repo
}

func (m *MockRepository) FindByID(ctx context.Context, id uuid.UUID) (*core.User, error) {
	m.FindByIDCalls++

	user, ok := m.usersByID[id]
	if !ok {
		return nil, core.ErrNotFound
	}
	return user, nil
}

func (m *MockRepository) FindByProviderID(ctx context.Context, providerID string, provider core.Provider) (*core.User, error) {
	m.FindByProviderIDCalls++

	providerMap, providerExists := m.providerUsers[provider]
	if !providerExists {
		return nil, core.ErrNotFound
	}

	user, userExists := providerMap[providerID]
	if !userExists {
		return nil, core.ErrNotFound
	}

	return user, nil
}

// CreateUser simulates creating a user (always succeeds in mock)
func (m *MockRepository) CreateUser(ctx context.Context, user *core.User) error {
	m.CreateUserCalls++

	// Check for duplicate provider IDs
	for _, providerData := range user.Providers {
		if providerMap, exists := m.providerUsers[providerData.Provider]; exists {
			if _, userExists := providerMap[providerData.ProviderID]; userExists {
				return core.ErrAlreadyExists
			}
		}
	}

	return nil
}

// UpdateProviderRefreshToken simulates updating a refresh token (always succeeds)
func (m *MockRepository) UpdateProviderRefreshToken(ctx context.Context, userID uuid.UUID, refreshToken string, provider core.Provider) error {
	// In mock, just verify user exists
	_, err := m.FindByID(ctx, userID)
	return err
}

// CreateRefreshToken simulates creating a refresh token (always succeeds)
func (m *MockRepository) CreateRefreshToken(ctx context.Context, token *core.RefreshToken) error {
	m.CreateRefreshTokenCalls++

	if _, exists := m.refreshTokens[token.TokenID]; exists {
		return core.ErrAlreadyExists
	}

	return nil
}

func (m *MockRepository) FindRefreshTokenByID(ctx context.Context, tokenID string) (*core.RefreshToken, error) {
	refreshToken, ok := m.refreshTokens[tokenID]
	if !ok {
		return nil, core.ErrNotFound
	}
	return refreshToken, nil
}

// DeleteRefreshToken simulates deleting a refresh token (always succeeds if exists)
func (m *MockRepository) DeleteRefreshTokenByID(ctx context.Context, tokenID string) error {
	_, err := m.FindRefreshTokenByID(ctx, tokenID)
	return err
}

// DeleteAllUserRefreshTokens simulates deleting all user tokens (always succeeds if user exists)
func (m *MockRepository) DeleteAllUserRefreshTokens(ctx context.Context, userID uuid.UUID) error {
	_, err := m.FindByID(ctx, userID)
	return err
}

// DeleteExpiredRefreshTokens simulates deleting old tokens (returns amount of such)
func (m *MockRepository) DeleteExpiredRefreshTokens(ctx context.Context) (int64, error) {
	now := time.Now()
	var count int64

	for _, token := range m.refreshTokens {
		if now.After(token.ExpiresAt) {
			count++
		}
	}

	return count, nil
}
