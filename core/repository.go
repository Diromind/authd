package core

import (
	"context"
	"errors"

	"github.com/google/uuid"
)

var (
	ErrNotFound            = errors.New("not found")
	ErrAlreadyExists       = errors.New("already exists")
	ErrUnsupportedProvider = errors.New("unsupported provider")
)

type Repository interface {
	// User operations

	FindByID(ctx context.Context, id uuid.UUID) (*User, error)

	FindByProviderID(ctx context.Context, providerID string, provider Provider) (*User, error)

	CreateUser(ctx context.Context, user *User) error

	UpdateProviderRefreshToken(ctx context.Context, userID uuid.UUID, refreshToken string, provider Provider) error

	// RefreshToken operations

	CreateRefreshToken(ctx context.Context, token *RefreshToken) error

	FindRefreshToken(ctx context.Context, token string) (*RefreshToken, error)

	DeleteRefreshToken(ctx context.Context, token string) error

	DeleteAllUserRefreshTokens(ctx context.Context, userID uuid.UUID) error

	DeleteExpiredRefreshTokens(ctx context.Context) (int64, error)
}
