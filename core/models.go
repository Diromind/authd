package core

import (
	"time"

	"github.com/google/uuid"
)

// Provider represents an OAuth authentication provider
type Provider string

const (
	ProviderGoogle Provider = "google"
	ProviderYandex Provider = "yandex"
	// Future providers can be added here
)

// ProviderAuthData represents authentication data for a single OAuth provider
type ProviderAuthData struct {
	Provider     Provider
	ProviderID   string
	RefreshToken string
}

// User represents an authenticated user with linked OAuth accounts
type User struct {
	ID        uuid.UUID
	CreatedAt time.Time
	UpdatedAt time.Time
	Providers []ProviderAuthData
}

// RefreshToken represents an authd session token with ID.Key format (ADRT_{ID}.{Key})
type RefreshToken struct {
	TokenID      string    // Plaintext ID for lookup (primary key)
	TokenKeyHash string    // Bcrypt hash of Key for verification
	UserID       uuid.UUID
	CreatedAt    time.Time
	ExpiresAt    time.Time
}
