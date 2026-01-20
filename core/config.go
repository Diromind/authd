package core

type Config struct {
	// JWT configuration
	JWTSecret            string // Secret key for signing JWT tokens
	AccessTokenDuration  int    // Access token lifetime in seconds
	RefreshTokenDuration int    // Refresh token lifetime in seconds

	// Google OAuth configuration
	GoogleClientID     string
	GoogleClientSecret string
	GoogleRedirectURI  string // OAuth redirect URI for Google

	// Yandex OAuth configuration
	YandexClientID     string
	YandexClientSecret string
	YandexRedirectURI  string // OAuth redirect URI for Yandex
}
