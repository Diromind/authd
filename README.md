# authd

**authd** is a standalone OAuth authentication service that unifies different login providers (Google, Yandex, Apple, etc.) into a single, easy-to-deploy authentication backend.

It exchanges OAuth provider tokens for your application's own JWT tokens, allowing you to centralize authentication logic while maintaining flexibility in deployment and storage options.

## What it Does

- **OAuth Integration**: Handles OAuth 2.0 flows for multiple providers
- **Token Management**: Issues JWT access tokens (short-lived) and refresh tokens (long-lived)
- **Privacy-First**: Stores only OAuth provider IDs and refresh tokens - **no personal data** (name, email, picture)
- **On-Demand User Info**: Fetches fresh user information from OAuth providers when needed
- **Multi-Provider Support**: Users can link multiple OAuth providers to a single account

## Architecture

authd uses **hexagonal architecture** (ports and adapters pattern) to separate business logic from infrastructure concerns:

```
authd/
├── core/                    # Mandatory: Business logic (provider-agnostic)
│   ├── models.go           # Domain models (User, RefreshToken, Provider enum)
│   ├── repository.go       # Storage interface
│   ├── provider.go         # OAuth provider interface
│   ├── auth_service.go     # Core authentication logic
│   ├── jwt.go              # JWT token generation/validation
│   ├── config.go           # Configuration abstraction
│   └── providers/          # OAuth provider implementations
│       ├── google.go       # Google OAuth
│       ├── yandex.go       # Yandex OAuth
│       └── mock.go         # Testing mock
│
├── storage/                # Optional: Database adapters
│   ├── ydb.go             # YDB (Yandex Database) - production
│   ├── sqlite.go          # SQLite - development/testing
│   └── mock.go            # In-memory - unit tests
│
├── runtime/                # Optional: Deployment adapters (TODO)
│   ├── serverless/        # Serverless functions (primary target)
│   ├── docker/            # Docker container
│   └── standalone/        # Standalone binary
│
└── schema/                 # Database schemas
    ├── ydb/               # YDB migrations
    └── sqlite/            # SQLite schema
```

This architecture allows you to:
- Use the same business logic across different databases
- Deploy to different runtimes without code changes
- Test with lightweight in-memory implementations
- Easily add new OAuth providers or storage backends

## Tech Stack

- **Language**: Go 1.21+
- **Core Dependencies**:
  - `github.com/golang-jwt/jwt/v5` - JWT tokens
  - `github.com/google/uuid` - UUID generation
- **OAuth Providers** (implemented):
  - Google OAuth 2.0
  - Yandex OAuth
- **OAuth Providers** (planned):
  - Apple Sign In
  - GitHub
  - VK (VKontakte)
- **Databases** (implemented):
  - **YDB** (Yandex Database) - serverless NoSQL, production-ready
  - **SQLite** (`modernc.org/sqlite`) - local development, pure Go
- **Databases** (planned):
  - PostgreSQL
  - MySQL
- **Runtimes** (planned):
  - Yandex Cloud Serverless Functions (primary target)
  - Docker containers
  - Standalone HTTP server

## Data Model

authd stores **minimal data** for privacy and compliance:

**Users Table:**
- `id` - Internal user UUID
- `created_at`, `updated_at` - Timestamps
- `google_id`, `google_refresh_token` - Google OAuth data (nullable)
- `yandex_id`, `yandex_refresh_token` - Yandex OAuth data (nullable)

**Refresh Tokens Table:**
- `token` - Refresh token string (primary key)
- `user_id` - Reference to user
- `created_at`, `expires_at` - Token lifecycle

**No PII stored**: User information (name, email, profile picture) is fetched on-demand from OAuth providers using stored refresh tokens.

## Authentication Flow

### Flow 1: Login (OAuth)

```
┌────────┐          ┌──────────┐          ┌───────────────┐          ┌──────────┐
│ Client │          │  OAuth   │          │     authd     │          │ Database │
│        │          │ Provider │          │               │          │          │
└───┬────┘          └────┬─────┘          └───────┬───────┘          └────┬─────┘
    │                    │                        │                       │
    │  1. Redirect to    │                        │                       │
    │  OAuth Provider    │                        │                       │
    ├───────────────────>│                        │                       │
    │                    │                        │                       │
    │  2. User grants    │                        │                       │
    │     permission     │                        │                       │
    │<───────────────────┤                        │                       │
    │                    │                        │                       │
    │  3. Authorization  │                        │                       │
    │     code (in URL)  │                        │                       │
    │<───────────────────┤                        │                       │
    │                    │                        │                       │
    │  4. POST /login                             │                       │
    │     {provider, code}                        │                       │
    ├────────────────────────────────────────────>│                       │
    │                    │                        │                       │
    │                    │  5. Exchange code      │                       │
    │                    │     for tokens         │                       │
    │                    │<───────────────────────┤                       │
    │                    │                        │                       │
    │                    │  6. OAuth tokens       │                       │
    │                    │     (access + refresh) │                       │
    │                    ├───────────────────────>│                       │
    │                    │                        │                       │
    │                    │  7. Get user info      │                       │
    │                    │<───────────────────────┤                       │
    │                    │                        │                       │
    │                    │  8. User info          │                       │
    │                    │     (provider_id, etc) │                       │
    │                    ├───────────────────────>│                       │
    │                    │                        │                       │
    │                    │                        │  9. FindByProviderID  │
    │                    │                        ├──────────────────────>│
    │                    │                        │                       │
    │                    │                        │ 10. User or NOT FOUND │
    │                    │                        │<──────────────────────┤
    │                    │                        │                       │
    │                    │                        │ 11. If not found:     │
    │                    │                        │     CreateUser()      │
    │                    │                        ├──────────────────────>│
    │                    │                        │<──────────────────────┤
    │                    │                        │                       │
    │                    │                        │ 12. Update provider   │
    │                    │                        │     refresh token     │
    │                    │                        ├──────────────────────>│
    │                    │                        │<──────────────────────┤
    │                    │                        │                       │
    │                    │                        │ 13. Create authd      │
    │                    │                        │     refresh token     │
    │                    │                        ├──────────────────────>│
    │                    │                        │<──────────────────────┤
    │                    │                        │                       │
    │                    │                        │ 14. Generate JWT      │
    │                    │                        │     (with user_id)    │
    │                    │                        │                       │
    │  15. Response:                              │                       │
    │      {access_token: "JWT",                  │                       │
    │       refresh_token: "UUID",                │                       │
    │       user_id: "UUID"}                      │                       │
    │<────────────────────────────────────────────┤                       │
    │                    │                        │                       │
    │ 16. Store tokens   │                        │                       │
    │                    │                        │                       │
```

**Key Steps:**
- Client receives authorization code from OAuth provider (Google, Yandex, etc.)
- authd exchanges code for OAuth access + refresh tokens using client_secret
- authd fetches user info from OAuth provider
- authd finds or creates user in database using provider_id
- authd stores OAuth refresh token for future user info requests
- authd creates its own refresh token for session management
- authd generates JWT access token containing user_id
- Client receives both tokens for API access and token refresh

### Flow 2: Access Token Refresh

```
┌────────┐                              ┌───────────────┐          ┌──────────┐
│ Client │                              │     authd     │          │ Database │
└───┬────┘                              └───────┬───────┘          └────┬─────┘
    │                                           │                       │
    │  1. POST /refresh                         │                       │
    │     {refresh_token: "UUID"}               │                       │
    ├──────────────────────────────────────────>│                       │
    │                                           │                       │
    │                                           │  2. FindRefreshToken  │
    │                                           ├──────────────────────>│
    │                                           │                       │
    │                                           │  3. Token + user_id   │
    │                                           │<──────────────────────┤
    │                                           │                       │
    │                                           │  4. Check expiration  │
    │                                           │                       │
    │  5. Error: 401 (if expired/not found)     │                       │
    │<──────────────────────────────────────────┤                       │
    │                                           │                       │
    │                                           │  6. Generate new JWT  │
    │                                           │     (with user_id)    │
    │                                           │                       │
    │  7. Response:                             │                       │
    │     {access_token: "new JWT"}             │                       │
    │<──────────────────────────────────────────┤                       │
    │                                           │                       │
    │  8. Update stored access token            │                       │
    │                                           │                       │
```

**Key Steps:**
- Client sends stored refresh token to get new access token
- authd validates refresh token exists and hasn't expired
- authd generates new JWT access token with same user_id
- Refresh token remains valid and unchanged (until it expires)
- If refresh token expired, client must re-authenticate via OAuth

### Flow 3: Get User Info (On-Demand)

```
┌────────┐          ┌──────────┐          ┌───────────────┐          ┌──────────┐
│ Client │          │  OAuth   │          │     authd     │          │ Database │
│        │          │ Provider │          │               │          │          │
└───┬────┘          └────┬─────┘          └───────┬───────┘          └────┬─────┘
    │                    │                        │                       │
    │  1. GET /userinfo                           │                       │
    │     Authorization: Bearer <JWT>             │                       │
    ├────────────────────────────────────────────>│                       │
    │                    │                        │                       │
    │                    │                        │  2. Validate JWT      │
    │                    │                        │     Extract user_id   │
    │                    │                        │                       │
    │  3. Error: 401 (if JWT invalid/expired)     │                       │
    │<────────────────────────────────────────────┤                       │
    │                    │                        │                       │
    │                    │                        │  4. FindByID(user_id) │
    │                    │                        ├──────────────────────>│
    │                    │                        │                       │
    │                    │                        │  5. User with OAuth   │
    │                    │                        │     refresh tokens    │
    │                    │                        │<──────────────────────┤
    │                    │                        │                       │
    │                    │  6. Refresh OAuth      │                       │
    │                    │     access token       │                       │
    │                    │<───────────────────────┤                       │
    │                    │                        │                       │
    │                    │  7. New OAuth access   │                       │
    │                    │     token              │                       │
    │                    ├───────────────────────>│                       │
    │                    │                        │                       │
    │                    │                        │  8. Update provider   │
    │                    │                        │     refresh token     │
    │                    │                        │     (if changed)      │
    │                    │                        ├──────────────────────>│
    │                    │                        │<──────────────────────┤
    │                    │                        │                       │
    │                    │  9. Get user info      │                       │
    │                    │<───────────────────────┤                       │
    │                    │                        │                       │
    │                    │ 10. Fresh user info    │                       │
    │                    │     {email, name,      │                       │
    │                    │      picture}          │                       │
    │                    ├───────────────────────>│                       │
    │                    │                        │                       │
    │ 11. Response:                               │                       │
    │     {email, name, picture}                  │                       │
    │<────────────────────────────────────────────┤                       │
    │                    │                        │                       │
```

**Key Steps:**
- Client sends JWT access token in Authorization header
- authd validates JWT and extracts user_id
- authd retrieves user's stored OAuth refresh token from database
- authd uses OAuth refresh token to get fresh OAuth access token from provider
- authd fetches current user info from OAuth provider (NOT from database)
- User info is always fresh and reflects current provider data
- **No PII stored** - email, name, picture come directly from OAuth provider

## Configuration

All configuration is runtime-independent and passed through the `Config` struct:

```go
type Config struct {
    // JWT
    JWTSecret            string
    AccessTokenDuration  int    // seconds (default: 1800 = 30 min)
    RefreshTokenDuration int    // seconds (default: 2592000 = 30 days)

    // Google OAuth
    GoogleClientID     string
    GoogleClientSecret string
    GoogleRedirectURI  string

    // Yandex OAuth
    YandexClientID     string
    YandexClientSecret string
    YandexRedirectURI  string
}
```

Runtime implementations (serverless, Docker, etc.) load this config from their respective sources (environment variables, secret managers, config files).

## Why Hexagonal Architecture?

1. **Flexibility**: Switch databases or deployment targets without changing business logic
2. **Testability**: Easy to test with in-memory mocks
3. **Maintainability**: Clear separation of concerns
4. **Extensibility**: Add new providers or storage backends by implementing interfaces
5. **Portability**: Same core code runs on serverless functions, containers, or standalone servers

## Development Status

- [x] Core business logic
- [x] Google OAuth provider
- [x] Yandex OAuth provider
- [x] YDB storage implementation
- [x] SQLite storage implementation
- [x] Mock implementations for testing
- [ ] Serverless runtime (Yandex Cloud Functions)
- [ ] Docker runtime
- [ ] Standalone HTTP server runtime
- [ ] Apple Sign In provider
- [ ] PostgreSQL storage
- [ ] API documentation
- [ ] Integration tests
- [ ] Deployment guides

## Deployment

### Recommended: Serverless (Yandex Cloud)

authd is designed for serverless-first deployment using:
- **Yandex Cloud Serverless Functions** - for compute
- **YDB (Yandex Database)** - for storage
- **Yandex Lockbox** - for secrets management

This provides:
- Zero maintenance
- Auto-scaling
- Pay-per-use pricing
- High availability out of the box

Deployment guides coming soon.

### Alternative: Docker / Standalone

You can also deploy authd as a traditional service using Docker or as a standalone HTTP server with SQLite or PostgreSQL. These runtimes are planned but not yet implemented.

## Contributing

Contributions are welcome! Especially for:
- New OAuth providers (Apple, GitHub, VK, etc.)
- New storage backends (PostgreSQL, MySQL)
- Runtime implementations (serverless, Docker, standalone)
- Tests and documentation

## License

[To be determined]
