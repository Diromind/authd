package main

import (
	"log"
	"net/http"
	"os"
	"strings"

	"authd/core"
	"authd/core/providers"
	"authd/storage"

	"gopkg.in/yaml.v3"
)

type AppConfig struct {
	Core   *core.Config            `yaml:",inline"`
	Google *providers.GoogleConfig `yaml:"google,omitempty"`
	Yandex *providers.YandexConfig `yaml:"yandex,omitempty"`

	DB   DBConfig   `yaml:"db"`
	Port string     `yaml:"port"`
}

type DBConfig struct {
	Type       string `yaml:"type"`
	SQLitePath string `yaml:"sqlite_path"`
}

func main() {
	configPath := getEnv("CONFIG_PATH", "config.yaml")
	appConfig := loadConfigFromYAML(configPath)

	repo := initRepository(appConfig.DB)
	providerMap := initProviders(appConfig)
	crypto, err := core.NewCryptoService(appConfig.Core.Crypto.EncryptionKey)
	if err != nil {
		log.Fatalf("Failed to initialize crypto service: %v", err)
	}

	authService := core.NewAuthService(repo, appConfig.Core, providerMap, crypto)
	server := core.NewServer(authService, appConfig.Core)

	http.HandleFunc("/login", server.HandleLogin)
	http.HandleFunc("/refresh", server.HandleRefresh)
	http.HandleFunc("/logout", server.HandleLogout)
	http.HandleFunc("/logout-all", server.HandleLogoutAll)
	http.HandleFunc("/userinfo", server.HandleUserInfo)
	http.HandleFunc("/health", server.HandleHealth)

	log.Printf("Starting authd server on port %s", appConfig.Port)
	log.Printf("Configured providers: %v", getConfiguredProviders(providerMap))

	if err := http.ListenAndServe(":"+appConfig.Port, nil); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}

func loadConfigFromYAML(path string) *AppConfig {
	data, err := os.ReadFile(path)
	if err != nil {
		log.Fatalf("Failed to read config file %s: %v", path, err)
	}

	var config AppConfig
	if err := yaml.Unmarshal(data, &config); err != nil {
		log.Fatalf("Failed to parse config file: %v", err)
	}

	return &config
}

func initRepository(dbConfig DBConfig) core.Repository {
	switch strings.ToLower(dbConfig.Type) {
	case "sqlite":
		repo, err := storage.NewSQLiteRepository(dbConfig.SQLitePath)
		if err != nil {
			log.Fatalf("Failed to initialize SQLite repository: %v", err)
		}
		log.Printf("Using SQLite database: %s", dbConfig.SQLitePath)
		return repo

	case "mock":
		log.Println("Using mock repository (in-memory)")
		return storage.NewMockRepository()

	default:
		log.Fatalf("Unsupported DB type: %s (supported: sqlite, mock)", dbConfig.Type)
		return nil
	}
}

func initProviders(cfg *AppConfig) map[core.Provider]core.AuthProvider {
	providerMap := make(map[core.Provider]core.AuthProvider)

	if cfg.Google != nil {
		providerMap[core.ProviderGoogle] = providers.NewGoogleProvider(cfg.Google)
		log.Println("Google OAuth provider initialized")
	}

	if cfg.Yandex != nil {
		providerMap[core.ProviderYandex] = providers.NewYandexProvider(cfg.Yandex)
		log.Println("Yandex OAuth provider initialized")
	}

	return providerMap
}

func getConfiguredProviders(providerMap map[core.Provider]core.AuthProvider) []string {
	providerNames := make([]string, 0, len(providerMap))
	for provider := range providerMap {
		providerNames = append(providerNames, string(provider))
	}
	return providerNames
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}
