package core

type Config struct {
	JWT    JWTConfig    `yaml:"jwt"`
	Crypto CryptoConfig `yaml:"crypto"`
}

type JWTConfig struct {
	Secret               string `yaml:"secret"`
	AccessTokenDuration  int    `yaml:"access_token_duration"`
	RefreshTokenDuration int    `yaml:"refresh_token_duration"`
}

type CryptoConfig struct {
	EncryptionKey string `yaml:"encryption_key"`
}
