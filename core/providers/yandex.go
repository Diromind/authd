package providers

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"authd/core"
)

type YandexConfig struct {
	ClientID        string `yaml:"client_id" json:"client_id"`
	ClientSecret    string `yaml:"client_secret" json:"client_secret"`
	RedirectURI     string `yaml:"redirect_uri" json:"redirect_uri"`
	OAuthBaseURL    string `yaml:"oauth_base_url" json:"oauth_base_url"`
	UserInfoBaseURL string `yaml:"userinfo_base_url" json:"userinfo_base_url"`
	AvatarBaseURL   string `yaml:"avatar_base_url" json:"avatar_base_url"`
	AvatarSize      string `yaml:"avatar_size" json:"avatar_size"`
}

type YandexProvider struct {
	config     *YandexConfig
	httpClient *http.Client
}

func NewYandexProvider(config *YandexConfig) *YandexProvider {
	return &YandexProvider{
		config:     config,
		httpClient: &http.Client{Timeout: 10 * time.Second},
	}
}

type yandexTokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int    `json:"expires_in"`
	TokenType    string `json:"token_type"`
}

type yandexUserInfo struct {
	ID              string `json:"id"`
	DisplayName     string `json:"display_name"`
	DefaultEmail    string `json:"default_email"`
	DefaultAvatarID string `json:"default_avatar_id"`
}

func (y *YandexProvider) ExchangeCode(ctx context.Context, code string) (*core.OAuthTokens, error) {
	data := url.Values{}
	data.Set("grant_type", "authorization_code")
	data.Set("code", code)
	data.Set("client_id", y.config.ClientID)
	data.Set("client_secret", y.config.ClientSecret)

	tokenURL := y.config.OAuthBaseURL + "/token"
	req, err := http.NewRequestWithContext(
		ctx,
		"POST",
		tokenURL,
		strings.NewReader(data.Encode()),
	)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", core.ErrProviderTokenExchange, err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := y.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", core.ErrProviderTokenExchange, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("%w: status %d: %s", core.ErrProviderTokenExchange, resp.StatusCode, string(body))
	}

	var tokenResp yandexTokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return nil, fmt.Errorf("%w: %v", core.ErrProviderTokenExchange, err)
	}

	return &core.OAuthTokens{
		AccessToken:  tokenResp.AccessToken,
		RefreshToken: tokenResp.RefreshToken,
		ExpiresIn:    tokenResp.ExpiresIn,
	}, nil
}

func (y *YandexProvider) GetUserInfo(ctx context.Context, accessToken string) (*core.UserInfo, error) {
	userinfoURL := y.config.UserInfoBaseURL + "/info?format=json"

	req, err := http.NewRequestWithContext(ctx, "GET", userinfoURL, nil)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", core.ErrProviderUserInfo, err)
	}

	req.Header.Set("Authorization", "OAuth "+accessToken)

	resp, err := y.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", core.ErrProviderUserInfo, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("%w: status %d: %s", core.ErrProviderUserInfo, resp.StatusCode, string(body))
	}

	var userInfo yandexUserInfo
	if err := json.NewDecoder(resp.Body).Decode(&userInfo); err != nil {
		return nil, fmt.Errorf("%w: %v", core.ErrProviderUserInfo, err)
	}

	pictureURL := ""
	if userInfo.DefaultAvatarID != "" {
		pictureURL = fmt.Sprintf("%s/%s/%s", y.config.AvatarBaseURL, userInfo.DefaultAvatarID, y.config.AvatarSize)
	}

	return &core.UserInfo{
		ProviderUserID: userInfo.ID,
		Email:          userInfo.DefaultEmail,
		Name:           userInfo.DisplayName,
		Picture:        pictureURL,
	}, nil
}

func (y *YandexProvider) RefreshAccessToken(ctx context.Context, refreshToken string) (*core.OAuthTokens, error) {
	data := url.Values{}
	data.Set("grant_type", "refresh_token")
	data.Set("refresh_token", refreshToken)
	data.Set("client_id", y.config.ClientID)
	data.Set("client_secret", y.config.ClientSecret)

	tokenURL := y.config.OAuthBaseURL + "/token"
	req, err := http.NewRequestWithContext(
		ctx,
		"POST",
		tokenURL,
		strings.NewReader(data.Encode()),
	)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", core.ErrProviderRefreshToken, err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := y.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", core.ErrProviderRefreshToken, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("%w: status %d: %s", core.ErrProviderRefreshToken, resp.StatusCode, string(body))
	}

	var tokenResp yandexTokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return nil, fmt.Errorf("%w: %v", core.ErrProviderRefreshToken, err)
	}

	return &core.OAuthTokens{
		AccessToken:  tokenResp.AccessToken,
		RefreshToken: tokenResp.RefreshToken,
		ExpiresIn:    tokenResp.ExpiresIn,
	}, nil
}

func (y *YandexProvider) Provider() core.Provider {
	return core.ProviderYandex
}
