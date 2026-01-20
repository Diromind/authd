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

const (
	YandexOAuthBaseURL    = "https://oauth.yandex.ru"
	YandexUserInfoBaseURL = "https://login.yandex.ru"
	YandexAvatarBaseURL   = "https://avatars.yandex.net/get-yapic"
	YandexAvatarSize      = "islands-200"
)

type YandexProvider struct {
	clientID     string
	clientSecret string
	redirectURI  string
	httpClient   *http.Client
}

func NewYandexProvider(config *core.Config) *YandexProvider {
	return &YandexProvider{
		clientID:     config.YandexClientID,
		clientSecret: config.YandexClientSecret,
		redirectURI:  config.YandexRedirectURI,
		httpClient:   &http.Client{Timeout: 10 * time.Second},
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
	data.Set("client_id", y.clientID)
	data.Set("client_secret", y.clientSecret)

	tokenURL := YandexOAuthBaseURL + "/token"
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
	userinfoURL := YandexUserInfoBaseURL + "/info?format=json"

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
		pictureURL = fmt.Sprintf("%s/%s/%s", YandexAvatarBaseURL, userInfo.DefaultAvatarID, YandexAvatarSize)
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
	data.Set("client_id", y.clientID)
	data.Set("client_secret", y.clientSecret)

	tokenURL := YandexOAuthBaseURL + "/token"
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
