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

type GoogleConfig struct {
	ClientID        string `yaml:"client_id"`
	ClientSecret    string `yaml:"client_secret"`
	RedirectURI     string `yaml:"redirect_uri"`
	OAuthBaseURL    string `yaml:"oauth_base_url"`
	UserInfoBaseURL string `yaml:"userinfo_base_url"`
}

type GoogleProvider struct {
	config     *GoogleConfig
	httpClient *http.Client
}

func NewGoogleProvider(config *GoogleConfig) *GoogleProvider {
	return &GoogleProvider{
		config:     config,
		httpClient: &http.Client{Timeout: 10 * time.Second},
	}
}

type googleTokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int    `json:"expires_in"`
	TokenType    string `json:"token_type"`
}

type googleUserInfo struct {
	ID            string `json:"id"`
	Email         string `json:"email"`
	VerifiedEmail bool   `json:"verified_email"`
	Name          string `json:"name"`
	Picture       string `json:"picture"`
}

func (g *GoogleProvider) ExchangeCode(ctx context.Context, code string) (*core.OAuthTokens, error) {
	data := url.Values{}
	data.Set("grant_type", "authorization_code")
	data.Set("code", code)
	data.Set("client_id", g.config.ClientID)
	data.Set("client_secret", g.config.ClientSecret)
	data.Set("redirect_uri", g.config.RedirectURI)

	tokenURL := g.config.OAuthBaseURL + "/token"
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

	resp, err := g.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", core.ErrProviderTokenExchange, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("%w: status %d: %s", core.ErrProviderTokenExchange, resp.StatusCode, string(body))
	}

	var tokenResp googleTokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return nil, fmt.Errorf("%w: %v", core.ErrProviderTokenExchange, err)
	}

	return &core.OAuthTokens{
		AccessToken:  tokenResp.AccessToken,
		RefreshToken: tokenResp.RefreshToken,
		ExpiresIn:    tokenResp.ExpiresIn,
	}, nil
}

func (g *GoogleProvider) GetUserInfo(ctx context.Context, accessToken string) (*core.UserInfo, error) {
	userinfoURL := g.config.UserInfoBaseURL + "/oauth2/v2/userinfo"

	req, err := http.NewRequestWithContext(ctx, "GET", userinfoURL, nil)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", core.ErrProviderUserInfo, err)
	}

	req.Header.Set("Authorization", "Bearer "+accessToken)

	resp, err := g.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", core.ErrProviderUserInfo, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("%w: status %d: %s", core.ErrProviderUserInfo, resp.StatusCode, string(body))
	}

	var userInfo googleUserInfo
	if err := json.NewDecoder(resp.Body).Decode(&userInfo); err != nil {
		return nil, fmt.Errorf("%w: %v", core.ErrProviderUserInfo, err)
	}

	return &core.UserInfo{
		ProviderUserID: userInfo.ID,
		Email:          userInfo.Email,
		Name:           userInfo.Name,
		Picture:        userInfo.Picture,
	}, nil
}

func (g *GoogleProvider) RefreshAccessToken(ctx context.Context, refreshToken string) (*core.OAuthTokens, error) {
	data := url.Values{}
	data.Set("grant_type", "refresh_token")
	data.Set("refresh_token", refreshToken)
	data.Set("client_id", g.config.ClientID)
	data.Set("client_secret", g.config.ClientSecret)

	tokenURL := g.config.OAuthBaseURL + "/token"
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

	resp, err := g.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", core.ErrProviderRefreshToken, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("%w: status %d: %s", core.ErrProviderRefreshToken, resp.StatusCode, string(body))
	}

	var tokenResp googleTokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return nil, fmt.Errorf("%w: %v", core.ErrProviderRefreshToken, err)
	}

	return &core.OAuthTokens{
		AccessToken:  tokenResp.AccessToken,
		RefreshToken: tokenResp.RefreshToken,
		ExpiresIn:    tokenResp.ExpiresIn,
	}, nil
}

func (g *GoogleProvider) Provider() core.Provider {
	return core.ProviderGoogle
}
