package oauth

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"time"

	"rauth/models"
)

const githubUserAgent = "rauth-backend/1.0"

var (
	githubAuthURL    = "https://github.com/login/oauth/authorize"
	githubTokenURL   = "https://github.com/login/oauth/access_token"
	githubUserURL    = "https://api.github.com/user"
	githubHTTPClient = &http.Client{Timeout: 10 * time.Second}
)

// BuildGitHubAuthURL crea la URL de autorización de GitHub
func BuildGitHubAuthURL(state, redirectURI string) string {
	params := url.Values{}
	params.Add("client_id", os.Getenv("GITHUB_CLIENT_ID"))
	params.Add("redirect_uri", redirectURI)
	params.Add("scope", "user:email")
	params.Add("state", state)

	return githubAuthURL + "?" + params.Encode()
}

// ExchangeGitHubCode intercambia el código por un access token
func ExchangeGitHubCode(code, redirectURI string) (string, string, error) {
	data := url.Values{}
	data.Set("code", code)
	data.Set("client_id", os.Getenv("GITHUB_CLIENT_ID"))
	data.Set("client_secret", os.Getenv("GITHUB_CLIENT_SECRET"))
	data.Set("redirect_uri", redirectURI)

	req, err := http.NewRequest("POST", githubTokenURL, nil)
	if err != nil {
		return "", "", fmt.Errorf("error creating request: %w", err)
	}
	req.URL.RawQuery = data.Encode()
	req.Header.Set("Accept", "application/json")

	req.Header.Set("User-Agent", githubUserAgent)

	resp, err := githubHTTPClient.Do(req)
	if err != nil {
		return "", "", fmt.Errorf("error exchanging code: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK {
		return "", "", fmt.Errorf("github returned status %d: %s", resp.StatusCode, string(body))
	}

	var tokenResp struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		TokenType    string `json:"token_type"`
		Scope        string `json:"scope"`
	}

	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return "", "", fmt.Errorf("error parsing token response: %w", err)
	}

	return tokenResp.AccessToken, tokenResp.RefreshToken, nil
}

// GetGitHubUserInfo obtiene información del usuario de GitHub
func GetGitHubUserInfo(accessToken string) (*models.OAuthUserInfo, error) {
	req, err := http.NewRequest("GET", githubUserURL, nil)
	if err != nil {
		return nil, fmt.Errorf("error creating request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)

	req.Header.Set("User-Agent", githubUserAgent)

	resp, err := githubHTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("error getting user info: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("github returned status %d: %s", resp.StatusCode, string(body))
	}

	var githubUser struct {
		ID        int64  `json:"id"`
		Email     string `json:"email"`
		Name      string `json:"name"`
		AvatarURL string `json:"avatar_url"`
	}

	if err := json.Unmarshal(body, &githubUser); err != nil {
		return nil, fmt.Errorf("error parsing user info: %w", err)
	}

	return &models.OAuthUserInfo{
		ProviderUserID: fmt.Sprintf("%d", githubUser.ID),
		Email:          githubUser.Email,
		Name:           githubUser.Name,
		AvatarURL:      githubUser.AvatarURL,
		EmailVerified:  true, // GitHub verifies emails
	}, nil
}
