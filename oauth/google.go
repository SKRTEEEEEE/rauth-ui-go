package oauth

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"

	"rauth/models"
)

var (
	googleAuthURL  = "https://accounts.google.com/o/oauth2/v2/auth"
	googleTokenURL = "https://oauth2.googleapis.com/token"
	googleUserURL  = "https://www.googleapis.com/oauth2/v2/userinfo"
)

// BuildGoogleAuthURL crea la URL de autorización de Google
func BuildGoogleAuthURL(state, redirectURI string) string {
	params := url.Values{}
	params.Add("client_id", os.Getenv("GOOGLE_CLIENT_ID"))
	params.Add("redirect_uri", redirectURI)
	params.Add("response_type", "code")
	params.Add("scope", "email profile")
	params.Add("state", state)
	params.Add("access_type", "offline")
	params.Add("prompt", "consent")

	return googleAuthURL + "?" + params.Encode()
}

// ExchangeGoogleCode intercambia el código por un access token
func ExchangeGoogleCode(code, redirectURI string) (string, string, error) {
	data := url.Values{}
	data.Set("code", code)
	data.Set("client_id", os.Getenv("GOOGLE_CLIENT_ID"))
	data.Set("client_secret", os.Getenv("GOOGLE_CLIENT_SECRET"))
	data.Set("redirect_uri", redirectURI)
	data.Set("grant_type", "authorization_code")

	resp, err := http.PostForm(googleTokenURL, data)
	if err != nil {
		return "", "", fmt.Errorf("error exchanging code: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK {
		return "", "", fmt.Errorf("google returned status %d: %s", resp.StatusCode, string(body))
	}

	var tokenResp struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		ExpiresIn    int    `json:"expires_in"`
	}

	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return "", "", fmt.Errorf("error parsing token response: %w", err)
	}

	return tokenResp.AccessToken, tokenResp.RefreshToken, nil
}

// GetGoogleUserInfo obtiene información del usuario de Google
func GetGoogleUserInfo(accessToken string) (*models.OAuthUserInfo, error) {
	req, _ := http.NewRequest("GET", googleUserURL, nil)
	req.Header.Set("Authorization", "Bearer "+accessToken)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("error getting user info: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("google returned status %d: %s", resp.StatusCode, string(body))
	}

	var googleUser struct {
		ID            string `json:"id"`
		Email         string `json:"email"`
		Name          string `json:"name"`
		Picture       string `json:"picture"`
		VerifiedEmail bool   `json:"verified_email"`
	}

	if err := json.Unmarshal(body, &googleUser); err != nil {
		return nil, fmt.Errorf("error parsing user info: %w", err)
	}

	return &models.OAuthUserInfo{
		ProviderUserID: googleUser.ID,
		Email:          googleUser.Email,
		Name:           googleUser.Name,
		AvatarURL:      googleUser.Picture,
		EmailVerified:  googleUser.VerifiedEmail,
	}, nil
}
