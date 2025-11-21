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

const facebookUserAgent = "rauth-backend/1.0"

var (
	facebookAuthURL    = "https://www.facebook.com/v18.0/dialog/oauth"
	facebookTokenURL   = "https://graph.facebook.com/v18.0/oauth/access_token"
	facebookUserURL    = "https://graph.facebook.com/v18.0/me"
	facebookHTTPClient = &http.Client{Timeout: 10 * time.Second}
)

type facebookProvider struct{}

// NewFacebookProvider retorna la implementación concreta del proveedor de Facebook.
func NewFacebookProvider() OAuthProvider {
	return &facebookProvider{}
}

// BuildFacebookAuthURL crea la URL de autorización de Facebook
func BuildFacebookAuthURL(state, redirectURI string) string {
	params := url.Values{}
	params.Add("client_id", os.Getenv("FACEBOOK_APP_ID"))
	params.Add("redirect_uri", redirectURI)
	params.Add("scope", "email,public_profile")
	params.Add("state", state)

	return facebookAuthURL + "?" + params.Encode()
}

// ExchangeFacebookCode intercambia el código por un access token
func ExchangeFacebookCode(code, redirectURI string) (string, string, error) {
	params := url.Values{}
	params.Add("client_id", os.Getenv("FACEBOOK_APP_ID"))
	params.Add("client_secret", os.Getenv("FACEBOOK_APP_SECRET"))
	params.Add("redirect_uri", redirectURI)
	params.Add("code", code)

	req, err := http.NewRequest("GET", facebookTokenURL+"?"+params.Encode(), nil)
	if err != nil {
		return "", "", fmt.Errorf("error creating request: %w", err)
	}
	req.Header.Set("User-Agent", facebookUserAgent)

	resp, err := facebookHTTPClient.Do(req)
	if err != nil {
		return "", "", fmt.Errorf("error exchanging code: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK {
		return "", "", fmt.Errorf("facebook returned status %d: %s", resp.StatusCode, string(body))
	}

	var tokenResp struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
		ExpiresIn   int    `json:"expires_in"`
	}

	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return "", "", fmt.Errorf("error parsing token response: %w", err)
	}

	// Facebook doesn't return refresh tokens in standard OAuth flow
	return tokenResp.AccessToken, "", nil
}

// GetFacebookUserInfo obtiene información del usuario de Facebook
func GetFacebookUserInfo(accessToken string) (*models.OAuthUserInfo, error) {
	params := url.Values{}
	params.Add("fields", "id,email,name,picture")
	params.Add("access_token", accessToken)

	req, err := http.NewRequest("GET", facebookUserURL+"?"+params.Encode(), nil)
	if err != nil {
		return nil, fmt.Errorf("error creating request: %w", err)
	}
	req.Header.Set("User-Agent", facebookUserAgent)

	resp, err := facebookHTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("error getting user info: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("facebook returned status %d: %s", resp.StatusCode, string(body))
	}

	var fbUser struct {
		ID      string `json:"id"`
		Email   string `json:"email"`
		Name    string `json:"name"`
		Picture struct {
			Data struct {
				URL string `json:"url"`
			} `json:"data"`
		} `json:"picture"`
	}

	if err := json.Unmarshal(body, &fbUser); err != nil {
		return nil, fmt.Errorf("error parsing user info: %w", err)
	}

	return &models.OAuthUserInfo{
		ProviderUserID: fbUser.ID,
		Email:          fbUser.Email,
		Name:           fbUser.Name,
		AvatarURL:      fbUser.Picture.Data.URL,
		EmailVerified:  true, // Facebook verifies emails
	}, nil
}

func (f *facebookProvider) BuildAuthURL(state, redirectURI string) string {
	return BuildFacebookAuthURL(state, redirectURI)
}

func (f *facebookProvider) ExchangeCode(code, redirectURI string) (string, string, error) {
	return ExchangeFacebookCode(code, redirectURI)
}

func (f *facebookProvider) GetUserInfo(accessToken string) (*models.OAuthUserInfo, error) {
	return GetFacebookUserInfo(accessToken)
}

func init() {
	RegisterProvider(models.ProviderFacebook, NewFacebookProvider())
}
