package oauth

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"

	"rauth/models"
)

func TestBuildFacebookAuthURL(t *testing.T) {
	// Setup environment
	os.Setenv("FACEBOOK_APP_ID", "test-facebook-app-id")
	defer os.Unsetenv("FACEBOOK_APP_ID")

	state := "test-state-123"
	redirectURI := "http://localhost:8080/api/v1/oauth/callback/facebook"

	authURL := BuildFacebookAuthURL(state, redirectURI)

	// Parse URL
	parsedURL, err := url.Parse(authURL)
	if err != nil {
		t.Fatalf("Failed to parse auth URL: %v", err)
	}

	// Verify base URL
	if parsedURL.Scheme != "https" {
		t.Errorf("Expected https scheme, got %s", parsedURL.Scheme)
	}
	if parsedURL.Host != "www.facebook.com" {
		t.Errorf("Expected www.facebook.com host, got %s", parsedURL.Host)
	}
	if !strings.Contains(parsedURL.Path, "/dialog/oauth") {
		t.Errorf("Expected /dialog/oauth path, got %s", parsedURL.Path)
	}

	// Verify query parameters
	query := parsedURL.Query()

	if query.Get("client_id") != "test-facebook-app-id" {
		t.Errorf("Expected client_id 'test-facebook-app-id', got '%s'", query.Get("client_id"))
	}
	if query.Get("redirect_uri") != redirectURI {
		t.Errorf("Expected redirect_uri '%s', got '%s'", redirectURI, query.Get("redirect_uri"))
	}
	if query.Get("scope") != "email,public_profile" {
		t.Errorf("Expected scope 'email,public_profile', got '%s'", query.Get("scope"))
	}
	if query.Get("state") != state {
		t.Errorf("Expected state '%s', got '%s'", state, query.Get("state"))
	}
}

func TestBuildFacebookAuthURL_MissingAppID(t *testing.T) {
	// Unset app ID
	os.Unsetenv("FACEBOOK_APP_ID")

	state := "test-state"
	redirectURI := "http://localhost:8080/callback"

	authURL := BuildFacebookAuthURL(state, redirectURI)

	// Should still build URL but with empty client_id
	if !strings.Contains(authURL, "client_id=") {
		t.Error("URL should contain client_id parameter")
	}

	parsedURL, _ := url.Parse(authURL)
	if parsedURL.Query().Get("client_id") != "" {
		t.Error("Expected empty client_id when FACEBOOK_APP_ID is not set")
	}
}

func TestExchangeFacebookCode_Success(t *testing.T) {
	// Create mock server
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify request method - Facebook uses GET for token exchange
		if r.Method != "GET" {
			t.Errorf("Expected GET request, got %s", r.Method)
		}

		// Verify query parameters
		query := r.URL.Query()
		if query.Get("code") != "test-code" {
			t.Errorf("Expected code 'test-code', got '%s'", query.Get("code"))
		}

		// Return success response
		response := map[string]interface{}{
			"access_token": "test-access-token",
			"token_type":   "bearer",
			"expires_in":   5183999,
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(response)
	}))
	defer mockServer.Close()

	// Override Facebook token URL for testing
	originalTokenURL := facebookTokenURL
	facebookTokenURL = mockServer.URL
	defer func() { facebookTokenURL = originalTokenURL }()

	// Setup environment
	os.Setenv("FACEBOOK_APP_ID", "test-app-id")
	os.Setenv("FACEBOOK_APP_SECRET", "test-app-secret")
	defer os.Unsetenv("FACEBOOK_APP_ID")
	defer os.Unsetenv("FACEBOOK_APP_SECRET")

	// Test exchange
	accessToken, refreshToken, err := ExchangeFacebookCode("test-code", "http://localhost:8080/callback")

	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}
	if accessToken != "test-access-token" {
		t.Errorf("Expected access token 'test-access-token', got '%s'", accessToken)
	}
	// Facebook doesn't typically return refresh tokens
	if refreshToken != "" {
		t.Errorf("Expected empty refresh token, got '%s'", refreshToken)
	}
}

func TestExchangeFacebookCode_InvalidCode(t *testing.T) {
	// Create mock server that returns error
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"error": map[string]interface{}{
				"message":    "Invalid verification code format.",
				"type":       "OAuthException",
				"code":       100,
				"error_data": map[string]interface{}{},
			},
		})
	}))
	defer mockServer.Close()

	// Override Facebook token URL for testing
	originalTokenURL := facebookTokenURL
	facebookTokenURL = mockServer.URL
	defer func() { facebookTokenURL = originalTokenURL }()

	// Setup environment
	os.Setenv("FACEBOOK_APP_ID", "test-app-id")
	os.Setenv("FACEBOOK_APP_SECRET", "test-app-secret")
	defer os.Unsetenv("FACEBOOK_APP_ID")
	defer os.Unsetenv("FACEBOOK_APP_SECRET")

	// Test exchange with invalid code
	_, _, err := ExchangeFacebookCode("invalid-code", "http://localhost:8080/callback")

	if err == nil {
		t.Fatal("Expected error for invalid code, got nil")
	}
	if !strings.Contains(err.Error(), "400") {
		t.Errorf("Expected error to contain status 400, got: %v", err)
	}
}

func TestExchangeFacebookCode_InvalidJSON(t *testing.T) {
	// Create mock server that returns invalid JSON
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("invalid json"))
	}))
	defer mockServer.Close()

	// Override Facebook token URL for testing
	originalTokenURL := facebookTokenURL
	facebookTokenURL = mockServer.URL
	defer func() { facebookTokenURL = originalTokenURL }()

	// Setup environment
	os.Setenv("FACEBOOK_APP_ID", "test-app-id")
	os.Setenv("FACEBOOK_APP_SECRET", "test-app-secret")
	defer os.Unsetenv("FACEBOOK_APP_ID")
	defer os.Unsetenv("FACEBOOK_APP_SECRET")

	// Test exchange
	_, _, err := ExchangeFacebookCode("test-code", "http://localhost:8080/callback")

	if err == nil {
		t.Fatal("Expected error for invalid JSON, got nil")
	}
	if !strings.Contains(err.Error(), "parsing token response") {
		t.Errorf("Expected error about parsing token response, got: %v", err)
	}
}

func TestExchangeFacebookCode_SetsUserAgent(t *testing.T) {
	const expectedUserAgent = "rauth-backend/1.0"

	userAgentHeader := ""
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		userAgentHeader = r.Header.Get("User-Agent")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]string{
			"access_token": "ua-access-token",
		})
	}))
	defer mockServer.Close()

	originalTokenURL := facebookTokenURL
	facebookTokenURL = mockServer.URL
	defer func() { facebookTokenURL = originalTokenURL }()

	os.Setenv("FACEBOOK_APP_ID", "test-app-id")
	os.Setenv("FACEBOOK_APP_SECRET", "test-app-secret")
	defer os.Unsetenv("FACEBOOK_APP_ID")
	defer os.Unsetenv("FACEBOOK_APP_SECRET")

	_, _, err := ExchangeFacebookCode("user-agent-code", "http://localhost")
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if userAgentHeader != expectedUserAgent {
		t.Fatalf("Expected User-Agent '%s', got '%s'", expectedUserAgent, userAgentHeader)
	}
}

func TestGetFacebookUserInfo_Success(t *testing.T) {
	// Create mock server
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify request method
		if r.Method != "GET" {
			t.Errorf("Expected GET request, got %s", r.Method)
		}

		// Verify access token in query params (Facebook uses query param for token)
		query := r.URL.Query()
		if query.Get("access_token") != "test-access-token" {
			t.Errorf("Expected access_token 'test-access-token', got '%s'", query.Get("access_token"))
		}

		// Return user info
		userInfo := map[string]interface{}{
			"id":    "12345678901234567",
			"email": "test@facebook.com",
			"name":  "Test User",
			"picture": map[string]interface{}{
				"data": map[string]interface{}{
					"url": "https://platform-lookaside.fbsbx.com/platform/profilepic/1234",
				},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(userInfo)
	}))
	defer mockServer.Close()

	// Override Facebook user URL for testing
	originalUserURL := facebookUserURL
	facebookUserURL = mockServer.URL
	defer func() { facebookUserURL = originalUserURL }()

	// Test get user info
	userInfo, err := GetFacebookUserInfo("test-access-token")

	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}
	if userInfo == nil {
		t.Fatal("Expected user info, got nil")
	}
	if userInfo.ProviderUserID != "12345678901234567" {
		t.Errorf("Expected provider user ID '12345678901234567', got '%s'", userInfo.ProviderUserID)
	}
	if userInfo.Email != "test@facebook.com" {
		t.Errorf("Expected email 'test@facebook.com', got '%s'", userInfo.Email)
	}
	if userInfo.Name != "Test User" {
		t.Errorf("Expected name 'Test User', got '%s'", userInfo.Name)
	}
	if userInfo.AvatarURL != "https://platform-lookaside.fbsbx.com/platform/profilepic/1234" {
		t.Errorf("Expected avatar URL 'https://platform-lookaside.fbsbx.com/platform/profilepic/1234', got '%s'", userInfo.AvatarURL)
	}
	if !userInfo.EmailVerified {
		t.Error("Expected email to be verified for Facebook users")
	}
}

func TestGetFacebookUserInfo_NullEmail(t *testing.T) {
	// Create mock server with null email
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		userInfo := map[string]interface{}{
			"id":      "87654321098765432",
			"email":   nil,
			"name":    "User Without Email",
			"picture": map[string]interface{}{},
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(userInfo)
	}))
	defer mockServer.Close()

	// Override Facebook user URL for testing
	originalUserURL := facebookUserURL
	facebookUserURL = mockServer.URL
	defer func() { facebookUserURL = originalUserURL }()

	// Test get user info
	userInfo, err := GetFacebookUserInfo("test-access-token")

	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}
	if userInfo.Email != "" {
		t.Errorf("Expected empty email for null, got '%s'", userInfo.Email)
	}
}

func TestGetFacebookUserInfo_InvalidToken(t *testing.T) {
	// Create mock server that returns 401
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"error": map[string]interface{}{
				"message":    "Invalid OAuth access token.",
				"type":       "OAuthException",
				"code":       190,
				"fbtrace_id": "ABC123",
			},
		})
	}))
	defer mockServer.Close()

	// Override Facebook user URL for testing
	originalUserURL := facebookUserURL
	facebookUserURL = mockServer.URL
	defer func() { facebookUserURL = originalUserURL }()

	// Test get user info with invalid token
	_, err := GetFacebookUserInfo("invalid-token")

	if err == nil {
		t.Fatal("Expected error for invalid token, got nil")
	}
	if !strings.Contains(err.Error(), "401") {
		t.Errorf("Expected error to contain status 401, got: %v", err)
	}
}

func TestGetFacebookUserInfo_InvalidJSON(t *testing.T) {
	// Create mock server that returns invalid JSON
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("invalid json"))
	}))
	defer mockServer.Close()

	// Override Facebook user URL for testing
	originalUserURL := facebookUserURL
	facebookUserURL = mockServer.URL
	defer func() { facebookUserURL = originalUserURL }()

	// Test get user info
	_, err := GetFacebookUserInfo("test-access-token")

	if err == nil {
		t.Fatal("Expected error for invalid JSON, got nil")
	}
	if !strings.Contains(err.Error(), "parsing user info") {
		t.Errorf("Expected error about parsing user info, got: %v", err)
	}
}

func TestGetFacebookUserInfo_SetsUserAgent(t *testing.T) {
	const expectedUserAgent = "rauth-backend/1.0"

	receivedUserAgent := ""
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedUserAgent = r.Header.Get("User-Agent")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]any{
			"id":      "112233445566778899",
			"email":   "header@test.com",
			"name":    "Header Test",
			"picture": map[string]any{},
		})
	}))
	defer mockServer.Close()

	originalUserURL := facebookUserURL
	facebookUserURL = mockServer.URL
	defer func() { facebookUserURL = originalUserURL }()

	_, err := GetFacebookUserInfo("token-with-user-agent")
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if receivedUserAgent != expectedUserAgent {
		t.Fatalf("Expected User-Agent '%s', got '%s'", expectedUserAgent, receivedUserAgent)
	}
}

func TestGetFacebookUserInfo_EmptyAccessToken(t *testing.T) {
	// Create mock server
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		query := r.URL.Query()
		if query.Get("access_token") != "" {
			t.Errorf("Expected empty access_token, got '%s'", query.Get("access_token"))
		}
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"error": map[string]interface{}{
				"message": "Invalid OAuth access token.",
			},
		})
	}))
	defer mockServer.Close()

	// Override Facebook user URL for testing
	originalUserURL := facebookUserURL
	facebookUserURL = mockServer.URL
	defer func() { facebookUserURL = originalUserURL }()

	// Test with empty access token
	_, err := GetFacebookUserInfo("")

	if err == nil {
		t.Fatal("Expected error for empty access token, got nil")
	}
}

func TestFacebookOAuth_URLConstants(t *testing.T) {
	// Verify constants are defined
	if facebookAuthURL == "" {
		t.Error("facebookAuthURL should be defined")
	}
	if facebookTokenURL == "" {
		t.Error("facebookTokenURL should be defined")
	}
	if facebookUserURL == "" {
		t.Error("facebookUserURL should be defined")
	}

	// Verify expected values
	expectedAuthURL := "https://www.facebook.com/v18.0/dialog/oauth"
	expectedTokenURL := "https://graph.facebook.com/v18.0/oauth/access_token"
	expectedUserURL := "https://graph.facebook.com/v18.0/me"

	if facebookAuthURL != expectedAuthURL {
		t.Errorf("Expected auth URL '%s', got '%s'", expectedAuthURL, facebookAuthURL)
	}
	if facebookTokenURL != expectedTokenURL {
		t.Errorf("Expected token URL '%s', got '%s'", expectedTokenURL, facebookTokenURL)
	}
	if facebookUserURL != expectedUserURL {
		t.Errorf("Expected user URL '%s', got '%s'", expectedUserURL, facebookUserURL)
	}
}

func TestFacebookOAuth_ReturnTypes(t *testing.T) {
	// Test BuildFacebookAuthURL returns a string
	os.Setenv("FACEBOOK_APP_ID", "test-id")
	defer os.Unsetenv("FACEBOOK_APP_ID")

	url := BuildFacebookAuthURL("state", "redirect")
	if url == "" {
		t.Error("BuildFacebookAuthURL should return a non-empty string")
	}

	// Test ExchangeFacebookCode returns correct types
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		response := map[string]interface{}{
			"access_token": "token",
			"token_type":   "bearer",
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
	}))
	defer mockServer.Close()

	originalTokenURL := facebookTokenURL
	facebookTokenURL = mockServer.URL
	defer func() { facebookTokenURL = originalTokenURL }()

	os.Setenv("FACEBOOK_APP_SECRET", "test-secret")
	defer os.Unsetenv("FACEBOOK_APP_SECRET")

	accessToken, refreshToken, err := ExchangeFacebookCode("code", "redirect")
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if accessToken == "" {
		t.Error("Expected non-empty access token")
	}
	// Facebook doesn't return refresh tokens
	_ = refreshToken
}

func TestGetFacebookUserInfo_ReturnsOAuthUserInfo(t *testing.T) {
	// Test that GetFacebookUserInfo returns *models.OAuthUserInfo
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		userInfo := map[string]interface{}{
			"id":      "123456789012345",
			"email":   "test@example.com",
			"name":    "Test",
			"picture": map[string]interface{}{},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(userInfo)
	}))
	defer mockServer.Close()

	originalUserURL := facebookUserURL
	facebookUserURL = mockServer.URL
	defer func() { facebookUserURL = originalUserURL }()

	userInfo, err := GetFacebookUserInfo("token")
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	// Verify it's the correct type
	var _ *models.OAuthUserInfo = userInfo
	if userInfo.ProviderUserID == "" {
		t.Error("Expected non-empty provider user ID")
	}
}

func TestFacebookProvider_Interface(t *testing.T) {
	// Verify facebookProvider implements OAuthProvider
	provider := NewFacebookProvider()
	var _ OAuthProvider = provider

	// Test BuildAuthURL
	os.Setenv("FACEBOOK_APP_ID", "test-app-id")
	defer os.Unsetenv("FACEBOOK_APP_ID")

	authURL := provider.BuildAuthURL("state", "redirect")
	if authURL == "" {
		t.Error("BuildAuthURL should return non-empty URL")
	}
}

func TestFacebookProvider_RegisteredOnInit(t *testing.T) {
	// Verify Facebook provider is registered
	provider, ok := GetProvider(models.ProviderFacebook)
	if !ok {
		t.Error("Facebook provider should be registered")
	}
	if provider == nil {
		t.Error("Facebook provider should not be nil")
	}
}
