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

func TestBuildGoogleAuthURL(t *testing.T) {
	// Setup environment
	os.Setenv("GOOGLE_CLIENT_ID", "test-client-id")
	defer os.Unsetenv("GOOGLE_CLIENT_ID")

	state := "test-state-123"
	redirectURI := "http://localhost:8080/api/v1/oauth/callback/google"

	authURL := BuildGoogleAuthURL(state, redirectURI)

	// Parse URL
	parsedURL, err := url.Parse(authURL)
	if err != nil {
		t.Fatalf("Failed to parse auth URL: %v", err)
	}

	// Verify base URL
	if parsedURL.Scheme != "https" {
		t.Errorf("Expected https scheme, got %s", parsedURL.Scheme)
	}
	if parsedURL.Host != "accounts.google.com" {
		t.Errorf("Expected accounts.google.com host, got %s", parsedURL.Host)
	}
	if parsedURL.Path != "/o/oauth2/v2/auth" {
		t.Errorf("Expected /o/oauth2/v2/auth path, got %s", parsedURL.Path)
	}

	// Verify query parameters
	query := parsedURL.Query()

	if query.Get("client_id") != "test-client-id" {
		t.Errorf("Expected client_id 'test-client-id', got '%s'", query.Get("client_id"))
	}
	if query.Get("redirect_uri") != redirectURI {
		t.Errorf("Expected redirect_uri '%s', got '%s'", redirectURI, query.Get("redirect_uri"))
	}
	if query.Get("response_type") != "code" {
		t.Errorf("Expected response_type 'code', got '%s'", query.Get("response_type"))
	}
	if query.Get("scope") != "email profile" {
		t.Errorf("Expected scope 'email profile', got '%s'", query.Get("scope"))
	}
	if query.Get("state") != state {
		t.Errorf("Expected state '%s', got '%s'", state, query.Get("state"))
	}
	if query.Get("access_type") != "offline" {
		t.Errorf("Expected access_type 'offline', got '%s'", query.Get("access_type"))
	}
	if query.Get("prompt") != "consent" {
		t.Errorf("Expected prompt 'consent', got '%s'", query.Get("prompt"))
	}
}

func TestBuildGoogleAuthURL_MissingClientID(t *testing.T) {
	// Unset client ID
	os.Unsetenv("GOOGLE_CLIENT_ID")

	state := "test-state"
	redirectURI := "http://localhost:8080/callback"

	authURL := BuildGoogleAuthURL(state, redirectURI)

	// Should still build URL but with empty client_id
	if !strings.Contains(authURL, "client_id=") {
		t.Error("URL should contain client_id parameter")
	}

	parsedURL, _ := url.Parse(authURL)
	if parsedURL.Query().Get("client_id") != "" {
		t.Error("Expected empty client_id when GOOGLE_CLIENT_ID is not set")
	}
}

func TestExchangeGoogleCode_Success(t *testing.T) {
	// Create mock server
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify request method
		if r.Method != "POST" {
			t.Errorf("Expected POST request, got %s", r.Method)
		}

		// Verify content type
		contentType := r.Header.Get("Content-Type")
		if !strings.Contains(contentType, "application/x-www-form-urlencoded") {
			t.Errorf("Expected application/x-www-form-urlencoded content type, got %s", contentType)
		}

		// Parse form data
		err := r.ParseForm()
		if err != nil {
			t.Fatalf("Failed to parse form: %v", err)
		}

		// Verify form parameters
		if r.Form.Get("code") != "test-code" {
			t.Errorf("Expected code 'test-code', got '%s'", r.Form.Get("code"))
		}
		if r.Form.Get("grant_type") != "authorization_code" {
			t.Errorf("Expected grant_type 'authorization_code', got '%s'", r.Form.Get("grant_type"))
		}

		// Return success response
		response := map[string]interface{}{
			"access_token":  "test-access-token",
			"refresh_token": "test-refresh-token",
			"expires_in":    3600,
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(response)
	}))
	defer mockServer.Close()

	// Override Google token URL for testing
	originalTokenURL := googleTokenURL
	googleTokenURL = mockServer.URL
	defer func() { googleTokenURL = originalTokenURL }()

	// Setup environment
	os.Setenv("GOOGLE_CLIENT_ID", "test-client-id")
	os.Setenv("GOOGLE_CLIENT_SECRET", "test-client-secret")
	defer os.Unsetenv("GOOGLE_CLIENT_ID")
	defer os.Unsetenv("GOOGLE_CLIENT_SECRET")

	// Test exchange
	accessToken, refreshToken, err := ExchangeGoogleCode("test-code", "http://localhost:8080/callback")

	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}
	if accessToken != "test-access-token" {
		t.Errorf("Expected access token 'test-access-token', got '%s'", accessToken)
	}
	if refreshToken != "test-refresh-token" {
		t.Errorf("Expected refresh token 'test-refresh-token', got '%s'", refreshToken)
	}
}

func TestExchangeGoogleCode_InvalidCode(t *testing.T) {
	// Create mock server that returns error
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"error":             "invalid_grant",
			"error_description": "Invalid authorization code",
		})
	}))
	defer mockServer.Close()

	// Override Google token URL for testing
	originalTokenURL := googleTokenURL
	googleTokenURL = mockServer.URL
	defer func() { googleTokenURL = originalTokenURL }()

	// Setup environment
	os.Setenv("GOOGLE_CLIENT_ID", "test-client-id")
	os.Setenv("GOOGLE_CLIENT_SECRET", "test-client-secret")
	defer os.Unsetenv("GOOGLE_CLIENT_ID")
	defer os.Unsetenv("GOOGLE_CLIENT_SECRET")

	// Test exchange with invalid code
	_, _, err := ExchangeGoogleCode("invalid-code", "http://localhost:8080/callback")

	if err == nil {
		t.Fatal("Expected error for invalid code, got nil")
	}
	if !strings.Contains(err.Error(), "400") {
		t.Errorf("Expected error to contain status 400, got: %v", err)
	}
}

func TestExchangeGoogleCode_InvalidJSON(t *testing.T) {
	// Create mock server that returns invalid JSON
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("invalid json"))
	}))
	defer mockServer.Close()

	// Override Google token URL for testing
	originalTokenURL := googleTokenURL
	googleTokenURL = mockServer.URL
	defer func() { googleTokenURL = originalTokenURL }()

	// Setup environment
	os.Setenv("GOOGLE_CLIENT_ID", "test-client-id")
	os.Setenv("GOOGLE_CLIENT_SECRET", "test-client-secret")
	defer os.Unsetenv("GOOGLE_CLIENT_ID")
	defer os.Unsetenv("GOOGLE_CLIENT_SECRET")

	// Test exchange
	_, _, err := ExchangeGoogleCode("test-code", "http://localhost:8080/callback")

	if err == nil {
		t.Fatal("Expected error for invalid JSON, got nil")
	}
	if !strings.Contains(err.Error(), "parsing token response") {
		t.Errorf("Expected error about parsing token response, got: %v", err)
	}
}

func TestGetGoogleUserInfo_Success(t *testing.T) {
	// Create mock server
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify request method
		if r.Method != "GET" {
			t.Errorf("Expected GET request, got %s", r.Method)
		}

		// Verify authorization header
		authHeader := r.Header.Get("Authorization")
		if authHeader != "Bearer test-access-token" {
			t.Errorf("Expected 'Bearer test-access-token' authorization, got '%s'", authHeader)
		}

		// Return user info
		userInfo := map[string]interface{}{
			"id":             "google-user-123",
			"email":          "test@gmail.com",
			"name":           "Test User",
			"picture":        "https://example.com/avatar.jpg",
			"verified_email": true,
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(userInfo)
	}))
	defer mockServer.Close()

	// Override Google user URL for testing
	originalUserURL := googleUserURL
	googleUserURL = mockServer.URL
	defer func() { googleUserURL = originalUserURL }()

	// Test get user info
	userInfo, err := GetGoogleUserInfo("test-access-token")

	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}
	if userInfo == nil {
		t.Fatal("Expected user info, got nil")
	}
	if userInfo.ProviderUserID != "google-user-123" {
		t.Errorf("Expected provider user ID 'google-user-123', got '%s'", userInfo.ProviderUserID)
	}
	if userInfo.Email != "test@gmail.com" {
		t.Errorf("Expected email 'test@gmail.com', got '%s'", userInfo.Email)
	}
	if userInfo.Name != "Test User" {
		t.Errorf("Expected name 'Test User', got '%s'", userInfo.Name)
	}
	if userInfo.AvatarURL != "https://example.com/avatar.jpg" {
		t.Errorf("Expected avatar URL 'https://example.com/avatar.jpg', got '%s'", userInfo.AvatarURL)
	}
	if !userInfo.EmailVerified {
		t.Error("Expected email to be verified")
	}
}

func TestGetGoogleUserInfo_UnverifiedEmail(t *testing.T) {
	// Create mock server
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		userInfo := map[string]interface{}{
			"id":             "google-user-456",
			"email":          "unverified@gmail.com",
			"name":           "Unverified User",
			"picture":        "",
			"verified_email": false,
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(userInfo)
	}))
	defer mockServer.Close()

	// Override Google user URL for testing
	originalUserURL := googleUserURL
	googleUserURL = mockServer.URL
	defer func() { googleUserURL = originalUserURL }()

	// Test get user info
	userInfo, err := GetGoogleUserInfo("test-access-token")

	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}
	if userInfo.EmailVerified {
		t.Error("Expected email to not be verified")
	}
}

func TestGetGoogleUserInfo_InvalidToken(t *testing.T) {
	// Create mock server that returns 401
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"error": map[string]interface{}{
				"code":    401,
				"message": "Invalid Credentials",
			},
		})
	}))
	defer mockServer.Close()

	// Override Google user URL for testing
	originalUserURL := googleUserURL
	googleUserURL = mockServer.URL
	defer func() { googleUserURL = originalUserURL }()

	// Test get user info with invalid token
	_, err := GetGoogleUserInfo("invalid-token")

	if err == nil {
		t.Fatal("Expected error for invalid token, got nil")
	}
	if !strings.Contains(err.Error(), "401") {
		t.Errorf("Expected error to contain status 401, got: %v", err)
	}
}

func TestGetGoogleUserInfo_InvalidJSON(t *testing.T) {
	// Create mock server that returns invalid JSON
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("invalid json"))
	}))
	defer mockServer.Close()

	// Override Google user URL for testing
	originalUserURL := googleUserURL
	googleUserURL = mockServer.URL
	defer func() { googleUserURL = originalUserURL }()

	// Test get user info
	_, err := GetGoogleUserInfo("test-access-token")

	if err == nil {
		t.Fatal("Expected error for invalid JSON, got nil")
	}
	if !strings.Contains(err.Error(), "parsing user info") {
		t.Errorf("Expected error about parsing user info, got: %v", err)
	}
}

func TestGetGoogleUserInfo_EmptyAccessToken(t *testing.T) {
	// Create mock server
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		// Empty token results in "Bearer" (HTTP trims trailing spaces)
		if !strings.HasPrefix(authHeader, "Bearer") {
			t.Errorf("Expected authorization to start with 'Bearer', got '%s'", authHeader)
		}
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"error": "invalid_token",
		})
	}))
	defer mockServer.Close()

	// Override Google user URL for testing
	originalUserURL := googleUserURL
	googleUserURL = mockServer.URL
	defer func() { googleUserURL = originalUserURL }()

	// Test with empty access token
	_, err := GetGoogleUserInfo("")

	if err == nil {
		t.Fatal("Expected error for empty access token, got nil")
	}
}

func TestGoogleOAuth_URLConstants(t *testing.T) {
	// Verify constants are defined
	if googleAuthURL == "" {
		t.Error("googleAuthURL should be defined")
	}
	if googleTokenURL == "" {
		t.Error("googleTokenURL should be defined")
	}
	if googleUserURL == "" {
		t.Error("googleUserURL should be defined")
	}

	// Verify expected values
	expectedAuthURL := "https://accounts.google.com/o/oauth2/v2/auth"
	expectedTokenURL := "https://oauth2.googleapis.com/token"
	expectedUserURL := "https://www.googleapis.com/oauth2/v2/userinfo"

	if googleAuthURL != expectedAuthURL {
		t.Errorf("Expected auth URL '%s', got '%s'", expectedAuthURL, googleAuthURL)
	}
	if googleTokenURL != expectedTokenURL {
		t.Errorf("Expected token URL '%s', got '%s'", expectedTokenURL, googleTokenURL)
	}
	if googleUserURL != expectedUserURL {
		t.Errorf("Expected user URL '%s', got '%s'", expectedUserURL, googleUserURL)
	}
}

func TestGoogleOAuth_ReturnTypes(t *testing.T) {
	// Test BuildGoogleAuthURL returns a string
	url := BuildGoogleAuthURL("state", "redirect")
	if url == "" {
		t.Error("BuildGoogleAuthURL should return a non-empty string")
	}

	// Test ExchangeGoogleCode returns correct types
	// This is a compile-time check, but we can test with a mock server
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		response := map[string]interface{}{
			"access_token":  "token",
			"refresh_token": "refresh",
			"expires_in":    3600,
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
	}))
	defer mockServer.Close()

	originalTokenURL := googleTokenURL
	googleTokenURL = mockServer.URL
	defer func() { googleTokenURL = originalTokenURL }()

	os.Setenv("GOOGLE_CLIENT_ID", "test-id")
	os.Setenv("GOOGLE_CLIENT_SECRET", "test-secret")
	defer os.Unsetenv("GOOGLE_CLIENT_ID")
	defer os.Unsetenv("GOOGLE_CLIENT_SECRET")

	accessToken, refreshToken, err := ExchangeGoogleCode("code", "redirect")
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if accessToken == "" || refreshToken == "" {
		t.Error("Expected non-empty tokens")
	}
}

func TestGetGoogleUserInfo_ReturnsOAuthUserInfo(t *testing.T) {
	// Test that GetGoogleUserInfo returns *models.OAuthUserInfo
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		userInfo := map[string]interface{}{
			"id":             "123",
			"email":          "test@example.com",
			"name":           "Test",
			"picture":        "url",
			"verified_email": true,
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(userInfo)
	}))
	defer mockServer.Close()

	originalUserURL := googleUserURL
	googleUserURL = mockServer.URL
	defer func() { googleUserURL = originalUserURL }()

	userInfo, err := GetGoogleUserInfo("token")
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	// Verify it's the correct type
	var _ *models.OAuthUserInfo = userInfo
	if userInfo.ProviderUserID == "" {
		t.Error("Expected non-empty provider user ID")
	}
}
