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

func TestBuildGitHubAuthURL(t *testing.T) {
	// Setup environment
	os.Setenv("GITHUB_CLIENT_ID", "test-github-client-id")
	defer os.Unsetenv("GITHUB_CLIENT_ID")

	state := "test-state-123"
	redirectURI := "http://localhost:8080/api/v1/oauth/callback/github"

	authURL := BuildGitHubAuthURL(state, redirectURI)

	// Parse URL
	parsedURL, err := url.Parse(authURL)
	if err != nil {
		t.Fatalf("Failed to parse auth URL: %v", err)
	}

	// Verify base URL
	if parsedURL.Scheme != "https" {
		t.Errorf("Expected https scheme, got %s", parsedURL.Scheme)
	}
	if parsedURL.Host != "github.com" {
		t.Errorf("Expected github.com host, got %s", parsedURL.Host)
	}
	if parsedURL.Path != "/login/oauth/authorize" {
		t.Errorf("Expected /login/oauth/authorize path, got %s", parsedURL.Path)
	}

	// Verify query parameters
	query := parsedURL.Query()

	if query.Get("client_id") != "test-github-client-id" {
		t.Errorf("Expected client_id 'test-github-client-id', got '%s'", query.Get("client_id"))
	}
	if query.Get("redirect_uri") != redirectURI {
		t.Errorf("Expected redirect_uri '%s', got '%s'", redirectURI, query.Get("redirect_uri"))
	}
	if query.Get("scope") != "user:email" {
		t.Errorf("Expected scope 'user:email', got '%s'", query.Get("scope"))
	}
	if query.Get("state") != state {
		t.Errorf("Expected state '%s', got '%s'", state, query.Get("state"))
	}
}

func TestBuildGitHubAuthURL_MissingClientID(t *testing.T) {
	// Unset client ID
	os.Unsetenv("GITHUB_CLIENT_ID")

	state := "test-state"
	redirectURI := "http://localhost:8080/callback"

	authURL := BuildGitHubAuthURL(state, redirectURI)

	// Should still build URL but with empty client_id
	if !strings.Contains(authURL, "client_id=") {
		t.Error("URL should contain client_id parameter")
	}

	parsedURL, _ := url.Parse(authURL)
	if parsedURL.Query().Get("client_id") != "" {
		t.Error("Expected empty client_id when GITHUB_CLIENT_ID is not set")
	}
}

func TestExchangeGitHubCode_Success(t *testing.T) {
	// Create mock server
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify request method
		if r.Method != "POST" {
			t.Errorf("Expected POST request, got %s", r.Method)
		}

		// Verify Accept header
		acceptHeader := r.Header.Get("Accept")
		if acceptHeader != "application/json" {
			t.Errorf("Expected Accept 'application/json', got '%s'", acceptHeader)
		}

		// Verify query parameters (GitHub uses query params in POST)
		query := r.URL.Query()
		if query.Get("code") != "test-code" {
			t.Errorf("Expected code 'test-code', got '%s'", query.Get("code"))
		}

		// Return success response
		response := map[string]interface{}{
			"access_token":  "test-access-token",
			"refresh_token": "test-refresh-token",
			"token_type":    "bearer",
			"scope":         "user:email",
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(response)
	}))
	defer mockServer.Close()

	// Override GitHub token URL for testing
	originalTokenURL := githubTokenURL
	githubTokenURL = mockServer.URL
	defer func() { githubTokenURL = originalTokenURL }()

	// Setup environment
	os.Setenv("GITHUB_CLIENT_ID", "test-client-id")
	os.Setenv("GITHUB_CLIENT_SECRET", "test-client-secret")
	defer os.Unsetenv("GITHUB_CLIENT_ID")
	defer os.Unsetenv("GITHUB_CLIENT_SECRET")

	// Test exchange
	accessToken, refreshToken, err := ExchangeGitHubCode("test-code", "http://localhost:8080/callback")

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

func TestExchangeGitHubCode_InvalidCode(t *testing.T) {
	// Create mock server that returns error
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"error":             "bad_verification_code",
			"error_description": "The code passed is incorrect or expired.",
		})
	}))
	defer mockServer.Close()

	// Override GitHub token URL for testing
	originalTokenURL := githubTokenURL
	githubTokenURL = mockServer.URL
	defer func() { githubTokenURL = originalTokenURL }()

	// Setup environment
	os.Setenv("GITHUB_CLIENT_ID", "test-client-id")
	os.Setenv("GITHUB_CLIENT_SECRET", "test-client-secret")
	defer os.Unsetenv("GITHUB_CLIENT_ID")
	defer os.Unsetenv("GITHUB_CLIENT_SECRET")

	// Test exchange with invalid code
	_, _, err := ExchangeGitHubCode("invalid-code", "http://localhost:8080/callback")

	if err == nil {
		t.Fatal("Expected error for invalid code, got nil")
	}
	if !strings.Contains(err.Error(), "400") {
		t.Errorf("Expected error to contain status 400, got: %v", err)
	}
}

func TestExchangeGitHubCode_InvalidJSON(t *testing.T) {
	// Create mock server that returns invalid JSON
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("invalid json"))
	}))
	defer mockServer.Close()

	// Override GitHub token URL for testing
	originalTokenURL := githubTokenURL
	githubTokenURL = mockServer.URL
	defer func() { githubTokenURL = originalTokenURL }()

	// Setup environment
	os.Setenv("GITHUB_CLIENT_ID", "test-client-id")
	os.Setenv("GITHUB_CLIENT_SECRET", "test-client-secret")
	defer os.Unsetenv("GITHUB_CLIENT_ID")
	defer os.Unsetenv("GITHUB_CLIENT_SECRET")

	// Test exchange
	_, _, err := ExchangeGitHubCode("test-code", "http://localhost:8080/callback")

	if err == nil {
		t.Fatal("Expected error for invalid JSON, got nil")
	}
	if !strings.Contains(err.Error(), "parsing token response") {
		t.Errorf("Expected error about parsing token response, got: %v", err)
	}
}

func TestGetGitHubUserInfo_Success(t *testing.T) {
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
			"id":         12345678,
			"email":      "test@github.com",
			"name":       "Test User",
			"avatar_url": "https://avatars.githubusercontent.com/u/12345678",
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(userInfo)
	}))
	defer mockServer.Close()

	// Override GitHub user URL for testing
	originalUserURL := githubUserURL
	githubUserURL = mockServer.URL
	defer func() { githubUserURL = originalUserURL }()

	// Test get user info
	userInfo, err := GetGitHubUserInfo("test-access-token")

	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}
	if userInfo == nil {
		t.Fatal("Expected user info, got nil")
	}
	if userInfo.ProviderUserID != "12345678" {
		t.Errorf("Expected provider user ID '12345678', got '%s'", userInfo.ProviderUserID)
	}
	if userInfo.Email != "test@github.com" {
		t.Errorf("Expected email 'test@github.com', got '%s'", userInfo.Email)
	}
	if userInfo.Name != "Test User" {
		t.Errorf("Expected name 'Test User', got '%s'", userInfo.Name)
	}
	if userInfo.AvatarURL != "https://avatars.githubusercontent.com/u/12345678" {
		t.Errorf("Expected avatar URL 'https://avatars.githubusercontent.com/u/12345678', got '%s'", userInfo.AvatarURL)
	}
	if !userInfo.EmailVerified {
		t.Error("Expected email to be verified for GitHub users")
	}
}

func TestGetGitHubUserInfo_NullEmail(t *testing.T) {
	// Create mock server with null email
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		userInfo := map[string]interface{}{
			"id":         87654321,
			"email":      nil,
			"name":       "User Without Email",
			"avatar_url": "https://avatars.githubusercontent.com/u/87654321",
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(userInfo)
	}))
	defer mockServer.Close()

	// Override GitHub user URL for testing
	originalUserURL := githubUserURL
	githubUserURL = mockServer.URL
	defer func() { githubUserURL = originalUserURL }()

	// Test get user info
	userInfo, err := GetGitHubUserInfo("test-access-token")

	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}
	if userInfo.Email != "" {
		t.Errorf("Expected empty email for null, got '%s'", userInfo.Email)
	}
}

func TestGetGitHubUserInfo_InvalidToken(t *testing.T) {
	// Create mock server that returns 401
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"message":           "Bad credentials",
			"documentation_url": "https://docs.github.com/rest",
		})
	}))
	defer mockServer.Close()

	// Override GitHub user URL for testing
	originalUserURL := githubUserURL
	githubUserURL = mockServer.URL
	defer func() { githubUserURL = originalUserURL }()

	// Test get user info with invalid token
	_, err := GetGitHubUserInfo("invalid-token")

	if err == nil {
		t.Fatal("Expected error for invalid token, got nil")
	}
	if !strings.Contains(err.Error(), "401") {
		t.Errorf("Expected error to contain status 401, got: %v", err)
	}
}

func TestGetGitHubUserInfo_InvalidJSON(t *testing.T) {
	// Create mock server that returns invalid JSON
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("invalid json"))
	}))
	defer mockServer.Close()

	// Override GitHub user URL for testing
	originalUserURL := githubUserURL
	githubUserURL = mockServer.URL
	defer func() { githubUserURL = originalUserURL }()

	// Test get user info
	_, err := GetGitHubUserInfo("test-access-token")

	if err == nil {
		t.Fatal("Expected error for invalid JSON, got nil")
	}
	if !strings.Contains(err.Error(), "parsing user info") {
		t.Errorf("Expected error about parsing user info, got: %v", err)
	}
}

func TestGetGitHubUserInfo_EmptyAccessToken(t *testing.T) {
	// Create mock server
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		// Empty token results in "Bearer" (HTTP trims trailing spaces)
		if !strings.HasPrefix(authHeader, "Bearer") {
			t.Errorf("Expected authorization to start with 'Bearer', got '%s'", authHeader)
		}
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"message": "Bad credentials",
		})
	}))
	defer mockServer.Close()

	// Override GitHub user URL for testing
	originalUserURL := githubUserURL
	githubUserURL = mockServer.URL
	defer func() { githubUserURL = originalUserURL }()

	// Test with empty access token
	_, err := GetGitHubUserInfo("")

	if err == nil {
		t.Fatal("Expected error for empty access token, got nil")
	}
}

func TestGitHubOAuth_URLConstants(t *testing.T) {
	// Verify constants are defined
	if githubAuthURL == "" {
		t.Error("githubAuthURL should be defined")
	}
	if githubTokenURL == "" {
		t.Error("githubTokenURL should be defined")
	}
	if githubUserURL == "" {
		t.Error("githubUserURL should be defined")
	}

	// Verify expected values
	expectedAuthURL := "https://github.com/login/oauth/authorize"
	expectedTokenURL := "https://github.com/login/oauth/access_token"
	expectedUserURL := "https://api.github.com/user"

	if githubAuthURL != expectedAuthURL {
		t.Errorf("Expected auth URL '%s', got '%s'", expectedAuthURL, githubAuthURL)
	}
	if githubTokenURL != expectedTokenURL {
		t.Errorf("Expected token URL '%s', got '%s'", expectedTokenURL, githubTokenURL)
	}
	if githubUserURL != expectedUserURL {
		t.Errorf("Expected user URL '%s', got '%s'", expectedUserURL, githubUserURL)
	}
}

func TestGitHubOAuth_ReturnTypes(t *testing.T) {
	// Test BuildGitHubAuthURL returns a string
	os.Setenv("GITHUB_CLIENT_ID", "test-id")
	defer os.Unsetenv("GITHUB_CLIENT_ID")

	url := BuildGitHubAuthURL("state", "redirect")
	if url == "" {
		t.Error("BuildGitHubAuthURL should return a non-empty string")
	}

	// Test ExchangeGitHubCode returns correct types
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		response := map[string]interface{}{
			"access_token":  "token",
			"refresh_token": "refresh",
			"token_type":    "bearer",
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
	}))
	defer mockServer.Close()

	originalTokenURL := githubTokenURL
	githubTokenURL = mockServer.URL
	defer func() { githubTokenURL = originalTokenURL }()

	os.Setenv("GITHUB_CLIENT_SECRET", "test-secret")
	defer os.Unsetenv("GITHUB_CLIENT_SECRET")

	accessToken, refreshToken, err := ExchangeGitHubCode("code", "redirect")
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if accessToken == "" {
		t.Error("Expected non-empty access token")
	}
	// GitHub refresh token might be empty if not using refresh token grant
	_ = refreshToken
}

func TestGetGitHubUserInfo_ReturnsOAuthUserInfo(t *testing.T) {
	// Test that GetGitHubUserInfo returns *models.OAuthUserInfo
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		userInfo := map[string]interface{}{
			"id":         123,
			"email":      "test@example.com",
			"name":       "Test",
			"avatar_url": "url",
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(userInfo)
	}))
	defer mockServer.Close()

	originalUserURL := githubUserURL
	githubUserURL = mockServer.URL
	defer func() { githubUserURL = originalUserURL }()

	userInfo, err := GetGitHubUserInfo("token")
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	// Verify it's the correct type
	var _ *models.OAuthUserInfo = userInfo
	if userInfo.ProviderUserID == "" {
		t.Error("Expected non-empty provider user ID")
	}
}
