package oauth

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
)

// TestGitHubOAuth_FullFlow tests the complete OAuth flow integration
func TestGitHubOAuth_FullFlow(t *testing.T) {
	// Skip if not in integration test mode
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	// Setup test OAuth credentials
	os.Setenv("GITHUB_CLIENT_ID", "test-client-id-integration")
	os.Setenv("GITHUB_CLIENT_SECRET", "test-client-secret-integration")
	defer os.Unsetenv("GITHUB_CLIENT_ID")
	defer os.Unsetenv("GITHUB_CLIENT_SECRET")

	// Mock GitHub OAuth server
	mockGitHubServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/token":
			// Handle token exchange
			if r.Method != "POST" {
				t.Errorf("Expected POST, got %s", r.Method)
				w.WriteHeader(http.StatusMethodNotAllowed)
				return
			}

			code := r.URL.Query().Get("code")
			if code == "" {
				w.WriteHeader(http.StatusBadRequest)
				json.NewEncoder(w).Encode(map[string]interface{}{
					"error": "bad_verification_code",
				})
				return
			}

			response := map[string]interface{}{
				"access_token":  "mock-access-token-" + code,
				"refresh_token": "mock-refresh-token-" + code,
				"token_type":    "bearer",
				"scope":         "user:email",
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(response)

		case "/user":
			// Handle user info request
			if r.Method != "GET" {
				t.Errorf("Expected GET, got %s", r.Method)
				w.WriteHeader(http.StatusMethodNotAllowed)
				return
			}

			authHeader := r.Header.Get("Authorization")
			if authHeader == "" {
				w.WriteHeader(http.StatusUnauthorized)
				json.NewEncoder(w).Encode(map[string]interface{}{
					"message": "Bad credentials",
				})
				return
			}

			userInfo := map[string]interface{}{
				"id":         99887766,
				"email":      "integration@github.com",
				"name":       "Integration Test User",
				"avatar_url": "https://avatars.githubusercontent.com/u/99887766",
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(userInfo)

		default:
			t.Errorf("Unexpected path: %s", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer mockGitHubServer.Close()

	// Override URLs for testing
	originalTokenURL := githubTokenURL
	originalUserURL := githubUserURL
	githubTokenURL = mockGitHubServer.URL + "/token"
	githubUserURL = mockGitHubServer.URL + "/user"
	defer func() {
		githubTokenURL = originalTokenURL
		githubUserURL = originalUserURL
	}()

	// Step 1: Build authorization URL
	state := "integration-test-state"
	redirectURI := "http://localhost:8080/api/v1/oauth/callback/github"
	authURL := BuildGitHubAuthURL(state, redirectURI)

	if authURL == "" {
		t.Fatal("BuildGitHubAuthURL returned empty string")
	}

	t.Logf("Authorization URL: %s", authURL)

	// Step 2: Simulate authorization code received
	authorizationCode := "integration-test-code"

	// Step 3: Exchange code for tokens
	accessToken, refreshToken, err := ExchangeGitHubCode(authorizationCode, redirectURI)
	if err != nil {
		t.Fatalf("ExchangeGitHubCode failed: %v", err)
	}

	if accessToken == "" {
		t.Error("Expected non-empty access token")
	}

	expectedAccessToken := "mock-access-token-" + authorizationCode
	expectedRefreshToken := "mock-refresh-token-" + authorizationCode

	if accessToken != expectedAccessToken {
		t.Errorf("Expected access token '%s', got '%s'", expectedAccessToken, accessToken)
	}
	if refreshToken != expectedRefreshToken {
		t.Errorf("Expected refresh token '%s', got '%s'", expectedRefreshToken, refreshToken)
	}

	t.Logf("Access Token: %s", accessToken)
	t.Logf("Refresh Token: %s", refreshToken)

	// Step 4: Get user info with access token
	userInfo, err := GetGitHubUserInfo(accessToken)
	if err != nil {
		t.Fatalf("GetGitHubUserInfo failed: %v", err)
	}

	if userInfo == nil {
		t.Fatal("Expected user info, got nil")
	}

	// Verify user info
	expectedUserID := "99887766"
	expectedEmail := "integration@github.com"
	expectedName := "Integration Test User"

	if userInfo.ProviderUserID != expectedUserID {
		t.Errorf("Expected user ID '%s', got '%s'", expectedUserID, userInfo.ProviderUserID)
	}
	if userInfo.Email != expectedEmail {
		t.Errorf("Expected email '%s', got '%s'", expectedEmail, userInfo.Email)
	}
	if userInfo.Name != expectedName {
		t.Errorf("Expected name '%s', got '%s'", expectedName, userInfo.Name)
	}
	if !userInfo.EmailVerified {
		t.Error("Expected email to be verified")
	}

	t.Logf("User Info: ID=%s, Email=%s, Name=%s", userInfo.ProviderUserID, userInfo.Email, userInfo.Name)
}

// TestGitHubOAuth_MissingRefreshToken ensures the flow works without refresh tokens
func TestGitHubOAuth_MissingRefreshToken(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	os.Setenv("GITHUB_CLIENT_ID", "missing-refresh-client-id")
	os.Setenv("GITHUB_CLIENT_SECRET", "missing-refresh-client-secret")
	defer os.Unsetenv("GITHUB_CLIENT_ID")
	defer os.Unsetenv("GITHUB_CLIENT_SECRET")

	mockGitHubServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/token":
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]any{
				"access_token": "token-no-refresh",
				"token_type":   "bearer",
			})
		case "/user":
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]any{
				"id":         445566,
				"email":      "norefresh@github.com",
				"name":       "No Refresh",
				"avatar_url": "https://avatars.githubusercontent.com/u/445566",
			})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer mockGitHubServer.Close()

	originalTokenURL := githubTokenURL
	originalUserURL := githubUserURL
	githubTokenURL = mockGitHubServer.URL + "/token"
	githubUserURL = mockGitHubServer.URL + "/user"
	defer func() {
		githubTokenURL = originalTokenURL
		githubUserURL = originalUserURL
	}()

	accessToken, refreshToken, err := ExchangeGitHubCode("code-no-refresh", "http://localhost/callback")
	if err != nil {
		t.Fatalf("ExchangeGitHubCode failed: %v", err)
	}
	if accessToken != "token-no-refresh" {
		t.Fatalf("Expected access token 'token-no-refresh', got '%s'", accessToken)
	}
	if refreshToken != "" {
		t.Fatalf("Expected empty refresh token, got '%s'", refreshToken)
	}

	userInfo, err := GetGitHubUserInfo(accessToken)
	if err != nil {
		t.Fatalf("GetGitHubUserInfo failed: %v", err)
	}
	if userInfo.Email != "norefresh@github.com" {
		t.Fatalf("Unexpected email %s", userInfo.Email)
	}
}

// TestGitHubOAuth_ErrorHandling tests error scenarios in the full flow
func TestGitHubOAuth_ErrorHandling(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	// Setup test OAuth credentials
	os.Setenv("GITHUB_CLIENT_ID", "test-client-id")
	os.Setenv("GITHUB_CLIENT_SECRET", "test-client-secret")
	defer os.Unsetenv("GITHUB_CLIENT_ID")
	defer os.Unsetenv("GITHUB_CLIENT_SECRET")

	// Mock GitHub OAuth server with error responses
	mockGitHubServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/token-error":
			// Return error for token exchange
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"error":             "bad_verification_code",
				"error_description": "The code passed is incorrect or expired.",
			})

		case "/user-error":
			// Return error for user info
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"message":           "Bad credentials",
				"documentation_url": "https://docs.github.com/rest",
			})

		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer mockGitHubServer.Close()

	// Test token exchange error
	t.Run("TokenExchangeError", func(t *testing.T) {
		originalTokenURL := githubTokenURL
		githubTokenURL = mockGitHubServer.URL + "/token-error"
		defer func() { githubTokenURL = originalTokenURL }()

		_, _, err := ExchangeGitHubCode("invalid-code", "http://localhost:8080/callback")
		if err == nil {
			t.Error("Expected error for invalid code, got nil")
		}
	})

	// Test user info error
	t.Run("UserInfoError", func(t *testing.T) {
		originalUserURL := githubUserURL
		githubUserURL = mockGitHubServer.URL + "/user-error"
		defer func() { githubUserURL = originalUserURL }()

		_, err := GetGitHubUserInfo("invalid-token")
		if err == nil {
			t.Error("Expected error for invalid token, got nil")
		}
	})
}

// TestGitHubOAuth_ConcurrentRequests tests concurrent OAuth requests
func TestGitHubOAuth_ConcurrentRequests(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	// Setup test OAuth credentials
	os.Setenv("GITHUB_CLIENT_ID", "test-client-id")
	os.Setenv("GITHUB_CLIENT_SECRET", "test-client-secret")
	defer os.Unsetenv("GITHUB_CLIENT_ID")
	defer os.Unsetenv("GITHUB_CLIENT_SECRET")

	requestCount := 0

	// Mock GitHub OAuth server
	mockGitHubServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount++
		switch r.URL.Path {
		case "/token":
			response := map[string]interface{}{
				"access_token":  fmt.Sprintf("token-%d", requestCount),
				"refresh_token": fmt.Sprintf("refresh-%d", requestCount),
				"token_type":    "bearer",
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(response)

		case "/user":
			userInfo := map[string]interface{}{
				"id":         requestCount,
				"email":      fmt.Sprintf("user%d@test.com", requestCount),
				"name":       fmt.Sprintf("User %d", requestCount),
				"avatar_url": "https://avatars.githubusercontent.com/u/1",
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(userInfo)
		}
	}))
	defer mockGitHubServer.Close()

	// Override URLs for testing
	originalTokenURL := githubTokenURL
	originalUserURL := githubUserURL
	githubTokenURL = mockGitHubServer.URL + "/token"
	githubUserURL = mockGitHubServer.URL + "/user"
	defer func() {
		githubTokenURL = originalTokenURL
		githubUserURL = originalUserURL
	}()

	// Run concurrent requests
	concurrency := 10
	done := make(chan bool, concurrency)
	errors := make(chan error, concurrency)

	for i := 0; i < concurrency; i++ {
		go func(index int) {
			// Exchange code
			code := fmt.Sprintf("code-%d", index)
			accessToken, _, err := ExchangeGitHubCode(code, "http://localhost:8080/callback")
			if err != nil {
				errors <- fmt.Errorf("ExchangeGitHubCode failed for %d: %w", index, err)
				done <- false
				return
			}

			// Get user info
			_, err = GetGitHubUserInfo(accessToken)
			if err != nil {
				errors <- fmt.Errorf("GetGitHubUserInfo failed for %d: %w", index, err)
				done <- false
				return
			}

			done <- true
		}(i)
	}

	// Wait for all goroutines to finish
	successCount := 0
	for i := 0; i < concurrency; i++ {
		select {
		case success := <-done:
			if success {
				successCount++
			}
		case err := <-errors:
			t.Errorf("Concurrent request error: %v", err)
		}
	}

	if successCount != concurrency {
		t.Errorf("Expected %d successful requests, got %d", concurrency, successCount)
	}

	t.Logf("Successfully completed %d concurrent GitHub OAuth requests", successCount)
}

// TestGitHubOAuth_RateLimiting tests behavior under rate limiting
func TestGitHubOAuth_RateLimiting(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	// Setup test OAuth credentials
	os.Setenv("GITHUB_CLIENT_ID", "test-client-id")
	os.Setenv("GITHUB_CLIENT_SECRET", "test-client-secret")
	defer os.Unsetenv("GITHUB_CLIENT_ID")
	defer os.Unsetenv("GITHUB_CLIENT_SECRET")

	requestCount := 0
	maxRequests := 5

	// Mock GitHub OAuth server with rate limiting
	mockGitHubServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount++

		if requestCount > maxRequests {
			w.Header().Set("X-RateLimit-Remaining", "0")
			w.WriteHeader(http.StatusForbidden)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"message":           "API rate limit exceeded",
				"documentation_url": "https://docs.github.com/rest/overview/resources-in-the-rest-api#rate-limiting",
			})
			return
		}

		switch r.URL.Path {
		case "/token":
			response := map[string]interface{}{
				"access_token":  "token",
				"refresh_token": "refresh",
				"token_type":    "bearer",
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(response)

		case "/user":
			userInfo := map[string]interface{}{
				"id":         12345,
				"email":      "user@test.com",
				"name":       "Test User",
				"avatar_url": "https://avatars.githubusercontent.com/u/12345",
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(userInfo)
		}
	}))
	defer mockGitHubServer.Close()

	// Override URLs for testing
	originalTokenURL := githubTokenURL
	githubTokenURL = mockGitHubServer.URL + "/token"
	defer func() { githubTokenURL = originalTokenURL }()

	// Make requests until rate limit
	successCount := 0
	rateLimitCount := 0

	for i := 0; i < maxRequests+3; i++ {
		_, _, err := ExchangeGitHubCode(fmt.Sprintf("code-%d", i), "http://localhost:8080/callback")
		if err != nil {
			if i < maxRequests {
				t.Errorf("Unexpected error before rate limit: %v", err)
			} else {
				rateLimitCount++
			}
		} else {
			successCount++
		}
	}

	if successCount != maxRequests {
		t.Errorf("Expected %d successful requests, got %d", maxRequests, successCount)
	}
	if rateLimitCount == 0 {
		t.Error("Expected some rate-limited requests, got none")
	}

	t.Logf("Successful requests: %d, Rate-limited requests: %d", successCount, rateLimitCount)
}
