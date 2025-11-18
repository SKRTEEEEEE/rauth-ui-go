package oauth

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
)

// TestGoogleOAuth_FullFlow tests the complete OAuth flow integration
func TestGoogleOAuth_FullFlow(t *testing.T) {
	// Skip if not in integration test mode
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	// Setup test OAuth credentials
	os.Setenv("GOOGLE_CLIENT_ID", "test-client-id-integration")
	os.Setenv("GOOGLE_CLIENT_SECRET", "test-client-secret-integration")
	defer os.Unsetenv("GOOGLE_CLIENT_ID")
	defer os.Unsetenv("GOOGLE_CLIENT_SECRET")

	// Mock Google OAuth server
	mockGoogleServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/token":
			// Handle token exchange
			if r.Method != "POST" {
				t.Errorf("Expected POST, got %s", r.Method)
				w.WriteHeader(http.StatusMethodNotAllowed)
				return
			}

			err := r.ParseForm()
			if err != nil {
				t.Errorf("Failed to parse form: %v", err)
				w.WriteHeader(http.StatusBadRequest)
				return
			}

			code := r.Form.Get("code")
			if code == "" {
				w.WriteHeader(http.StatusBadRequest)
				json.NewEncoder(w).Encode(map[string]interface{}{
					"error": "invalid_grant",
				})
				return
			}

			response := map[string]interface{}{
				"access_token":  "mock-access-token-" + code,
				"refresh_token": "mock-refresh-token-" + code,
				"expires_in":    3600,
				"token_type":    "Bearer",
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(response)

		case "/userinfo":
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
					"error": "invalid_token",
				})
				return
			}

			userInfo := map[string]interface{}{
				"id":             "google-integration-user-123",
				"email":          "integration@test.com",
				"name":           "Integration Test User",
				"picture":        "https://example.com/integration-avatar.jpg",
				"verified_email": true,
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(userInfo)

		default:
			t.Errorf("Unexpected path: %s", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer mockGoogleServer.Close()

	// Override URLs for testing
	originalTokenURL := googleTokenURL
	originalUserURL := googleUserURL
	googleTokenURL = mockGoogleServer.URL + "/token"
	googleUserURL = mockGoogleServer.URL + "/userinfo"
	defer func() {
		googleTokenURL = originalTokenURL
		googleUserURL = originalUserURL
	}()

	// Step 1: Build authorization URL
	state := "integration-test-state"
	redirectURI := "http://localhost:8080/api/v1/oauth/callback/google"
	authURL := BuildGoogleAuthURL(state, redirectURI)

	if authURL == "" {
		t.Fatal("BuildGoogleAuthURL returned empty string")
	}

	t.Logf("Authorization URL: %s", authURL)

	// Step 2: Simulate authorization code received
	authorizationCode := "integration-test-code"

	// Step 3: Exchange code for tokens
	accessToken, refreshToken, err := ExchangeGoogleCode(authorizationCode, redirectURI)
	if err != nil {
		t.Fatalf("ExchangeGoogleCode failed: %v", err)
	}

	if accessToken == "" {
		t.Error("Expected non-empty access token")
	}
	if refreshToken == "" {
		t.Error("Expected non-empty refresh token")
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
	userInfo, err := GetGoogleUserInfo(accessToken)
	if err != nil {
		t.Fatalf("GetGoogleUserInfo failed: %v", err)
	}

	if userInfo == nil {
		t.Fatal("Expected user info, got nil")
	}

	// Verify user info
	expectedUserID := "google-integration-user-123"
	expectedEmail := "integration@test.com"
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

// TestGoogleOAuth_ErrorHandling tests error scenarios in the full flow
func TestGoogleOAuth_ErrorHandling(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	// Setup test OAuth credentials
	os.Setenv("GOOGLE_CLIENT_ID", "test-client-id")
	os.Setenv("GOOGLE_CLIENT_SECRET", "test-client-secret")
	defer os.Unsetenv("GOOGLE_CLIENT_ID")
	defer os.Unsetenv("GOOGLE_CLIENT_SECRET")

	// Mock Google OAuth server with error responses
	mockGoogleServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/token-error":
			// Return error for token exchange
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"error":             "invalid_grant",
				"error_description": "Authorization code is invalid",
			})

		case "/userinfo-error":
			// Return error for user info
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"error": map[string]interface{}{
					"code":    401,
					"message": "Invalid Credentials",
				},
			})

		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer mockGoogleServer.Close()

	// Test token exchange error
	t.Run("TokenExchangeError", func(t *testing.T) {
		originalTokenURL := googleTokenURL
		googleTokenURL = mockGoogleServer.URL + "/token-error"
		defer func() { googleTokenURL = originalTokenURL }()

		_, _, err := ExchangeGoogleCode("invalid-code", "http://localhost:8080/callback")
		if err == nil {
			t.Error("Expected error for invalid code, got nil")
		}
	})

	// Test user info error
	t.Run("UserInfoError", func(t *testing.T) {
		originalUserURL := googleUserURL
		googleUserURL = mockGoogleServer.URL + "/userinfo-error"
		defer func() { googleUserURL = originalUserURL }()

		_, err := GetGoogleUserInfo("invalid-token")
		if err == nil {
			t.Error("Expected error for invalid token, got nil")
		}
	})
}

// TestGoogleOAuth_ConcurrentRequests tests concurrent OAuth requests
func TestGoogleOAuth_ConcurrentRequests(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	// Setup test OAuth credentials
	os.Setenv("GOOGLE_CLIENT_ID", "test-client-id")
	os.Setenv("GOOGLE_CLIENT_SECRET", "test-client-secret")
	defer os.Unsetenv("GOOGLE_CLIENT_ID")
	defer os.Unsetenv("GOOGLE_CLIENT_SECRET")

	requestCount := 0

	// Mock Google OAuth server
	mockGoogleServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount++
		switch r.URL.Path {
		case "/token":
			response := map[string]interface{}{
				"access_token":  fmt.Sprintf("token-%d", requestCount),
				"refresh_token": fmt.Sprintf("refresh-%d", requestCount),
				"expires_in":    3600,
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(response)

		case "/userinfo":
			userInfo := map[string]interface{}{
				"id":             fmt.Sprintf("user-%d", requestCount),
				"email":          fmt.Sprintf("user%d@test.com", requestCount),
				"name":           fmt.Sprintf("User %d", requestCount),
				"picture":        "https://example.com/avatar.jpg",
				"verified_email": true,
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(userInfo)
		}
	}))
	defer mockGoogleServer.Close()

	// Override URLs for testing
	originalTokenURL := googleTokenURL
	originalUserURL := googleUserURL
	googleTokenURL = mockGoogleServer.URL + "/token"
	googleUserURL = mockGoogleServer.URL + "/userinfo"
	defer func() {
		googleTokenURL = originalTokenURL
		googleUserURL = originalUserURL
	}()

	// Run concurrent requests
	concurrency := 10
	done := make(chan bool, concurrency)
	errors := make(chan error, concurrency)

	for i := 0; i < concurrency; i++ {
		go func(index int) {
			// Exchange code
			code := fmt.Sprintf("code-%d", index)
			accessToken, _, err := ExchangeGoogleCode(code, "http://localhost:8080/callback")
			if err != nil {
				errors <- fmt.Errorf("ExchangeGoogleCode failed for %d: %w", index, err)
				done <- false
				return
			}

			// Get user info
			_, err = GetGoogleUserInfo(accessToken)
			if err != nil {
				errors <- fmt.Errorf("GetGoogleUserInfo failed for %d: %w", index, err)
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

	t.Logf("Successfully completed %d concurrent OAuth requests", successCount)
}

// TestGoogleOAuth_RateLimiting tests behavior under rate limiting
func TestGoogleOAuth_RateLimiting(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	// Setup test OAuth credentials
	os.Setenv("GOOGLE_CLIENT_ID", "test-client-id")
	os.Setenv("GOOGLE_CLIENT_SECRET", "test-client-secret")
	defer os.Unsetenv("GOOGLE_CLIENT_ID")
	defer os.Unsetenv("GOOGLE_CLIENT_SECRET")

	requestCount := 0
	maxRequests := 5

	// Mock Google OAuth server with rate limiting
	mockGoogleServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount++

		if requestCount > maxRequests {
			w.WriteHeader(http.StatusTooManyRequests)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"error":             "rate_limit_exceeded",
				"error_description": "Too many requests",
			})
			return
		}

		switch r.URL.Path {
		case "/token":
			response := map[string]interface{}{
				"access_token":  "token",
				"refresh_token": "refresh",
				"expires_in":    3600,
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(response)

		case "/userinfo":
			userInfo := map[string]interface{}{
				"id":             "user-id",
				"email":          "user@test.com",
				"name":           "Test User",
				"picture":        "https://example.com/avatar.jpg",
				"verified_email": true,
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(userInfo)
		}
	}))
	defer mockGoogleServer.Close()

	// Override URLs for testing
	originalTokenURL := googleTokenURL
	googleTokenURL = mockGoogleServer.URL + "/token"
	defer func() { googleTokenURL = originalTokenURL }()

	// Make requests until rate limit
	successCount := 0
	rateLimitCount := 0

	for i := 0; i < maxRequests+3; i++ {
		_, _, err := ExchangeGoogleCode(fmt.Sprintf("code-%d", i), "http://localhost:8080/callback")
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
