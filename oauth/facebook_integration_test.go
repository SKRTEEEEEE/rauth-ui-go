package oauth

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
)

// TestFacebookOAuth_FullFlow tests the complete OAuth flow integration
func TestFacebookOAuth_FullFlow(t *testing.T) {
	// Skip if not in integration test mode
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	// Setup test OAuth credentials
	os.Setenv("FACEBOOK_APP_ID", "test-app-id-integration")
	os.Setenv("FACEBOOK_APP_SECRET", "test-app-secret-integration")
	defer os.Unsetenv("FACEBOOK_APP_ID")
	defer os.Unsetenv("FACEBOOK_APP_SECRET")

	// Mock Facebook OAuth server
	mockFacebookServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/token":
			// Handle token exchange
			if r.Method != "GET" {
				t.Errorf("Expected GET, got %s", r.Method)
				w.WriteHeader(http.StatusMethodNotAllowed)
				return
			}

			code := r.URL.Query().Get("code")
			if code == "" {
				w.WriteHeader(http.StatusBadRequest)
				json.NewEncoder(w).Encode(map[string]interface{}{
					"error": map[string]interface{}{
						"message": "Invalid verification code format.",
						"type":    "OAuthException",
						"code":    100,
					},
				})
				return
			}

			response := map[string]interface{}{
				"access_token": "mock-access-token-" + code,
				"token_type":   "bearer",
				"expires_in":   5183999,
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

			accessToken := r.URL.Query().Get("access_token")
			if accessToken == "" {
				w.WriteHeader(http.StatusUnauthorized)
				json.NewEncoder(w).Encode(map[string]interface{}{
					"error": map[string]interface{}{
						"message": "Invalid OAuth access token.",
					},
				})
				return
			}

			userInfo := map[string]interface{}{
				"id":    "99887766554433221",
				"email": "integration@facebook.com",
				"name":  "Integration Test User",
				"picture": map[string]interface{}{
					"data": map[string]interface{}{
						"url": "https://platform-lookaside.fbsbx.com/platform/profilepic/integration",
					},
				},
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(userInfo)

		default:
			t.Errorf("Unexpected path: %s", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer mockFacebookServer.Close()

	// Override URLs for testing
	originalTokenURL := facebookTokenURL
	originalUserURL := facebookUserURL
	facebookTokenURL = mockFacebookServer.URL + "/token"
	facebookUserURL = mockFacebookServer.URL + "/user"
	defer func() {
		facebookTokenURL = originalTokenURL
		facebookUserURL = originalUserURL
	}()

	// Step 1: Build authorization URL
	state := "integration-test-state"
	redirectURI := "http://localhost:8080/api/v1/oauth/callback/facebook"
	authURL := BuildFacebookAuthURL(state, redirectURI)

	if authURL == "" {
		t.Fatal("BuildFacebookAuthURL returned empty string")
	}

	t.Logf("Authorization URL: %s", authURL)

	// Step 2: Simulate authorization code received
	authorizationCode := "integration-test-code"

	// Step 3: Exchange code for tokens
	accessToken, refreshToken, err := ExchangeFacebookCode(authorizationCode, redirectURI)
	if err != nil {
		t.Fatalf("ExchangeFacebookCode failed: %v", err)
	}

	if accessToken == "" {
		t.Error("Expected non-empty access token")
	}

	expectedAccessToken := "mock-access-token-" + authorizationCode

	if accessToken != expectedAccessToken {
		t.Errorf("Expected access token '%s', got '%s'", expectedAccessToken, accessToken)
	}
	// Facebook doesn't return refresh tokens
	if refreshToken != "" {
		t.Logf("Refresh Token (should be empty for Facebook): %s", refreshToken)
	}

	t.Logf("Access Token: %s", accessToken)

	// Step 4: Get user info with access token
	userInfo, err := GetFacebookUserInfo(accessToken)
	if err != nil {
		t.Fatalf("GetFacebookUserInfo failed: %v", err)
	}

	if userInfo == nil {
		t.Fatal("Expected user info, got nil")
	}

	// Verify user info
	expectedUserID := "99887766554433221"
	expectedEmail := "integration@facebook.com"
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

// TestFacebookOAuth_NoRefreshToken ensures the flow works without refresh tokens (standard for Facebook)
func TestFacebookOAuth_NoRefreshToken(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	os.Setenv("FACEBOOK_APP_ID", "no-refresh-app-id")
	os.Setenv("FACEBOOK_APP_SECRET", "no-refresh-app-secret")
	defer os.Unsetenv("FACEBOOK_APP_ID")
	defer os.Unsetenv("FACEBOOK_APP_SECRET")

	mockFacebookServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/token":
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]any{
				"access_token": "token-no-refresh",
				"token_type":   "bearer",
				"expires_in":   5183999,
			})
		case "/user":
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]any{
				"id":      "445566778899001122",
				"email":   "norefresh@facebook.com",
				"name":    "No Refresh",
				"picture": map[string]any{},
			})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer mockFacebookServer.Close()

	originalTokenURL := facebookTokenURL
	originalUserURL := facebookUserURL
	facebookTokenURL = mockFacebookServer.URL + "/token"
	facebookUserURL = mockFacebookServer.URL + "/user"
	defer func() {
		facebookTokenURL = originalTokenURL
		facebookUserURL = originalUserURL
	}()

	accessToken, refreshToken, err := ExchangeFacebookCode("code-no-refresh", "http://localhost/callback")
	if err != nil {
		t.Fatalf("ExchangeFacebookCode failed: %v", err)
	}
	if accessToken != "token-no-refresh" {
		t.Fatalf("Expected access token 'token-no-refresh', got '%s'", accessToken)
	}
	if refreshToken != "" {
		t.Logf("Unexpected refresh token for Facebook: '%s'", refreshToken)
	}

	userInfo, err := GetFacebookUserInfo(accessToken)
	if err != nil {
		t.Fatalf("GetFacebookUserInfo failed: %v", err)
	}
	if userInfo.Email != "norefresh@facebook.com" {
		t.Fatalf("Unexpected email %s", userInfo.Email)
	}
}

// TestFacebookOAuth_ErrorHandling tests error scenarios in the full flow
func TestFacebookOAuth_ErrorHandling(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	// Setup test OAuth credentials
	os.Setenv("FACEBOOK_APP_ID", "test-app-id")
	os.Setenv("FACEBOOK_APP_SECRET", "test-app-secret")
	defer os.Unsetenv("FACEBOOK_APP_ID")
	defer os.Unsetenv("FACEBOOK_APP_SECRET")

	// Mock Facebook OAuth server with error responses
	mockFacebookServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/token-error":
			// Return error for token exchange
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"error": map[string]interface{}{
					"message": "Invalid verification code format.",
					"type":    "OAuthException",
					"code":    100,
				},
			})

		case "/user-error":
			// Return error for user info
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"error": map[string]interface{}{
					"message":    "Invalid OAuth access token.",
					"type":       "OAuthException",
					"code":       190,
					"fbtrace_id": "ABC123",
				},
			})

		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer mockFacebookServer.Close()

	// Test token exchange error
	t.Run("TokenExchangeError", func(t *testing.T) {
		originalTokenURL := facebookTokenURL
		facebookTokenURL = mockFacebookServer.URL + "/token-error"
		defer func() { facebookTokenURL = originalTokenURL }()

		_, _, err := ExchangeFacebookCode("invalid-code", "http://localhost:8080/callback")
		if err == nil {
			t.Error("Expected error for invalid code, got nil")
		}
	})

	// Test user info error
	t.Run("UserInfoError", func(t *testing.T) {
		originalUserURL := facebookUserURL
		facebookUserURL = mockFacebookServer.URL + "/user-error"
		defer func() { facebookUserURL = originalUserURL }()

		_, err := GetFacebookUserInfo("invalid-token")
		if err == nil {
			t.Error("Expected error for invalid token, got nil")
		}
	})
}

// TestFacebookOAuth_ConcurrentRequests tests concurrent OAuth requests
func TestFacebookOAuth_ConcurrentRequests(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	// Setup test OAuth credentials
	os.Setenv("FACEBOOK_APP_ID", "test-app-id")
	os.Setenv("FACEBOOK_APP_SECRET", "test-app-secret")
	defer os.Unsetenv("FACEBOOK_APP_ID")
	defer os.Unsetenv("FACEBOOK_APP_SECRET")

	requestCount := 0

	// Mock Facebook OAuth server
	mockFacebookServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount++
		switch r.URL.Path {
		case "/token":
			response := map[string]interface{}{
				"access_token": fmt.Sprintf("token-%d", requestCount),
				"token_type":   "bearer",
				"expires_in":   5183999,
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(response)

		case "/user":
			userInfo := map[string]interface{}{
				"id":      fmt.Sprintf("%d", requestCount),
				"email":   fmt.Sprintf("user%d@test.com", requestCount),
				"name":    fmt.Sprintf("User %d", requestCount),
				"picture": map[string]interface{}{},
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(userInfo)
		}
	}))
	defer mockFacebookServer.Close()

	// Override URLs for testing
	originalTokenURL := facebookTokenURL
	originalUserURL := facebookUserURL
	facebookTokenURL = mockFacebookServer.URL + "/token"
	facebookUserURL = mockFacebookServer.URL + "/user"
	defer func() {
		facebookTokenURL = originalTokenURL
		facebookUserURL = originalUserURL
	}()

	// Run concurrent requests
	concurrency := 10
	done := make(chan bool, concurrency)
	errors := make(chan error, concurrency)

	for i := 0; i < concurrency; i++ {
		go func(index int) {
			// Exchange code
			code := fmt.Sprintf("code-%d", index)
			accessToken, _, err := ExchangeFacebookCode(code, "http://localhost:8080/callback")
			if err != nil {
				errors <- fmt.Errorf("ExchangeFacebookCode failed for %d: %w", index, err)
				done <- false
				return
			}

			// Get user info
			_, err = GetFacebookUserInfo(accessToken)
			if err != nil {
				errors <- fmt.Errorf("GetFacebookUserInfo failed for %d: %w", index, err)
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

	t.Logf("Successfully completed %d concurrent Facebook OAuth requests", successCount)
}

// TestFacebookOAuth_RateLimiting tests behavior under rate limiting
func TestFacebookOAuth_RateLimiting(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	// Setup test OAuth credentials
	os.Setenv("FACEBOOK_APP_ID", "test-app-id")
	os.Setenv("FACEBOOK_APP_SECRET", "test-app-secret")
	defer os.Unsetenv("FACEBOOK_APP_ID")
	defer os.Unsetenv("FACEBOOK_APP_SECRET")

	requestCount := 0
	maxRequests := 5

	// Mock Facebook OAuth server with rate limiting
	mockFacebookServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount++

		if requestCount > maxRequests {
			w.WriteHeader(http.StatusTooManyRequests)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"error": map[string]interface{}{
					"message":    "(#4) Application request limit reached",
					"type":       "OAuthException",
					"code":       4,
					"fbtrace_id": "RATE123",
				},
			})
			return
		}

		switch r.URL.Path {
		case "/token":
			response := map[string]interface{}{
				"access_token": "token",
				"token_type":   "bearer",
				"expires_in":   5183999,
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(response)

		case "/user":
			userInfo := map[string]interface{}{
				"id":      "12345678901234567",
				"email":   "user@test.com",
				"name":    "Test User",
				"picture": map[string]interface{}{},
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(userInfo)
		}
	}))
	defer mockFacebookServer.Close()

	// Override URLs for testing
	originalTokenURL := facebookTokenURL
	facebookTokenURL = mockFacebookServer.URL + "/token"
	defer func() { facebookTokenURL = originalTokenURL }()

	// Make requests until rate limit
	successCount := 0
	rateLimitCount := 0

	for i := 0; i < maxRequests+3; i++ {
		_, _, err := ExchangeFacebookCode(fmt.Sprintf("code-%d", i), "http://localhost:8080/callback")
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

// TestFacebookOAuth_PrivateEmail tests handling of private email
func TestFacebookOAuth_PrivateEmail(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	os.Setenv("FACEBOOK_APP_ID", "private-email-app-id")
	os.Setenv("FACEBOOK_APP_SECRET", "private-email-app-secret")
	defer os.Unsetenv("FACEBOOK_APP_ID")
	defer os.Unsetenv("FACEBOOK_APP_SECRET")

	mockFacebookServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/token":
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]any{
				"access_token": "private-email-token",
				"token_type":   "bearer",
			})
		case "/user":
			// User has private email (not shared with app)
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]any{
				"id":      "998877665544332211",
				"name":    "Private Email User",
				"picture": map[string]any{},
				// No email field - user didn't grant email permission
			})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer mockFacebookServer.Close()

	originalTokenURL := facebookTokenURL
	originalUserURL := facebookUserURL
	facebookTokenURL = mockFacebookServer.URL + "/token"
	facebookUserURL = mockFacebookServer.URL + "/user"
	defer func() {
		facebookTokenURL = originalTokenURL
		facebookUserURL = originalUserURL
	}()

	accessToken, _, err := ExchangeFacebookCode("private-code", "http://localhost/callback")
	if err != nil {
		t.Fatalf("ExchangeFacebookCode failed: %v", err)
	}

	userInfo, err := GetFacebookUserInfo(accessToken)
	if err != nil {
		t.Fatalf("GetFacebookUserInfo failed: %v", err)
	}

	if userInfo.Email != "" {
		t.Errorf("Expected empty email for private user, got '%s'", userInfo.Email)
	}
	if userInfo.Name != "Private Email User" {
		t.Errorf("Expected name 'Private Email User', got '%s'", userInfo.Name)
	}
}
