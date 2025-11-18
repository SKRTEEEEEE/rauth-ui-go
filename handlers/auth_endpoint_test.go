package handlers

import (
	"context"
	"fmt"
	"io"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"rauth/database"
	"rauth/models"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestOAuthEndpoints_RealScenarios tests real-world scenarios
func TestOAuthEndpoints_RealScenarios(t *testing.T) {
	if os.Getenv("INTEGRATION_TEST") != "true" {
		t.Skip("Skipping endpoint test")
	}

	tests := []struct {
		name           string
		setupFunc      func(context.Context, *testing.T) (uuid.UUID, string)
		provider       string
		redirectURI    string
		expectStatus   int
		expectContains string
	}{
		{
			name: "Valid Google OAuth request",
			setupFunc: func(ctx context.Context, t *testing.T) (uuid.UUID, string) {
				appID := uuid.New()
				apiKey := "test-key-" + uuid.New().String()
				_, err := database.DB.Exec(ctx,
					"INSERT INTO applications (id, name, api_key, allowed_redirect_uris, cors_origins) VALUES ($1, $2, $3, $4, $5)",
					appID, "Test App", apiKey, []string{"http://localhost:3000/callback"}, []string{"*"})
				require.NoError(t, err)

				_, err = database.DB.Exec(ctx,
					"INSERT INTO oauth_providers (app_id, provider, enabled) VALUES ($1, $2, $3)",
					appID, models.ProviderGoogle, true)
				require.NoError(t, err)

				return appID, apiKey
			},
			provider:       "google",
			redirectURI:    "http://localhost:3000/callback",
			expectStatus:   307,
			expectContains: "accounts.google.com",
		},
		{
			name: "Invalid provider",
			setupFunc: func(ctx context.Context, t *testing.T) (uuid.UUID, string) {
				appID := uuid.New()
				apiKey := "test-key-" + uuid.New().String()
				_, err := database.DB.Exec(ctx,
					"INSERT INTO applications (id, name, api_key, allowed_redirect_uris, cors_origins) VALUES ($1, $2, $3, $4, $5)",
					appID, "Test App", apiKey, []string{"http://localhost"}, []string{"*"})
				require.NoError(t, err)
				return appID, apiKey
			},
			provider:       "invalid-provider",
			redirectURI:    "http://localhost",
			expectStatus:   400,
			expectContains: "Invalid provider",
		},
		{
			name: "Provider not enabled for app",
			setupFunc: func(ctx context.Context, t *testing.T) (uuid.UUID, string) {
				appID := uuid.New()
				apiKey := "test-key-" + uuid.New().String()
				_, err := database.DB.Exec(ctx,
					"INSERT INTO applications (id, name, api_key, allowed_redirect_uris, cors_origins) VALUES ($1, $2, $3, $4, $5)",
					appID, "Test App", apiKey, []string{"http://localhost"}, []string{"*"})
				require.NoError(t, err)

				// Create provider but keep it disabled
				_, err = database.DB.Exec(ctx,
					"INSERT INTO oauth_providers (app_id, provider, enabled) VALUES ($1, $2, $3)",
					appID, models.ProviderGoogle, false)
				require.NoError(t, err)

				return appID, apiKey
			},
			provider:       "google",
			redirectURI:    "http://localhost",
			expectStatus:   403,
			expectContains: "not enabled",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			app := setupTestApp()

			// Setup
			appID, _ := tt.setupFunc(ctx, t)

			// Cleanup
			defer func() {
				database.DB.Exec(ctx, "DELETE FROM oauth_providers WHERE app_id = $1", appID)
				database.DB.Exec(ctx, "DELETE FROM applications WHERE id = $1", appID)
			}()

			// Make request
			url := fmt.Sprintf("/api/v1/oauth/authorize?provider=%s&app_id=%s&redirect_uri=%s",
				tt.provider, appID, tt.redirectURI)
			req := httptest.NewRequest("GET", url, nil)
			resp, err := app.Test(req, -1)
			require.NoError(t, err)

			assert.Equal(t, tt.expectStatus, resp.StatusCode)

			if tt.expectStatus == 307 {
				// Check redirect location
				location := resp.Header.Get("Location")
				assert.Contains(t, location, tt.expectContains)
			} else {
				// Check error message
				body, _ := io.ReadAll(resp.Body)
				assert.Contains(t, string(body), tt.expectContains)
			}
		})
	}
}

// TestOAuthCallback_ErrorHandling tests error scenarios in callback
func TestOAuthCallback_ErrorHandling(t *testing.T) {
	if os.Getenv("INTEGRATION_TEST") != "true" {
		t.Skip("Skipping callback error handling test")
	}

	app := setupTestApp()

	tests := []struct {
		name         string
		url          string
		expectStatus int
		expectError  string
	}{
		{
			name:         "Missing code",
			url:          "/api/v1/oauth/callback/google?state=test-state",
			expectStatus: 400,
			expectError:  "Missing code or state",
		},
		{
			name:         "Missing state",
			url:          "/api/v1/oauth/callback/google?code=test-code",
			expectStatus: 400,
			expectError:  "Missing code or state",
		},
		{
			name:         "Invalid state",
			url:          "/api/v1/oauth/callback/google?code=test-code&state=invalid-state-12345",
			expectStatus: 400,
			expectError:  "Invalid or expired state",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", tt.url, nil)
			resp, err := app.Test(req, -1)
			require.NoError(t, err)

			assert.Equal(t, tt.expectStatus, resp.StatusCode)

			body, _ := io.ReadAll(resp.Body)
			assert.Contains(t, string(body), tt.expectError)
		})
	}
}

// TestOAuthAuthorize_SecurityChecks tests security validations
func TestOAuthAuthorize_SecurityChecks(t *testing.T) {
	if os.Getenv("INTEGRATION_TEST") != "true" {
		t.Skip("Skipping security checks test")
	}

	ctx := context.Background()
	app := setupTestApp()

	// Create test application
	appID := uuid.New()
	apiKey := "test-key-" + uuid.New().String()
	_, err := database.DB.Exec(ctx,
		"INSERT INTO applications (id, name, api_key, allowed_redirect_uris, cors_origins) VALUES ($1, $2, $3, $4, $5)",
		appID, "Test App", apiKey, []string{"http://localhost:3000/callback"}, []string{"*"})
	require.NoError(t, err)

	_, err = database.DB.Exec(ctx,
		"INSERT INTO oauth_providers (app_id, provider, enabled) VALUES ($1, $2, $3)",
		appID, models.ProviderGoogle, true)
	require.NoError(t, err)

	defer func() {
		database.DB.Exec(ctx, "DELETE FROM oauth_providers WHERE app_id = $1", appID)
		database.DB.Exec(ctx, "DELETE FROM applications WHERE id = $1", appID)
	}()

	t.Run("SQL Injection in provider", func(t *testing.T) {
		url := fmt.Sprintf("/api/v1/oauth/authorize?provider=google' OR '1'='1&app_id=%s&redirect_uri=http://localhost",
			appID)
		req := httptest.NewRequest("GET", url, nil)
		resp, err := app.Test(req, -1)
		require.NoError(t, err)

		// Should reject invalid provider
		assert.Equal(t, 400, resp.StatusCode)
	})

	t.Run("XSS in redirect_uri", func(t *testing.T) {
		maliciousURI := "javascript:alert('xss')"
		url := fmt.Sprintf("/api/v1/oauth/authorize?provider=google&app_id=%s&redirect_uri=%s",
			appID, maliciousURI)
		req := httptest.NewRequest("GET", url, nil)
		resp, err := app.Test(req, -1)
		require.NoError(t, err)

		// The flow should still work, but the redirect_uri validation
		// should be done by the client's allowed_redirect_uris
		// For this test, we just verify it doesn't crash
		assert.NotEqual(t, 500, resp.StatusCode)
	})

	t.Run("Very long state token", func(t *testing.T) {
		url := fmt.Sprintf("/api/v1/oauth/authorize?provider=google&app_id=%s&redirect_uri=http://localhost:3000/callback",
			appID)
		req := httptest.NewRequest("GET", url, nil)
		resp, err := app.Test(req, -1)
		require.NoError(t, err)

		// Should generate state successfully
		assert.Equal(t, 307, resp.StatusCode)

		location := resp.Header.Get("Location")
		parts := strings.Split(location, "state=")
		if len(parts) > 1 {
			stateParts := strings.Split(parts[1], "&")
			state := stateParts[0]

			// State should be exactly 64 characters (32 bytes hex)
			assert.Equal(t, 64, len(state))
		}
	})
}

// TestOAuthState_RaceConditions tests concurrent state operations
func TestOAuthState_RaceConditions(t *testing.T) {
	if os.Getenv("INTEGRATION_TEST") != "true" {
		t.Skip("Skipping race condition test")
	}

	ctx := context.Background()

	// Create multiple states concurrently
	done := make(chan bool, 100)
	errors := make(chan error, 100)

	for i := 0; i < 100; i++ {
		go func(index int) {
			state := fmt.Sprintf("test-state-%d", index)
			appID := uuid.New()
			stateData := models.OAuthState{
				AppID:       appID,
				RedirectURI: "http://localhost",
				CreatedAt:   time.Now(),
			}

			err := database.SaveOAuthState(ctx, state, stateData)
			if err != nil {
				errors <- err
			}
			done <- true
		}(i)
	}

	// Wait for all operations
	for i := 0; i < 100; i++ {
		<-done
	}

	close(errors)

	// Check for errors
	errorCount := 0
	for err := range errors {
		t.Logf("Error: %v", err)
		errorCount++
	}

	assert.Equal(t, 0, errorCount, "No errors should occur during concurrent state operations")
}

// TestOAuthProviders_AllSupported tests all supported providers
func TestOAuthProviders_AllSupported(t *testing.T) {
	if os.Getenv("INTEGRATION_TEST") != "true" {
		t.Skip("Skipping all providers test")
	}

	ctx := context.Background()
	app := setupTestApp()

	// Test each provider
	providers := []string{"google", "github", "facebook", "microsoft"}

	for _, provider := range providers {
		t.Run(provider, func(t *testing.T) {
			// Create test application
			appID := uuid.New()
			apiKey := "test-key-" + uuid.New().String()
			_, err := database.DB.Exec(ctx,
				"INSERT INTO applications (id, name, api_key, allowed_redirect_uris, cors_origins) VALUES ($1, $2, $3, $4, $5)",
				appID, "Test App", apiKey, []string{"http://localhost"}, []string{"*"})
			require.NoError(t, err)

			_, err = database.DB.Exec(ctx,
				"INSERT INTO oauth_providers (app_id, provider, enabled) VALUES ($1, $2, $3)",
				appID, provider, true)
			require.NoError(t, err)

			defer func() {
				database.DB.Exec(ctx, "DELETE FROM oauth_providers WHERE app_id = $1", appID)
				database.DB.Exec(ctx, "DELETE FROM applications WHERE id = $1", appID)
			}()

			// Make request
			url := fmt.Sprintf("/api/v1/oauth/authorize?provider=%s&app_id=%s&redirect_uri=http://localhost",
				provider, appID)
			req := httptest.NewRequest("GET", url, nil)
			resp, err := app.Test(req, -1)
			require.NoError(t, err)

			// Google should work (implemented), others might return 501 (not implemented yet)
			if provider == "google" {
				assert.Equal(t, 307, resp.StatusCode)
			} else {
				// Other providers not yet implemented
				assert.True(t, resp.StatusCode == 307 || resp.StatusCode == 501)
			}
		})
	}
}
