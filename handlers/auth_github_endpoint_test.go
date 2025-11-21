package handlers

import (
	"context"
	"fmt"
	"io"
	"net/http/httptest"
	"os"
	"testing"

	"rauth/database"
	"rauth/models"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestGitHubOAuthEndpoints_RealScenarios tests real-world scenarios for GitHub OAuth
func TestGitHubOAuthEndpoints_RealScenarios(t *testing.T) {
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
			name: "Valid GitHub OAuth request",
			setupFunc: func(ctx context.Context, t *testing.T) (uuid.UUID, string) {
				appID := uuid.New()
				apiKey := "test-key-" + uuid.New().String()
				_, err := database.DB.Exec(ctx,
					"INSERT INTO applications (id, name, api_key, allowed_redirect_uris, cors_origins) VALUES ($1, $2, $3, $4, $5)",
					appID, "Test App", apiKey, []string{"http://localhost:3000/callback"}, []string{"*"})
				require.NoError(t, err)

				_, err = database.DB.Exec(ctx,
					"INSERT INTO oauth_providers (app_id, provider, enabled) VALUES ($1, $2, $3)",
					appID, models.ProviderGitHub, true)
				require.NoError(t, err)

				return appID, apiKey
			},
			provider:       "github",
			redirectURI:    "http://localhost:3000/callback",
			expectStatus:   307,
			expectContains: "github.com",
		},
		{
			name: "GitHub OAuth provider not enabled for app",
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
					appID, models.ProviderGitHub, false)
				require.NoError(t, err)

				return appID, apiKey
			},
			provider:       "github",
			redirectURI:    "http://localhost",
			expectStatus:   403,
			expectContains: "not enabled",
		},
		{
			name: "GitHub OAuth provider not found for app",
			setupFunc: func(ctx context.Context, t *testing.T) (uuid.UUID, string) {
				appID := uuid.New()
				apiKey := "test-key-" + uuid.New().String()
				_, err := database.DB.Exec(ctx,
					"INSERT INTO applications (id, name, api_key, allowed_redirect_uris, cors_origins) VALUES ($1, $2, $3, $4, $5)",
					appID, "Test App", apiKey, []string{"http://localhost"}, []string{"*"})
				require.NoError(t, err)

				// Don't create any oauth provider for github
				return appID, apiKey
			},
			provider:       "github",
			redirectURI:    "http://localhost",
			expectStatus:   404,
			expectContains: "not found",
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

// TestGitHubOAuthCallback_ErrorHandling tests error scenarios in callback for GitHub
func TestGitHubOAuthCallback_ErrorHandling(t *testing.T) {
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
			name:         "Missing code for GitHub",
			url:          "/api/v1/oauth/callback/github?state=test-state",
			expectStatus: 400,
			expectError:  "Missing code or state",
		},
		{
			name:         "Missing state for GitHub",
			url:          "/api/v1/oauth/callback/github?code=test-code",
			expectStatus: 400,
			expectError:  "Missing code or state",
		},
		{
			name:         "Invalid state for GitHub",
			url:          "/api/v1/oauth/callback/github?code=test-code&state=invalid-state-12345",
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

// TestGitHubOAuthAuthorize_URLConstruction tests that GitHub auth URL is constructed correctly
func TestGitHubOAuthAuthorize_URLConstruction(t *testing.T) {
	if os.Getenv("INTEGRATION_TEST") != "true" {
		t.Skip("Skipping URL construction test")
	}

	ctx := context.Background()
	app := setupTestApp()

	// Set GitHub credentials
	os.Setenv("GITHUB_CLIENT_ID", "test-github-client-id")
	defer os.Unsetenv("GITHUB_CLIENT_ID")

	// Create test application with GitHub enabled
	appID := uuid.New()
	apiKey := "test-key-" + uuid.New().String()
	_, err := database.DB.Exec(ctx,
		"INSERT INTO applications (id, name, api_key, allowed_redirect_uris, cors_origins) VALUES ($1, $2, $3, $4, $5)",
		appID, "Test App", apiKey, []string{"http://localhost:3000/callback"}, []string{"*"})
	require.NoError(t, err)

	_, err = database.DB.Exec(ctx,
		"INSERT INTO oauth_providers (app_id, provider, enabled) VALUES ($1, $2, $3)",
		appID, models.ProviderGitHub, true)
	require.NoError(t, err)

	defer func() {
		database.DB.Exec(ctx, "DELETE FROM oauth_providers WHERE app_id = $1", appID)
		database.DB.Exec(ctx, "DELETE FROM applications WHERE id = $1", appID)
	}()

	// Make request
	url := fmt.Sprintf("/api/v1/oauth/authorize?provider=github&app_id=%s&redirect_uri=http://localhost:3000/callback",
		appID)
	req := httptest.NewRequest("GET", url, nil)
	resp, err := app.Test(req, -1)
	require.NoError(t, err)

	// Should redirect
	assert.Equal(t, 307, resp.StatusCode)

	// Check redirect location
	location := resp.Header.Get("Location")
	assert.Contains(t, location, "https://github.com/login/oauth/authorize")
	assert.Contains(t, location, "client_id=test-github-client-id")
	assert.Contains(t, location, "scope=user:email")
	assert.Contains(t, location, "state=")
}

// TestGitHubOAuthAuthorize_InvalidAppID validates error handling for malformed app IDs
func TestGitHubOAuthAuthorize_InvalidAppID(t *testing.T) {
	if os.Getenv("INTEGRATION_TEST") != "true" {
		t.Skip("Skipping invalid app_id test")
	}

	app := setupTestApp()
	req := httptest.NewRequest("GET",
		"/api/v1/oauth/authorize?provider=github&app_id=not-a-valid-uuid&redirect_uri=http://localhost",
		nil)
	resp, err := app.Test(req, -1)
	require.NoError(t, err)

	assert.Equal(t, 400, resp.StatusCode)
	body, _ := io.ReadAll(resp.Body)
	assert.Contains(t, string(body), "Invalid app_id")
}

// TestGitHubOAuth_ProviderSpecificBehavior tests GitHub-specific OAuth behavior
func TestGitHubOAuth_ProviderSpecificBehavior(t *testing.T) {
	if os.Getenv("INTEGRATION_TEST") != "true" {
		t.Skip("Skipping provider-specific test")
	}

	ctx := context.Background()
	app := setupTestApp()

	// Set GitHub credentials
	os.Setenv("GITHUB_CLIENT_ID", "test-github-client-id")
	defer os.Unsetenv("GITHUB_CLIENT_ID")

	// Create test application
	appID := uuid.New()
	apiKey := "test-key-" + uuid.New().String()
	_, err := database.DB.Exec(ctx,
		"INSERT INTO applications (id, name, api_key, allowed_redirect_uris, cors_origins) VALUES ($1, $2, $3, $4, $5)",
		appID, "Test App", apiKey, []string{"http://localhost:3000/callback"}, []string{"*"})
	require.NoError(t, err)

	// Enable both Google and GitHub
	_, err = database.DB.Exec(ctx,
		"INSERT INTO oauth_providers (app_id, provider, enabled) VALUES ($1, $2, $3)",
		appID, models.ProviderGoogle, true)
	require.NoError(t, err)

	_, err = database.DB.Exec(ctx,
		"INSERT INTO oauth_providers (app_id, provider, enabled) VALUES ($1, $2, $3)",
		appID, models.ProviderGitHub, true)
	require.NoError(t, err)

	defer func() {
		database.DB.Exec(ctx, "DELETE FROM oauth_providers WHERE app_id = $1", appID)
		database.DB.Exec(ctx, "DELETE FROM applications WHERE id = $1", appID)
	}()

	t.Run("GitHub redirects to GitHub", func(t *testing.T) {
		url := fmt.Sprintf("/api/v1/oauth/authorize?provider=github&app_id=%s&redirect_uri=http://localhost:3000/callback",
			appID)
		req := httptest.NewRequest("GET", url, nil)
		resp, err := app.Test(req, -1)
		require.NoError(t, err)

		assert.Equal(t, 307, resp.StatusCode)
		location := resp.Header.Get("Location")
		assert.Contains(t, location, "github.com")
		assert.NotContains(t, location, "google.com")
	})

	t.Run("Google redirects to Google", func(t *testing.T) {
		url := fmt.Sprintf("/api/v1/oauth/authorize?provider=google&app_id=%s&redirect_uri=http://localhost:3000/callback",
			appID)
		req := httptest.NewRequest("GET", url, nil)
		resp, err := app.Test(req, -1)
		require.NoError(t, err)

		assert.Equal(t, 307, resp.StatusCode)
		location := resp.Header.Get("Location")
		assert.Contains(t, location, "google.com")
		assert.NotContains(t, location, "github.com")
	})
}
