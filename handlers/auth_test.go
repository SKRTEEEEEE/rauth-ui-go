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

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// setupTestApp creates a Fiber app for testing
func setupTestApp() *fiber.App {
	app := fiber.New()
	app.Get("/api/v1/oauth/authorize", OAuthAuthorize)
	app.Get("/api/v1/oauth/callback/:provider", OAuthCallback)
	return app
}

// Test generateStateToken
func TestGenerateStateToken(t *testing.T) {
	token1 := generateStateToken()
	token2 := generateStateToken()

	// Should generate different tokens
	assert.NotEqual(t, token1, token2)

	// Should be 64 characters (32 bytes hex encoded)
	assert.Equal(t, 64, len(token1))
	assert.Equal(t, 64, len(token2))

	// Should be valid hex
	assert.Regexp(t, "^[0-9a-f]{64}$", token1)
	assert.Regexp(t, "^[0-9a-f]{64}$", token2)
}

// Test OAuthAuthorize - Missing parameters
func TestOAuthAuthorize_MissingParameters(t *testing.T) {
	app := setupTestApp()

	tests := []struct {
		name        string
		queryParams string
		expectError string
	}{
		{
			name:        "No parameters",
			queryParams: "",
			expectError: "Missing required parameters",
		},
		{
			name:        "Missing provider",
			queryParams: "?app_id=123&redirect_uri=http://localhost",
			expectError: "Missing required parameters",
		},
		{
			name:        "Missing app_id",
			queryParams: "?provider=google&redirect_uri=http://localhost",
			expectError: "Missing required parameters",
		},
		{
			name:        "Missing redirect_uri",
			queryParams: "?provider=google&app_id=123",
			expectError: "Missing required parameters",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/api/v1/oauth/authorize"+tt.queryParams, nil)
			resp, err := app.Test(req)
			require.NoError(t, err)

			assert.Equal(t, fiber.StatusBadRequest, resp.StatusCode)

			body, _ := io.ReadAll(resp.Body)
			assert.Contains(t, string(body), tt.expectError)
		})
	}
}

// Test OAuthAuthorize - Invalid provider
func TestOAuthAuthorize_InvalidProvider(t *testing.T) {
	app := setupTestApp()

	req := httptest.NewRequest("GET",
		"/api/v1/oauth/authorize?provider=invalid&app_id="+uuid.New().String()+"&redirect_uri=http://localhost",
		nil)
	resp, err := app.Test(req)
	require.NoError(t, err)

	assert.Equal(t, fiber.StatusBadRequest, resp.StatusCode)

	body, _ := io.ReadAll(resp.Body)
	assert.Contains(t, string(body), "Invalid provider")
}

// Test OAuthAuthorize - Invalid app_id format
func TestOAuthAuthorize_InvalidAppID(t *testing.T) {
	app := setupTestApp()

	req := httptest.NewRequest("GET",
		"/api/v1/oauth/authorize?provider=google&app_id=not-a-uuid&redirect_uri=http://localhost",
		nil)
	resp, err := app.Test(req)
	require.NoError(t, err)

	assert.Equal(t, fiber.StatusBadRequest, resp.StatusCode)

	body, _ := io.ReadAll(resp.Body)
	assert.Contains(t, string(body), "Invalid app_id")
}

// Test OAuthAuthorize - App not found
func TestOAuthAuthorize_AppNotFound(t *testing.T) {
	if os.Getenv("INTEGRATION_TEST") != "true" {
		t.Skip("Skipping integration test")
	}

	app := setupTestApp()

	// Use a valid UUID that doesn't exist in the database
	nonExistentAppID := uuid.New().String()

	req := httptest.NewRequest("GET",
		fmt.Sprintf("/api/v1/oauth/authorize?provider=google&app_id=%s&redirect_uri=http://localhost", nonExistentAppID),
		nil)
	resp, err := app.Test(req, -1) // -1 means no timeout
	require.NoError(t, err)

	assert.Equal(t, fiber.StatusNotFound, resp.StatusCode)

	body, _ := io.ReadAll(resp.Body)
	assert.Contains(t, string(body), "not found")
}

// Test OAuthAuthorize - Provider not enabled
func TestOAuthAuthorize_ProviderNotEnabled(t *testing.T) {
	if os.Getenv("INTEGRATION_TEST") != "true" {
		t.Skip("Skipping integration test")
	}

	app := setupTestApp()
	ctx := context.Background()

	// Create test application
	appID := uuid.New()
	_, err := database.DB.Exec(ctx,
		"INSERT INTO applications (id, name, api_key, allowed_redirect_uris, cors_origins) VALUES ($1, $2, $3, $4, $5)",
		appID, "Test App", "test-key-"+uuid.New().String(), []string{"http://localhost"}, []string{"*"})
	require.NoError(t, err)

	// Create OAuth provider entry but set enabled = false
	_, err = database.DB.Exec(ctx,
		"INSERT INTO oauth_providers (app_id, provider, enabled) VALUES ($1, $2, $3)",
		appID, models.ProviderGoogle, false)
	require.NoError(t, err)

	// Cleanup
	defer func() {
		database.DB.Exec(ctx, "DELETE FROM oauth_providers WHERE app_id = $1", appID)
		database.DB.Exec(ctx, "DELETE FROM applications WHERE id = $1", appID)
	}()

	req := httptest.NewRequest("GET",
		fmt.Sprintf("/api/v1/oauth/authorize?provider=google&app_id=%s&redirect_uri=http://localhost", appID),
		nil)
	resp, err := app.Test(req, -1)
	require.NoError(t, err)

	assert.Equal(t, fiber.StatusForbidden, resp.StatusCode)

	body, _ := io.ReadAll(resp.Body)
	assert.Contains(t, string(body), "not enabled")
}

// Test OAuthAuthorize - Successful flow
func TestOAuthAuthorize_Success(t *testing.T) {
	if os.Getenv("INTEGRATION_TEST") != "true" {
		t.Skip("Skipping integration test")
	}

	app := setupTestApp()
	ctx := context.Background()

	// Create test application
	appID := uuid.New()
	_, err := database.DB.Exec(ctx,
		"INSERT INTO applications (id, name, api_key, allowed_redirect_uris, cors_origins) VALUES ($1, $2, $3, $4, $5)",
		appID, "Test App", "test-key-"+uuid.New().String(), []string{"http://localhost"}, []string{"*"})
	require.NoError(t, err)

	// Create OAuth provider entry with enabled = true
	_, err = database.DB.Exec(ctx,
		"INSERT INTO oauth_providers (app_id, provider, enabled) VALUES ($1, $2, $3)",
		appID, models.ProviderGoogle, true)
	require.NoError(t, err)

	// Cleanup
	defer func() {
		database.DB.Exec(ctx, "DELETE FROM oauth_providers WHERE app_id = $1", appID)
		database.DB.Exec(ctx, "DELETE FROM applications WHERE id = $1", appID)
	}()

	req := httptest.NewRequest("GET",
		fmt.Sprintf("/api/v1/oauth/authorize?provider=google&app_id=%s&redirect_uri=http://localhost/callback", appID),
		nil)
	resp, err := app.Test(req, -1)
	require.NoError(t, err)

	// Should redirect (307) to Google
	assert.Equal(t, fiber.StatusTemporaryRedirect, resp.StatusCode)

	// Check Location header
	location := resp.Header.Get("Location")
	assert.Contains(t, location, "accounts.google.com/o/oauth2/v2/auth")
	assert.Contains(t, location, "state=")
	assert.Contains(t, location, "client_id=")
}

// Test OAuthCallback - Missing parameters
func TestOAuthCallback_MissingParameters(t *testing.T) {
	app := setupTestApp()

	tests := []struct {
		name        string
		queryParams string
	}{
		{
			name:        "No parameters",
			queryParams: "",
		},
		{
			name:        "Missing code",
			queryParams: "?state=test-state",
		},
		{
			name:        "Missing state",
			queryParams: "?code=test-code",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/api/v1/oauth/callback/google"+tt.queryParams, nil)
			resp, err := app.Test(req)
			require.NoError(t, err)

			assert.Equal(t, fiber.StatusBadRequest, resp.StatusCode)

			body, _ := io.ReadAll(resp.Body)
			assert.Contains(t, string(body), "Missing code or state")
		})
	}
}

// Test OAuthCallback - Invalid state
func TestOAuthCallback_InvalidState(t *testing.T) {
	if os.Getenv("INTEGRATION_TEST") != "true" {
		t.Skip("Skipping integration test")
	}

	app := setupTestApp()

	req := httptest.NewRequest("GET",
		"/api/v1/oauth/callback/google?code=test-code&state=invalid-state",
		nil)
	resp, err := app.Test(req, -1)
	require.NoError(t, err)

	assert.Equal(t, fiber.StatusBadRequest, resp.StatusCode)

	body, _ := io.ReadAll(resp.Body)
	assert.Contains(t, string(body), "Invalid or expired state")
}

// Test findOrCreateUser - Create new user
func TestFindOrCreateUser_CreateNew(t *testing.T) {
	if os.Getenv("INTEGRATION_TEST") != "true" {
		t.Skip("Skipping integration test")
	}

	// Initialize database connection
	if err := database.Connect(); err != nil {
		t.Fatalf("Failed to connect to database: %v", err)
	}

	ctx := context.Background()
	appID := uuid.New()

	// Create test application
	_, err := database.DB.Exec(ctx,
		"INSERT INTO applications (id, name, api_key, allowed_redirect_uris, cors_origins) VALUES ($1, $2, $3, $4, $5)",
		appID, "Test App", "test-key-"+uuid.New().String(), []string{"http://localhost"}, []string{"*"})
	require.NoError(t, err)

	// Cleanup
	defer func() {
		database.DB.Exec(ctx, "DELETE FROM identities WHERE provider = $1 AND provider_user_id = $2",
			models.ProviderGoogle, "test-user-123")
		database.DB.Exec(ctx, "DELETE FROM users WHERE app_id = $1", appID)
		database.DB.Exec(ctx, "DELETE FROM applications WHERE id = $1", appID)
	}()

	userInfo := &models.OAuthUserInfo{
		ProviderUserID: "test-user-123",
		Email:          "test@example.com",
		Name:           "Test User",
		AvatarURL:      "https://example.com/avatar.jpg",
		EmailVerified:  true,
	}

	userID, err := findOrCreateUser(ctx, appID, models.ProviderGoogle, userInfo, "access-token", "refresh-token")
	require.NoError(t, err)
	assert.NotEqual(t, uuid.Nil, userID)

	// Verify user was created
	var email string
	err = database.DB.QueryRow(ctx, "SELECT email FROM users WHERE id = $1", userID).Scan(&email)
	require.NoError(t, err)
	assert.Equal(t, "test@example.com", email)

	// Verify identity was created
	var providerUserID string
	err = database.DB.QueryRow(ctx, "SELECT provider_user_id FROM identities WHERE user_id = $1", userID).Scan(&providerUserID)
	require.NoError(t, err)
	assert.Equal(t, "test-user-123", providerUserID)
}

// Test findOrCreateUser - Existing user
func TestFindOrCreateUser_ExistingUser(t *testing.T) {
	if os.Getenv("INTEGRATION_TEST") != "true" {
		t.Skip("Skipping integration test")
	}

	// Initialize database connection
	if err := database.Connect(); err != nil {
		t.Fatalf("Failed to connect to database: %v", err)
	}

	ctx := context.Background()
	appID := uuid.New()
	userID := uuid.New()

	// Create test application
	_, err := database.DB.Exec(ctx,
		"INSERT INTO applications (id, name, api_key, allowed_redirect_uris, cors_origins) VALUES ($1, $2, $3, $4, $5)",
		appID, "Test App", "test-key-"+uuid.New().String(), []string{"http://localhost"}, []string{"*"})
	require.NoError(t, err)

	// Create existing user
	_, err = database.DB.Exec(ctx,
		"INSERT INTO users (id, app_id, email, name, avatar_url, email_verified) VALUES ($1, $2, $3, $4, $5, $6)",
		userID, appID, "existing@example.com", "Existing User", "", true)
	require.NoError(t, err)

	// Create existing identity
	_, err = database.DB.Exec(ctx,
		"INSERT INTO identities (user_id, provider, provider_user_id, provider_email, access_token, refresh_token) VALUES ($1, $2, $3, $4, $5, $6)",
		userID, models.ProviderGoogle, "existing-user-456", "existing@example.com", "old-token", "old-refresh")
	require.NoError(t, err)

	// Cleanup
	defer func() {
		database.DB.Exec(ctx, "DELETE FROM identities WHERE user_id = $1", userID)
		database.DB.Exec(ctx, "DELETE FROM users WHERE id = $1", userID)
		database.DB.Exec(ctx, "DELETE FROM applications WHERE id = $1", appID)
	}()

	userInfo := &models.OAuthUserInfo{
		ProviderUserID: "existing-user-456",
		Email:          "existing@example.com",
		Name:           "Existing User",
		AvatarURL:      "https://example.com/avatar.jpg",
		EmailVerified:  true,
	}

	returnedUserID, err := findOrCreateUser(ctx, appID, models.ProviderGoogle, userInfo, "new-access-token", "new-refresh-token")
	require.NoError(t, err)
	assert.Equal(t, userID, returnedUserID)

	// Verify tokens were updated
	var accessToken string
	err = database.DB.QueryRow(ctx, "SELECT access_token FROM identities WHERE user_id = $1", userID).Scan(&accessToken)
	require.NoError(t, err)
	assert.Equal(t, "new-access-token", accessToken)
}

// Benchmark generateStateToken
func BenchmarkGenerateStateToken(b *testing.B) {
	for i := 0; i < b.N; i++ {
		generateStateToken()
	}
}
