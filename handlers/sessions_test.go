package handlers

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"testing"
	"time"

	"rauth/database"
	"rauth/models"
	"rauth/utils"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// setupSessionTestData creates test app, user and session for testing session endpoints
func setupSessionTestData(t *testing.T) (uuid.UUID, uuid.UUID, uuid.UUID, string, func()) {
	ctx := context.Background()

	// Create test application
	var appID uuid.UUID
	err := database.DB.QueryRow(ctx,
		`INSERT INTO applications (name, api_key, allowed_redirect_uris, cors_origins)
		 VALUES ($1, $2, $3, $4) RETURNING id`,
		"Test App for Sessions",
		generateAPIKey(),
		[]string{"http://localhost:3000/callback"},
		[]string{"http://localhost:3000"},
	).Scan(&appID)
	require.NoError(t, err)

	// Create test user
	var userID uuid.UUID
	email := "sessionuser@example.com"
	name := "Session Test User"
	err = database.DB.QueryRow(ctx,
		`INSERT INTO users (app_id, email, name, avatar_url, email_verified)
		 VALUES ($1, $2, $3, $4, $5) RETURNING id`,
		appID,
		email,
		name,
		"https://example.com/avatar.jpg",
		true,
	).Scan(&userID)
	require.NoError(t, err)

	// Generate JWT token
	sessionID := uuid.New()
	token, err := utils.GenerateJWT(userID, appID, sessionID, email)
	require.NoError(t, err)

	// Create session in database
	tokenHash := utils.HashToken(token)
	expiresAt := time.Now().Add(24 * time.Hour)
	ipAddress := "192.168.1.1"
	userAgent := "TestAgent/1.0"
	_, err = database.DB.Exec(ctx,
		`INSERT INTO sessions (id, user_id, app_id, token_hash, ip_address, user_agent, expires_at, last_used_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, NOW())`,
		sessionID,
		userID,
		appID,
		tokenHash,
		ipAddress,
		userAgent,
		expiresAt,
	)
	require.NoError(t, err)

	cleanup := func() {
		database.DB.Exec(ctx, "DELETE FROM sessions WHERE user_id = $1", userID)
		database.DB.Exec(ctx, "DELETE FROM users WHERE id = $1", userID)
		database.DB.Exec(ctx, "DELETE FROM applications WHERE id = $1", appID)
	}

	return appID, userID, sessionID, token, cleanup
}

// TestValidateSession tests the ValidateSession handler
func TestValidateSession(t *testing.T) {
	if err := database.Connect(); err != nil {
		t.Skipf("Skipping test: database not available: %v", err)
	}
	defer database.Close()

	_, userID, sessionID, token, cleanup := setupSessionTestData(t)
	defer cleanup()

	app := setupTestAppWithAuthMiddleware()
	app.Post("/sessions/validate", ValidateSession)

	tests := []struct {
		name           string
		token          string
		expectedStatus int
		checkResponse  func(t *testing.T, resp map[string]interface{})
	}{
		{
			name:           "valid token returns session info",
			token:          token,
			expectedStatus: fiber.StatusOK,
			checkResponse: func(t *testing.T, resp map[string]interface{}) {
				assert.Equal(t, true, resp["valid"])
				assert.Equal(t, userID.String(), resp["user_id"])
				assert.Equal(t, sessionID.String(), resp["session_id"])
				assert.NotEmpty(t, resp["expires_at"])
			},
		},
		{
			name:           "missing token returns unauthorized",
			token:          "",
			expectedStatus: fiber.StatusUnauthorized,
			checkResponse: func(t *testing.T, resp map[string]interface{}) {
				assert.Contains(t, resp["error"], "Authorization header required")
			},
		},
		{
			name:           "invalid token returns unauthorized",
			token:          "invalid-token",
			expectedStatus: fiber.StatusUnauthorized,
			checkResponse: func(t *testing.T, resp map[string]interface{}) {
				assert.Contains(t, resp["error"], "Invalid")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("POST", "/sessions/validate", nil)
			if tt.token != "" {
				req.Header.Set("Authorization", "Bearer "+tt.token)
			}

			resp, err := app.Test(req, -1)
			require.NoError(t, err)
			assert.Equal(t, tt.expectedStatus, resp.StatusCode)

			var result map[string]interface{}
			json.NewDecoder(resp.Body).Decode(&result)
			tt.checkResponse(t, result)
		})
	}
}

// TestRefreshSession tests the RefreshSession handler
func TestRefreshSession(t *testing.T) {
	if err := database.Connect(); err != nil {
		t.Skipf("Skipping test: database not available: %v", err)
	}
	defer database.Close()

	_, _, _, token, cleanup := setupSessionTestData(t)
	defer cleanup()

	app := setupTestAppWithAuthMiddleware()
	app.Post("/sessions/refresh", RefreshSession)

	tests := []struct {
		name           string
		token          string
		expectedStatus int
		checkResponse  func(t *testing.T, resp map[string]interface{})
	}{
		{
			name:           "valid token returns new token",
			token:          token,
			expectedStatus: fiber.StatusOK,
			checkResponse: func(t *testing.T, resp map[string]interface{}) {
				assert.NotEmpty(t, resp["token"])
				// The new token should be different from the old one (contains new expiration)
				newToken := resp["token"].(string)
				assert.NotEmpty(t, newToken)
				// Validate the new token is a valid JWT
				claims, err := utils.ValidateJWT(newToken)
				assert.NoError(t, err)
				assert.NotNil(t, claims)
			},
		},
		{
			name:           "missing token returns unauthorized",
			token:          "",
			expectedStatus: fiber.StatusUnauthorized,
			checkResponse: func(t *testing.T, resp map[string]interface{}) {
				assert.Contains(t, resp["error"], "Authorization header required")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("POST", "/sessions/refresh", nil)
			if tt.token != "" {
				req.Header.Set("Authorization", "Bearer "+tt.token)
			}

			resp, err := app.Test(req, -1)
			require.NoError(t, err)
			assert.Equal(t, tt.expectedStatus, resp.StatusCode)

			var result map[string]interface{}
			json.NewDecoder(resp.Body).Decode(&result)
			tt.checkResponse(t, result)
		})
	}
}

// TestLogoutSession tests the LogoutSession handler
func TestLogoutSession(t *testing.T) {
	if err := database.Connect(); err != nil {
		t.Skipf("Skipping test: database not available: %v", err)
	}
	defer database.Close()

	ctx := context.Background()

	// Create fresh test data for logout test
	var appID uuid.UUID
	err := database.DB.QueryRow(ctx,
		`INSERT INTO applications (name, api_key, allowed_redirect_uris, cors_origins)
		 VALUES ($1, $2, $3, $4) RETURNING id`,
		"Test App for Logout",
		generateAPIKey(),
		[]string{},
		[]string{},
	).Scan(&appID)
	require.NoError(t, err)
	defer database.DB.Exec(ctx, "DELETE FROM applications WHERE id = $1", appID)

	var userID uuid.UUID
	email := "logout@example.com"
	err = database.DB.QueryRow(ctx,
		`INSERT INTO users (app_id, email, name, email_verified)
		 VALUES ($1, $2, $3, $4) RETURNING id`,
		appID,
		email,
		"Logout User",
		true,
	).Scan(&userID)
	require.NoError(t, err)
	defer database.DB.Exec(ctx, "DELETE FROM users WHERE id = $1", userID)

	sessionID := uuid.New()
	token, err := utils.GenerateJWT(userID, appID, sessionID, email)
	require.NoError(t, err)

	tokenHash := utils.HashToken(token)
	expiresAt := time.Now().Add(24 * time.Hour)
	_, err = database.DB.Exec(ctx,
		`INSERT INTO sessions (id, user_id, app_id, token_hash, expires_at, last_used_at)
		 VALUES ($1, $2, $3, $4, $5, NOW())`,
		sessionID,
		userID,
		appID,
		tokenHash,
		expiresAt,
	)
	require.NoError(t, err)

	app := setupTestAppWithAuthMiddleware()
	app.Delete("/sessions/current", LogoutSession)

	t.Run("logout deletes session", func(t *testing.T) {
		req := httptest.NewRequest("DELETE", "/sessions/current", nil)
		req.Header.Set("Authorization", "Bearer "+token)

		resp, err := app.Test(req, -1)
		require.NoError(t, err)
		assert.Equal(t, fiber.StatusNoContent, resp.StatusCode)

		// Verify session was deleted
		var count int
		err = database.DB.QueryRow(ctx, "SELECT COUNT(*) FROM sessions WHERE id = $1", sessionID).Scan(&count)
		require.NoError(t, err)
		assert.Equal(t, 0, count)
	})

	t.Run("logout without token returns unauthorized", func(t *testing.T) {
		req := httptest.NewRequest("DELETE", "/sessions/current", nil)

		resp, err := app.Test(req, -1)
		require.NoError(t, err)
		assert.Equal(t, fiber.StatusUnauthorized, resp.StatusCode)
	})
}

// TestListMySessions tests the ListMySessions handler
func TestListMySessions(t *testing.T) {
	if err := database.Connect(); err != nil {
		t.Skipf("Skipping test: database not available: %v", err)
	}
	defer database.Close()

	ctx := context.Background()

	// Create test application
	var appID uuid.UUID
	err := database.DB.QueryRow(ctx,
		`INSERT INTO applications (name, api_key, allowed_redirect_uris, cors_origins)
		 VALUES ($1, $2, $3, $4) RETURNING id`,
		"Test App for List Sessions",
		generateAPIKey(),
		[]string{},
		[]string{},
	).Scan(&appID)
	require.NoError(t, err)
	defer database.DB.Exec(ctx, "DELETE FROM applications WHERE id = $1", appID)

	var userID uuid.UUID
	email := "listsessions@example.com"
	err = database.DB.QueryRow(ctx,
		`INSERT INTO users (app_id, email, name, email_verified)
		 VALUES ($1, $2, $3, $4) RETURNING id`,
		appID,
		email,
		"List Sessions User",
		true,
	).Scan(&userID)
	require.NoError(t, err)
	defer database.DB.Exec(ctx, "DELETE FROM users WHERE id = $1", userID)

	// Create primary session
	sessionID := uuid.New()
	token, err := utils.GenerateJWT(userID, appID, sessionID, email)
	require.NoError(t, err)

	tokenHash := utils.HashToken(token)
	expiresAt := time.Now().Add(24 * time.Hour)
	_, err = database.DB.Exec(ctx,
		`INSERT INTO sessions (id, user_id, app_id, token_hash, ip_address, user_agent, expires_at, last_used_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, NOW())`,
		sessionID,
		userID,
		appID,
		tokenHash,
		"192.168.1.1",
		"TestAgent/1.0",
		expiresAt,
	)
	require.NoError(t, err)
	defer database.DB.Exec(ctx, "DELETE FROM sessions WHERE user_id = $1", userID)

	// Create additional sessions
	for i := 0; i < 3; i++ {
		extraSessionID := uuid.New()
		extraToken, _ := utils.GenerateJWT(userID, appID, extraSessionID, email)
		extraTokenHash := utils.HashToken(extraToken)
		database.DB.Exec(ctx,
			`INSERT INTO sessions (id, user_id, app_id, token_hash, ip_address, user_agent, expires_at, last_used_at)
			 VALUES ($1, $2, $3, $4, $5, $6, $7, NOW())`,
			extraSessionID,
			userID,
			appID,
			extraTokenHash,
			"192.168.1."+string(rune('2'+i)),
			"ExtraAgent/"+string(rune('1'+i)),
			expiresAt,
		)
	}

	app := setupTestAppWithAuthMiddleware()
	app.Get("/sessions", ListMySessions)

	t.Run("list sessions returns all user sessions", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/sessions", nil)
		req.Header.Set("Authorization", "Bearer "+token)

		resp, err := app.Test(req, -1)
		require.NoError(t, err)
		assert.Equal(t, fiber.StatusOK, resp.StatusCode)

		var sessions []models.Session
		json.NewDecoder(resp.Body).Decode(&sessions)
		assert.GreaterOrEqual(t, len(sessions), 4) // At least the 4 sessions we created
	})

	t.Run("list sessions without token returns unauthorized", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/sessions", nil)

		resp, err := app.Test(req, -1)
		require.NoError(t, err)
		assert.Equal(t, fiber.StatusUnauthorized, resp.StatusCode)
	})
}

// TestRefreshSessionUpdatesTokenHash tests that refresh properly updates token hash
func TestRefreshSessionUpdatesTokenHash(t *testing.T) {
	if err := database.Connect(); err != nil {
		t.Skipf("Skipping test: database not available: %v", err)
	}
	defer database.Close()

	ctx := context.Background()

	// Setup test data
	var appID uuid.UUID
	err := database.DB.QueryRow(ctx,
		`INSERT INTO applications (name, api_key, allowed_redirect_uris, cors_origins)
		 VALUES ($1, $2, $3, $4) RETURNING id`,
		"Test App for Token Hash",
		generateAPIKey(),
		[]string{},
		[]string{},
	).Scan(&appID)
	require.NoError(t, err)
	defer database.DB.Exec(ctx, "DELETE FROM applications WHERE id = $1", appID)

	var userID uuid.UUID
	email := "tokenhash@example.com"
	err = database.DB.QueryRow(ctx,
		`INSERT INTO users (app_id, email, name, email_verified)
		 VALUES ($1, $2, $3, $4) RETURNING id`,
		appID,
		email,
		"Token Hash User",
		true,
	).Scan(&userID)
	require.NoError(t, err)
	defer database.DB.Exec(ctx, "DELETE FROM users WHERE id = $1", userID)

	sessionID := uuid.New()
	token, err := utils.GenerateJWT(userID, appID, sessionID, email)
	require.NoError(t, err)

	originalTokenHash := utils.HashToken(token)
	expiresAt := time.Now().Add(24 * time.Hour)
	_, err = database.DB.Exec(ctx,
		`INSERT INTO sessions (id, user_id, app_id, token_hash, expires_at, last_used_at)
		 VALUES ($1, $2, $3, $4, $5, NOW())`,
		sessionID,
		userID,
		appID,
		originalTokenHash,
		expiresAt,
	)
	require.NoError(t, err)
	defer database.DB.Exec(ctx, "DELETE FROM sessions WHERE id = $1", sessionID)

	app := setupTestAppWithAuthMiddleware()
	app.Post("/sessions/refresh", RefreshSession)

	// Verify session exists before refresh
	var preRefreshHash string
	err = database.DB.QueryRow(ctx, "SELECT token_hash FROM sessions WHERE id = $1", sessionID).Scan(&preRefreshHash)
	require.NoError(t, err, "Session should exist before refresh")
	assert.Equal(t, originalTokenHash, preRefreshHash, "Pre-refresh hash should match original")

	// Wait a moment to ensure JWT timestamp changes (JWT uses second resolution)
	time.Sleep(1100 * time.Millisecond)

	req := httptest.NewRequest("POST", "/sessions/refresh", nil)
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := app.Test(req, -1)
	require.NoError(t, err)

	var result map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&result)

	assert.Equal(t, fiber.StatusOK, resp.StatusCode, "Response: %v", result)

	newToken := result["token"].(string)
	newTokenHash := utils.HashToken(newToken)

	// Verify the token hash was updated in the database
	var storedTokenHash string
	err = database.DB.QueryRow(ctx, "SELECT token_hash FROM sessions WHERE id = $1", sessionID).Scan(&storedTokenHash)
	require.NoError(t, err)

	// The stored hash should match the new token's hash
	assert.Equal(t, newTokenHash, storedTokenHash, "Stored hash should be new token hash")
	// And it should be different from the original (due to different timestamp)
	assert.NotEqual(t, originalTokenHash, storedTokenHash, "Stored hash should not be original")
}

// TestExpiredSessionsNotListed tests that expired sessions are not returned in list
func TestExpiredSessionsNotListed(t *testing.T) {
	if err := database.Connect(); err != nil {
		t.Skipf("Skipping test: database not available: %v", err)
	}
	defer database.Close()

	ctx := context.Background()

	var appID uuid.UUID
	err := database.DB.QueryRow(ctx,
		`INSERT INTO applications (name, api_key, allowed_redirect_uris, cors_origins)
		 VALUES ($1, $2, $3, $4) RETURNING id`,
		"Test App for Expired Sessions",
		generateAPIKey(),
		[]string{},
		[]string{},
	).Scan(&appID)
	require.NoError(t, err)
	defer database.DB.Exec(ctx, "DELETE FROM applications WHERE id = $1", appID)

	var userID uuid.UUID
	email := "expired@example.com"
	err = database.DB.QueryRow(ctx,
		`INSERT INTO users (app_id, email, name, email_verified)
		 VALUES ($1, $2, $3, $4) RETURNING id`,
		appID,
		email,
		"Expired Sessions User",
		true,
	).Scan(&userID)
	require.NoError(t, err)
	defer database.DB.Exec(ctx, "DELETE FROM users WHERE id = $1", userID)

	// Create valid session (this is the one we use for authentication)
	validSessionID := uuid.New()
	validToken, err := utils.GenerateJWT(userID, appID, validSessionID, email)
	require.NoError(t, err)

	validTokenHash := utils.HashToken(validToken)
	validExpiresAt := time.Now().Add(24 * time.Hour)
	_, err = database.DB.Exec(ctx,
		`INSERT INTO sessions (id, user_id, app_id, token_hash, expires_at, last_used_at)
		 VALUES ($1, $2, $3, $4, $5, NOW())`,
		validSessionID,
		userID,
		appID,
		validTokenHash,
		validExpiresAt,
	)
	require.NoError(t, err)
	defer database.DB.Exec(ctx, "DELETE FROM sessions WHERE user_id = $1", userID)

	// Create expired session
	expiredSessionID := uuid.New()
	expiredToken, _ := utils.GenerateJWT(userID, appID, expiredSessionID, email)
	expiredTokenHash := utils.HashToken(expiredToken)
	expiredAt := time.Now().Add(-1 * time.Hour)
	database.DB.Exec(ctx,
		`INSERT INTO sessions (id, user_id, app_id, token_hash, expires_at, last_used_at)
		 VALUES ($1, $2, $3, $4, $5, NOW())`,
		expiredSessionID,
		userID,
		appID,
		expiredTokenHash,
		expiredAt,
	)

	app := setupTestAppWithAuthMiddleware()
	app.Get("/sessions", ListMySessions)

	req := httptest.NewRequest("GET", "/sessions", nil)
	req.Header.Set("Authorization", "Bearer "+validToken)

	resp, err := app.Test(req, -1)
	require.NoError(t, err)
	assert.Equal(t, fiber.StatusOK, resp.StatusCode)

	var sessions []models.Session
	json.NewDecoder(resp.Body).Decode(&sessions)

	// Verify expired session is not in the list
	for _, session := range sessions {
		assert.NotEqual(t, expiredSessionID, session.ID, "Expired session should not be in list")
	}
}
