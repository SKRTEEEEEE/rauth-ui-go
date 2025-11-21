package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http/httptest"
	"strings"
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

// setupUserTestData creates test app, user and session for testing
func setupUserTestData(t *testing.T) (uuid.UUID, uuid.UUID, uuid.UUID, string, func()) {
	ctx := context.Background()

	// Create test application
	var appID uuid.UUID
	err := database.DB.QueryRow(ctx,
		`INSERT INTO applications (name, api_key, allowed_redirect_uris, cors_origins)
		 VALUES ($1, $2, $3, $4) RETURNING id`,
		"Test App for Users",
		generateAPIKey(),
		[]string{"http://localhost:3000/callback"},
		[]string{"http://localhost:3000"},
	).Scan(&appID)
	require.NoError(t, err)

	// Create test user
	var userID uuid.UUID
	email := "testuser@example.com"
	name := "Test User"
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

	// Create test identity
	_, err = database.DB.Exec(ctx,
		`INSERT INTO identities (user_id, provider, provider_user_id, provider_email)
		 VALUES ($1, $2, $3, $4)`,
		userID,
		"google",
		"google-12345",
		email,
	)
	require.NoError(t, err)

	// Generate JWT token
	sessionID := uuid.New()
	token, err := utils.GenerateJWT(userID, appID, sessionID, email)
	require.NoError(t, err)

	// Create session in database
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

	cleanup := func() {
		database.DB.Exec(ctx, "DELETE FROM sessions WHERE id = $1", sessionID)
		database.DB.Exec(ctx, "DELETE FROM identities WHERE user_id = $1", userID)
		database.DB.Exec(ctx, "DELETE FROM users WHERE id = $1", userID)
		database.DB.Exec(ctx, "DELETE FROM applications WHERE id = $1", appID)
	}

	return appID, userID, sessionID, token, cleanup
}

// TestGetMe tests the GetMe handler
func TestGetMe(t *testing.T) {
	if err := database.Connect(); err != nil {
		t.Skipf("Skipping test: database not available: %v", err)
	}
	defer database.Close()

	appID, userID, _, token, cleanup := setupUserTestData(t)
	defer cleanup()

	app := setupTestAppWithAuthMiddleware()
	app.Get("/users/me", GetMe)

	tests := []struct {
		name           string
		token          string
		expectedStatus int
		checkResponse  func(t *testing.T, resp map[string]interface{})
	}{
		{
			name:           "valid token returns user",
			token:          token,
			expectedStatus: fiber.StatusOK,
			checkResponse: func(t *testing.T, resp map[string]interface{}) {
				user, ok := resp["user"].(map[string]interface{})
				require.True(t, ok, "response should contain user object")

				assert.Equal(t, userID.String(), user["id"])
				assert.Equal(t, appID.String(), user["app_id"])
				assert.Equal(t, "testuser@example.com", user["email"])
				assert.Equal(t, "Test User", user["name"])
				assert.Equal(t, "https://example.com/avatar.jpg", user["avatar_url"])
				assert.Equal(t, true, user["email_verified"])

				identities, ok := resp["identities"].([]interface{})
				require.True(t, ok, "response should contain identities array")
				assert.GreaterOrEqual(t, len(identities), 1)
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
			req := httptest.NewRequest("GET", "/users/me", nil)
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

// TestUpdateMe tests the UpdateMe handler
func TestUpdateMe(t *testing.T) {
	if err := database.Connect(); err != nil {
		t.Skipf("Skipping test: database not available: %v", err)
	}
	defer database.Close()

	_, _, _, token, cleanup := setupUserTestData(t)
	defer cleanup()

	app := setupTestAppWithAuthMiddleware()
	app.Patch("/users/me", UpdateMe)

	tests := []struct {
		name           string
		token          string
		requestBody    interface{}
		expectedStatus int
		checkResponse  func(t *testing.T, resp map[string]interface{})
	}{
		{
			name:  "update name only",
			token: token,
			requestBody: models.UpdateUserRequest{
				Name: stringPtr("New Name"),
			},
			expectedStatus: fiber.StatusOK,
			checkResponse: func(t *testing.T, resp map[string]interface{}) {
				assert.Equal(t, "New Name", resp["name"])
			},
		},
		{
			name:  "update email only",
			token: token,
			requestBody: models.UpdateUserRequest{
				Email: stringPtr("newemail@example.com"),
			},
			expectedStatus: fiber.StatusOK,
			checkResponse: func(t *testing.T, resp map[string]interface{}) {
				assert.Equal(t, "newemail@example.com", resp["email"])
			},
		},
		{
			name:  "update multiple fields",
			token: token,
			requestBody: models.UpdateUserRequest{
				Name:  stringPtr("Another Name"),
				Email: stringPtr("another@example.com"),
			},
			expectedStatus: fiber.StatusOK,
			checkResponse: func(t *testing.T, resp map[string]interface{}) {
				assert.Equal(t, "Another Name", resp["name"])
				assert.Equal(t, "another@example.com", resp["email"])
			},
		},
		{
			name:           "missing token returns unauthorized",
			token:          "",
			requestBody:    models.UpdateUserRequest{Name: stringPtr("New Name")},
			expectedStatus: fiber.StatusUnauthorized,
			checkResponse: func(t *testing.T, resp map[string]interface{}) {
				assert.Contains(t, resp["error"], "Authorization header required")
			},
		},
		{
			name:           "invalid JSON returns bad request",
			token:          token,
			requestBody:    "invalid json",
			expectedStatus: fiber.StatusBadRequest,
			checkResponse: func(t *testing.T, resp map[string]interface{}) {
				assert.Contains(t, resp["error"], "Invalid request body")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var body []byte
			switch v := tt.requestBody.(type) {
			case string:
				body = []byte(v)
			default:
				body, _ = json.Marshal(v)
			}

			req := httptest.NewRequest("PATCH", "/users/me", bytes.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
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

// TestDeleteMe tests the DeleteMe handler
func TestDeleteMe(t *testing.T) {
	if err := database.Connect(); err != nil {
		t.Skipf("Skipping test: database not available: %v", err)
	}
	defer database.Close()

	// Create fresh test data for deletion test (separate from other tests)
	ctx := context.Background()

	// Create test application
	var appID uuid.UUID
	err := database.DB.QueryRow(ctx,
		`INSERT INTO applications (name, api_key, allowed_redirect_uris, cors_origins)
		 VALUES ($1, $2, $3, $4) RETURNING id`,
		"Test App for Delete",
		generateAPIKey(),
		[]string{},
		[]string{},
	).Scan(&appID)
	require.NoError(t, err)
	defer database.DB.Exec(ctx, "DELETE FROM applications WHERE id = $1", appID)

	// Create test user
	var userID uuid.UUID
	email := "deleteuser@example.com"
	err = database.DB.QueryRow(ctx,
		`INSERT INTO users (app_id, email, name, email_verified)
		 VALUES ($1, $2, $3, $4) RETURNING id`,
		appID,
		email,
		"Delete User",
		true,
	).Scan(&userID)
	require.NoError(t, err)

	// Create session
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
	app.Delete("/users/me", DeleteMe)

	t.Run("delete user successfully", func(t *testing.T) {
		req := httptest.NewRequest("DELETE", "/users/me", nil)
		req.Header.Set("Authorization", "Bearer "+token)

		resp, err := app.Test(req, -1)
		require.NoError(t, err)
		assert.Equal(t, fiber.StatusNoContent, resp.StatusCode)

		// Verify user was deleted
		var count int
		err = database.DB.QueryRow(ctx, "SELECT COUNT(*) FROM users WHERE id = $1", userID).Scan(&count)
		require.NoError(t, err)
		assert.Equal(t, 0, count)
	})

	t.Run("delete without token returns unauthorized", func(t *testing.T) {
		req := httptest.NewRequest("DELETE", "/users/me", nil)

		resp, err := app.Test(req, -1)
		require.NoError(t, err)
		assert.Equal(t, fiber.StatusUnauthorized, resp.StatusCode)
	})
}

// TestGetMeUserNotFound tests GetMe when user doesn't exist in DB
// Note: Due to CASCADE DELETE on sessions, when a user is deleted, their sessions are also deleted.
// This test verifies that attempting to access with a token for a deleted user returns 401
// because the session will have been cascade deleted along with the user.
func TestGetMeUserNotFound(t *testing.T) {
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
		"Test App for Not Found",
		generateAPIKey(),
		[]string{},
		[]string{},
	).Scan(&appID)
	require.NoError(t, err)
	defer database.DB.Exec(ctx, "DELETE FROM applications WHERE id = $1", appID)

	// Create a user and session
	var userID uuid.UUID
	email := "notfound@example.com"
	err = database.DB.QueryRow(ctx,
		`INSERT INTO users (app_id, email, name, email_verified)
		 VALUES ($1, $2, $3, $4) RETURNING id`,
		appID,
		email,
		"Not Found User",
		true,
	).Scan(&userID)
	require.NoError(t, err)

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

	// Delete user - this will cascade delete sessions as well
	_, err = database.DB.Exec(ctx, "DELETE FROM users WHERE id = $1", userID)
	require.NoError(t, err)

	app := setupTestAppWithAuthMiddleware()
	app.Get("/users/me", GetMe)

	req := httptest.NewRequest("GET", "/users/me", nil)
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := app.Test(req, -1)
	require.NoError(t, err)

	// Since sessions are cascade deleted with the user, we expect 401 Unauthorized
	// (session not found) rather than 404 Not Found (user not found)
	assert.Equal(t, fiber.StatusUnauthorized, resp.StatusCode)

	var result map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&result)
	assert.Contains(t, result["error"], "Session not found or expired")
}

// setupTestAppWithAuthMiddleware creates a fiber app with auth middleware for testing
func setupTestAppWithAuthMiddleware() *fiber.App {
	app := fiber.New()
	app.Use(testAuthMiddleware)
	return app
}

// testAuthMiddleware simulates the RequireAuth middleware for testing
func testAuthMiddleware(c *fiber.Ctx) error {
	authHeader := c.Get("Authorization")
	if authHeader == "" {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"error": "Authorization header required",
		})
	}

	parts := strings.Split(authHeader, " ")
	if len(parts) != 2 || parts[0] != "Bearer" {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"error": "Invalid authorization format",
		})
	}

	tokenString := parts[1]

	claims, err := utils.ValidateJWT(tokenString)
	if err != nil {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"error": "Invalid or expired token",
		})
	}

	// Verify session exists in DB
	ctx := context.Background()
	tokenHash := utils.HashToken(tokenString)

	var session models.Session
	query := `
		SELECT id, user_id, app_id, expires_at
		FROM sessions
		WHERE id = $1 AND token_hash = $2 AND expires_at > NOW()
	`

	err = database.DB.QueryRow(ctx, query, claims.SessionID, tokenHash).Scan(
		&session.ID,
		&session.UserID,
		&session.AppID,
		&session.ExpiresAt,
	)

	if err != nil {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"error": "Session not found or expired",
		})
	}

	c.Locals("jwt_claims", claims)
	c.Locals("session", session)

	return c.Next()
}
