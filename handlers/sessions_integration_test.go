package handlers

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"testing"
	"time"

	"rauth/database"
	"rauth/middleware"
	"rauth/models"
	"rauth/utils"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestSessionEndpointsIntegration tests the complete session API flow
func TestSessionEndpointsIntegration(t *testing.T) {
	// Skip if database not available
	if err := database.Connect(); err != nil {
		t.Skipf("Skipping integration test: database not available: %v", err)
	}
	defer database.Close()

	// Setup Fiber app with session routes
	app := fiber.New()
	sessionRoutes := app.Group("/api/v1/sessions")
	sessionRoutes.Use(middleware.RequireAuth)

	sessionRoutes.Post("/validate", ValidateSession)
	sessionRoutes.Post("/refresh", RefreshSession)
	sessionRoutes.Delete("/current", LogoutSession)
	sessionRoutes.Get("/", ListMySessions)

	ctx := context.Background()

	t.Run("Complete Session Management Flow", func(t *testing.T) {
		// Step 1: Setup test data
		var appID uuid.UUID
		err := database.DB.QueryRow(ctx,
			`INSERT INTO applications (name, api_key, allowed_redirect_uris, cors_origins)
			 VALUES ($1, $2, $3, $4) RETURNING id`,
			"Session Integration Test App",
			generateAPIKey(),
			[]string{"http://localhost:3000/callback"},
			[]string{"http://localhost:3000"},
		).Scan(&appID)
		require.NoError(t, err)
		defer database.DB.Exec(ctx, "DELETE FROM applications WHERE id = $1", appID)

		// Create user
		var userID uuid.UUID
		email := "session-integration@example.com"
		err = database.DB.QueryRow(ctx,
			`INSERT INTO users (app_id, email, name, avatar_url, email_verified)
			 VALUES ($1, $2, $3, $4, $5) RETURNING id`,
			appID,
			email,
			"Session Integration User",
			"https://example.com/avatar.jpg",
			true,
		).Scan(&userID)
		require.NoError(t, err)
		defer database.DB.Exec(ctx, "DELETE FROM users WHERE id = $1", userID)

		// Create session
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
			"Integration Test Agent",
			expiresAt,
		)
		require.NoError(t, err)
		defer database.DB.Exec(ctx, "DELETE FROM sessions WHERE user_id = $1", userID)

		// Step 2: Validate session
		req := httptest.NewRequest("POST", "/api/v1/sessions/validate", nil)
		req.Header.Set("Authorization", "Bearer "+token)

		resp, err := app.Test(req, -1)
		require.NoError(t, err)
		assert.Equal(t, fiber.StatusOK, resp.StatusCode)

		var validateResp map[string]interface{}
		json.NewDecoder(resp.Body).Decode(&validateResp)
		assert.Equal(t, true, validateResp["valid"])
		assert.Equal(t, userID.String(), validateResp["user_id"])
		assert.Equal(t, sessionID.String(), validateResp["session_id"])

		// Step 3: List sessions
		req = httptest.NewRequest("GET", "/api/v1/sessions/", nil)
		req.Header.Set("Authorization", "Bearer "+token)

		resp, err = app.Test(req, -1)
		require.NoError(t, err)
		assert.Equal(t, fiber.StatusOK, resp.StatusCode)

		var sessions []models.Session
		json.NewDecoder(resp.Body).Decode(&sessions)
		assert.Equal(t, 1, len(sessions))
		assert.Equal(t, sessionID, sessions[0].ID)

		// Step 4: Refresh token
		// Wait a moment to ensure JWT timestamp changes (JWT uses second resolution)
		time.Sleep(1100 * time.Millisecond)

		req = httptest.NewRequest("POST", "/api/v1/sessions/refresh", nil)
		req.Header.Set("Authorization", "Bearer "+token)

		resp, err = app.Test(req, -1)
		require.NoError(t, err)
		assert.Equal(t, fiber.StatusOK, resp.StatusCode)

		var refreshResp map[string]interface{}
		json.NewDecoder(resp.Body).Decode(&refreshResp)
		newToken := refreshResp["token"].(string)
		assert.NotEmpty(t, newToken)

		// Step 5: Validate new token works
		req = httptest.NewRequest("POST", "/api/v1/sessions/validate", nil)
		req.Header.Set("Authorization", "Bearer "+newToken)

		resp, err = app.Test(req, -1)
		require.NoError(t, err)
		assert.Equal(t, fiber.StatusOK, resp.StatusCode)

		// Step 6: Old token should no longer work (token hash changed)
		// The old token has the same session_id but different token_hash
		// The middleware verifies: WHERE id = $1 AND token_hash = $2
		// Since token_hash was updated, old token should fail
		req = httptest.NewRequest("POST", "/api/v1/sessions/validate", nil)
		req.Header.Set("Authorization", "Bearer "+token)

		resp, err = app.Test(req, -1)
		require.NoError(t, err)
		// Old token should fail because token_hash was updated in DB
		// If this returns 200, it means the session was found (unexpected)
		// This validates the token refresh security mechanism
		var oldTokenResp map[string]interface{}
		json.NewDecoder(resp.Body).Decode(&oldTokenResp)
		// The old token should be rejected because its hash doesn't match
		assert.Equal(t, fiber.StatusUnauthorized, resp.StatusCode, "Old token should be rejected after refresh. Response: %v", oldTokenResp)

		// Step 7: Logout with new token
		req = httptest.NewRequest("DELETE", "/api/v1/sessions/current", nil)
		req.Header.Set("Authorization", "Bearer "+newToken)

		resp, err = app.Test(req, -1)
		require.NoError(t, err)
		assert.Equal(t, fiber.StatusNoContent, resp.StatusCode)

		// Step 8: Verify session was deleted
		var count int
		err = database.DB.QueryRow(ctx, "SELECT COUNT(*) FROM sessions WHERE id = $1", sessionID).Scan(&count)
		require.NoError(t, err)
		assert.Equal(t, 0, count)

		// Step 9: Token should no longer work
		req = httptest.NewRequest("POST", "/api/v1/sessions/validate", nil)
		req.Header.Set("Authorization", "Bearer "+newToken)

		resp, err = app.Test(req, -1)
		require.NoError(t, err)
		assert.Equal(t, fiber.StatusUnauthorized, resp.StatusCode)
	})

	t.Run("Multiple Sessions Management", func(t *testing.T) {
		// Setup test data
		var appID uuid.UUID
		err := database.DB.QueryRow(ctx,
			`INSERT INTO applications (name, api_key, allowed_redirect_uris, cors_origins)
			 VALUES ($1, $2, $3, $4) RETURNING id`,
			"Multi Session Test App",
			generateAPIKey(),
			[]string{},
			[]string{},
		).Scan(&appID)
		require.NoError(t, err)
		defer database.DB.Exec(ctx, "DELETE FROM applications WHERE id = $1", appID)

		var userID uuid.UUID
		email := "multisession@example.com"
		err = database.DB.QueryRow(ctx,
			`INSERT INTO users (app_id, email, name, email_verified)
			 VALUES ($1, $2, $3, $4) RETURNING id`,
			appID,
			email,
			"Multi Session User",
			true,
		).Scan(&userID)
		require.NoError(t, err)
		defer database.DB.Exec(ctx, "DELETE FROM users WHERE id = $1", userID)

		// Create multiple sessions
		var tokens []string
		var sessionIDs []uuid.UUID
		for i := 0; i < 3; i++ {
			sessionID := uuid.New()
			sessionIDs = append(sessionIDs, sessionID)

			token, err := utils.GenerateJWT(userID, appID, sessionID, email)
			require.NoError(t, err)
			tokens = append(tokens, token)

			tokenHash := utils.HashToken(token)
			expiresAt := time.Now().Add(24 * time.Hour)
			_, err = database.DB.Exec(ctx,
				`INSERT INTO sessions (id, user_id, app_id, token_hash, ip_address, user_agent, expires_at, last_used_at)
				 VALUES ($1, $2, $3, $4, $5, $6, $7, NOW())`,
				sessionID,
				userID,
				appID,
				tokenHash,
				"192.168.1."+string(rune('1'+i)),
				"Device "+string(rune('A'+i)),
				expiresAt,
			)
			require.NoError(t, err)
		}
		defer database.DB.Exec(ctx, "DELETE FROM sessions WHERE user_id = $1", userID)

		// List all sessions
		req := httptest.NewRequest("GET", "/api/v1/sessions/", nil)
		req.Header.Set("Authorization", "Bearer "+tokens[0])

		resp, err := app.Test(req, -1)
		require.NoError(t, err)
		assert.Equal(t, fiber.StatusOK, resp.StatusCode)

		var sessions []models.Session
		json.NewDecoder(resp.Body).Decode(&sessions)
		assert.Equal(t, 3, len(sessions))

		// Logout from second session
		req = httptest.NewRequest("DELETE", "/api/v1/sessions/current", nil)
		req.Header.Set("Authorization", "Bearer "+tokens[1])

		resp, err = app.Test(req, -1)
		require.NoError(t, err)
		assert.Equal(t, fiber.StatusNoContent, resp.StatusCode)

		// Verify only 2 sessions remain
		req = httptest.NewRequest("GET", "/api/v1/sessions/", nil)
		req.Header.Set("Authorization", "Bearer "+tokens[0])

		resp, err = app.Test(req, -1)
		require.NoError(t, err)
		assert.Equal(t, fiber.StatusOK, resp.StatusCode)

		json.NewDecoder(resp.Body).Decode(&sessions)
		assert.Equal(t, 2, len(sessions))

		// Verify session 1 (tokens[1]) was deleted
		for _, session := range sessions {
			assert.NotEqual(t, sessionIDs[1], session.ID)
		}
	})

	t.Run("Session Authentication Errors", func(t *testing.T) {
		// Test without Authorization header
		req := httptest.NewRequest("POST", "/api/v1/sessions/validate", nil)
		resp, err := app.Test(req, -1)
		require.NoError(t, err)
		assert.Equal(t, fiber.StatusUnauthorized, resp.StatusCode)

		// Test with invalid token format
		req = httptest.NewRequest("POST", "/api/v1/sessions/validate", nil)
		req.Header.Set("Authorization", "InvalidFormat")
		resp, err = app.Test(req, -1)
		require.NoError(t, err)
		assert.Equal(t, fiber.StatusUnauthorized, resp.StatusCode)

		// Test with invalid Bearer token
		req = httptest.NewRequest("POST", "/api/v1/sessions/validate", nil)
		req.Header.Set("Authorization", "Bearer invalid-token-here")
		resp, err = app.Test(req, -1)
		require.NoError(t, err)
		assert.Equal(t, fiber.StatusUnauthorized, resp.StatusCode)
	})

	t.Run("Expired Session Handling", func(t *testing.T) {
		// Use unique identifiers to avoid conflicts with other tests
		uniqueID := uuid.New().String()[:8]

		var appID uuid.UUID
		err := database.DB.QueryRow(ctx,
			`INSERT INTO applications (name, api_key, allowed_redirect_uris, cors_origins)
			 VALUES ($1, $2, $3, $4) RETURNING id`,
			"Expired Session Test "+uniqueID,
			generateAPIKey(),
			[]string{},
			[]string{},
		).Scan(&appID)
		require.NoError(t, err)
		defer database.DB.Exec(ctx, "DELETE FROM applications WHERE id = $1", appID)

		var userID uuid.UUID
		email := "expiredsession-" + uniqueID + "@example.com"
		err = database.DB.QueryRow(ctx,
			`INSERT INTO users (app_id, email, name, email_verified)
			 VALUES ($1, $2, $3, $4) RETURNING id`,
			appID,
			email,
			"Expired Session User",
			true,
		).Scan(&userID)
		require.NoError(t, err)
		defer database.DB.Exec(ctx, "DELETE FROM users WHERE id = $1", userID)

		// Create an expired session
		sessionID := uuid.New()
		token, err := utils.GenerateJWT(userID, appID, sessionID, email)
		require.NoError(t, err)

		tokenHash := utils.HashToken(token)
		expiredAt := time.Now().Add(-1 * time.Hour) // Already expired
		_, err = database.DB.Exec(ctx,
			`INSERT INTO sessions (id, user_id, app_id, token_hash, expires_at, last_used_at)
			 VALUES ($1, $2, $3, $4, $5, NOW())`,
			sessionID,
			userID,
			appID,
			tokenHash,
			expiredAt,
		)
		require.NoError(t, err)
		defer database.DB.Exec(ctx, "DELETE FROM sessions WHERE id = $1", sessionID)

		// Try to validate expired session - should fail because session is expired
		req := httptest.NewRequest("POST", "/api/v1/sessions/validate", nil)
		req.Header.Set("Authorization", "Bearer "+token)

		resp, err := app.Test(req, -1)
		require.NoError(t, err)

		// The session has expires_at in the past, so middleware should reject it
		// The middleware checks: WHERE id = $1 AND token_hash = $2 AND expires_at > NOW()
		assert.Equal(t, fiber.StatusUnauthorized, resp.StatusCode, "Expired session should be rejected by middleware")
	})
}
