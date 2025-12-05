package handlers

import (
	"bytes"
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

// TestUserEndpointsIntegration tests the complete user API flow
func TestUserEndpointsIntegration(t *testing.T) {
	// Skip if database not available
	if err := database.Connect(); err != nil {
		t.Skipf("Skipping integration test: database not available: %v", err)
	}
	defer database.Close()

	// Setup Fiber app with user routes
	app := fiber.New()
	userRoutes := app.Group("/api/v1/users")
	userRoutes.Use(middleware.RequireAuth)

	userRoutes.Get("/me", GetMe)
	userRoutes.Patch("/me", UpdateMe)
	userRoutes.Delete("/me", DeleteMe)

	ctx := context.Background()

	t.Run("Complete User Profile Flow", func(t *testing.T) {
		// Step 1: Setup test data
		var appID uuid.UUID
		err := database.DB.QueryRow(ctx,
			`INSERT INTO applications (name, api_key, allowed_redirect_uris, cors_origins)
			 VALUES ($1, $2, $3, $4) RETURNING id`,
			"Integration Test App",
			generateAPIKey(),
			[]string{"http://localhost:3000/callback"},
			[]string{"http://localhost:3000"},
		).Scan(&appID)
		require.NoError(t, err)

		defer database.DB.Exec(ctx, "DELETE FROM applications WHERE id = $1", appID)

		// Create user
		var userID uuid.UUID
		email := "integration@example.com"
		err = database.DB.QueryRow(ctx,
			`INSERT INTO users (app_id, email, name, avatar_url, email_verified)
			 VALUES ($1, $2, $3, $4, $5) RETURNING id`,
			appID,
			email,
			"Integration User",
			"https://example.com/avatar.jpg",
			true,
		).Scan(&userID)
		require.NoError(t, err)

		defer database.DB.Exec(ctx, "DELETE FROM users WHERE id = $1", userID)

		// Create identities
		_, err = database.DB.Exec(ctx,
			`INSERT INTO identities (user_id, provider, provider_user_id, provider_email)
			 VALUES ($1, $2, $3, $4)`,
			userID,
			"google",
			"google-integration-123",
			email,
		)
		require.NoError(t, err)

		defer database.DB.Exec(ctx, "DELETE FROM identities WHERE user_id = $1", userID)

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

		defer database.DB.Exec(ctx, "DELETE FROM sessions WHERE id = $1", sessionID)

		// Step 2: Get user profile
		req := httptest.NewRequest("GET", "/api/v1/users/me", nil)
		req.Header.Set("Authorization", "Bearer "+token)

		resp, err := app.Test(req, -1)
		require.NoError(t, err)
		assert.Equal(t, fiber.StatusOK, resp.StatusCode)

		var profileResp map[string]interface{}
		json.NewDecoder(resp.Body).Decode(&profileResp)

		user := profileResp["user"].(map[string]interface{})
		assert.Equal(t, userID.String(), user["id"])
		assert.Equal(t, "Integration User", user["name"])
		assert.Equal(t, "integration@example.com", user["email"])

		identities := profileResp["identities"].([]interface{})
		assert.Equal(t, 1, len(identities))
		identity := identities[0].(map[string]interface{})
		assert.Equal(t, "google", identity["provider"])

		// Step 3: Update user name
		updateReq := models.UpdateUserRequest{
			Name: stringPtr("Updated Integration User"),
		}

		body, _ := json.Marshal(updateReq)
		req = httptest.NewRequest("PATCH", "/api/v1/users/me", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+token)

		resp, err = app.Test(req, -1)
		require.NoError(t, err)
		assert.Equal(t, fiber.StatusOK, resp.StatusCode)

		var updatedUser models.User
		json.NewDecoder(resp.Body).Decode(&updatedUser)
		assert.Equal(t, "Updated Integration User", *updatedUser.Name)

		// Step 4: Update user email
		updateReq = models.UpdateUserRequest{
			Email: stringPtr("newemail@example.com"),
		}

		body, _ = json.Marshal(updateReq)
		req = httptest.NewRequest("PATCH", "/api/v1/users/me", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+token)

		resp, err = app.Test(req, -1)
		require.NoError(t, err)
		assert.Equal(t, fiber.StatusOK, resp.StatusCode)

		json.NewDecoder(resp.Body).Decode(&updatedUser)
		assert.Equal(t, "newemail@example.com", *updatedUser.Email)

		// Step 5: Verify changes persisted with GET
		req = httptest.NewRequest("GET", "/api/v1/users/me", nil)
		req.Header.Set("Authorization", "Bearer "+token)

		resp, err = app.Test(req, -1)
		require.NoError(t, err)
		assert.Equal(t, fiber.StatusOK, resp.StatusCode)

		json.NewDecoder(resp.Body).Decode(&profileResp)
		user = profileResp["user"].(map[string]interface{})
		assert.Equal(t, "Updated Integration User", user["name"])
		assert.Equal(t, "newemail@example.com", user["email"])
	})

	t.Run("User Deletion Flow", func(t *testing.T) {
		// Setup test data
		var appID uuid.UUID
		err := database.DB.QueryRow(ctx,
			`INSERT INTO applications (name, api_key, allowed_redirect_uris, cors_origins)
			 VALUES ($1, $2, $3, $4) RETURNING id`,
			"Delete Test App",
			generateAPIKey(),
			[]string{},
			[]string{},
		).Scan(&appID)
		require.NoError(t, err)

		defer database.DB.Exec(ctx, "DELETE FROM applications WHERE id = $1", appID)

		// Create user
		var userID uuid.UUID
		email := "deleteintegration@example.com"
		err = database.DB.QueryRow(ctx,
			`INSERT INTO users (app_id, email, name, email_verified)
			 VALUES ($1, $2, $3, $4) RETURNING id`,
			appID,
			email,
			"Delete Test User",
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

		// Delete user
		req := httptest.NewRequest("DELETE", "/api/v1/users/me", nil)
		req.Header.Set("Authorization", "Bearer "+token)

		resp, err := app.Test(req, -1)
		require.NoError(t, err)
		assert.Equal(t, fiber.StatusNoContent, resp.StatusCode)

		// Verify user was deleted
		var count int
		err = database.DB.QueryRow(ctx, "SELECT COUNT(*) FROM users WHERE id = $1", userID).Scan(&count)
		require.NoError(t, err)
		assert.Equal(t, 0, count)

		// Verify sessions were cascade deleted
		err = database.DB.QueryRow(ctx, "SELECT COUNT(*) FROM sessions WHERE user_id = $1", userID).Scan(&count)
		require.NoError(t, err)
		assert.Equal(t, 0, count)
	})

	t.Run("Multiple Identities User", func(t *testing.T) {
		// Setup test data with multiple identities
		var appID uuid.UUID
		err := database.DB.QueryRow(ctx,
			`INSERT INTO applications (name, api_key, allowed_redirect_uris, cors_origins)
			 VALUES ($1, $2, $3, $4) RETURNING id`,
			"Multi Identity Test App",
			generateAPIKey(),
			[]string{},
			[]string{},
		).Scan(&appID)
		require.NoError(t, err)

		defer database.DB.Exec(ctx, "DELETE FROM applications WHERE id = $1", appID)

		// Create user
		var userID uuid.UUID
		email := "multiidentity@example.com"
		err = database.DB.QueryRow(ctx,
			`INSERT INTO users (app_id, email, name, email_verified)
			 VALUES ($1, $2, $3, $4) RETURNING id`,
			appID,
			email,
			"Multi Identity User",
			true,
		).Scan(&userID)
		require.NoError(t, err)

		defer database.DB.Exec(ctx, "DELETE FROM users WHERE id = $1", userID)

		// Create multiple identities
		providers := []struct {
			provider       string
			providerUserID string
		}{
			{"google", "google-multi-123"},
			{"github", "github-multi-456"},
			{"facebook", "facebook-multi-789"},
		}

		for _, p := range providers {
			_, err = database.DB.Exec(ctx,
				`INSERT INTO identities (user_id, provider, provider_user_id, provider_email)
				 VALUES ($1, $2, $3, $4)`,
				userID,
				p.provider,
				p.providerUserID,
				email,
			)
			require.NoError(t, err)
		}

		defer database.DB.Exec(ctx, "DELETE FROM identities WHERE user_id = $1", userID)

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

		defer database.DB.Exec(ctx, "DELETE FROM sessions WHERE id = $1", sessionID)

		// Get user profile and verify all identities are returned
		req := httptest.NewRequest("GET", "/api/v1/users/me", nil)
		req.Header.Set("Authorization", "Bearer "+token)

		resp, err := app.Test(req, -1)
		require.NoError(t, err)
		assert.Equal(t, fiber.StatusOK, resp.StatusCode)

		var profileResp map[string]interface{}
		json.NewDecoder(resp.Body).Decode(&profileResp)

		identities := profileResp["identities"].([]interface{})
		assert.Equal(t, 3, len(identities))

		// Verify all providers are present
		providerSet := make(map[string]bool)
		for _, id := range identities {
			identity := id.(map[string]interface{})
			providerSet[identity["provider"].(string)] = true
		}
		assert.True(t, providerSet["google"])
		assert.True(t, providerSet["github"])
		assert.True(t, providerSet["facebook"])
	})

	t.Run("Authentication Errors", func(t *testing.T) {
		// Test without Authorization header
		req := httptest.NewRequest("GET", "/api/v1/users/me", nil)
		resp, err := app.Test(req, -1)
		require.NoError(t, err)
		assert.Equal(t, fiber.StatusUnauthorized, resp.StatusCode)

		// Test with invalid token format
		req = httptest.NewRequest("GET", "/api/v1/users/me", nil)
		req.Header.Set("Authorization", "InvalidFormat")
		resp, err = app.Test(req, -1)
		require.NoError(t, err)
		assert.Equal(t, fiber.StatusUnauthorized, resp.StatusCode)

		// Test with invalid Bearer token
		req = httptest.NewRequest("GET", "/api/v1/users/me", nil)
		req.Header.Set("Authorization", "Bearer invalid-token-here")
		resp, err = app.Test(req, -1)
		require.NoError(t, err)
		assert.Equal(t, fiber.StatusUnauthorized, resp.StatusCode)

		// Test with expired session
		var appID uuid.UUID
		err = database.DB.QueryRow(ctx,
			`INSERT INTO applications (name, api_key, allowed_redirect_uris, cors_origins)
			 VALUES ($1, $2, $3, $4) RETURNING id`,
			"Expired Session Test",
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

		req = httptest.NewRequest("GET", "/api/v1/users/me", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		resp, err = app.Test(req, -1)
		require.NoError(t, err)
		assert.Equal(t, fiber.StatusUnauthorized, resp.StatusCode)
	})
}
