package handlers

import (
	"bytes"
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

// TestUserEndpointGetMe tests the GET /api/v1/users/me endpoint
func TestUserEndpointGetMe(t *testing.T) {
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
		"Endpoint Test App",
		generateAPIKey(),
		[]string{"http://localhost:3000/callback"},
		[]string{"http://localhost:3000"},
	).Scan(&appID)
	require.NoError(t, err)
	defer database.DB.Exec(ctx, "DELETE FROM applications WHERE id = $1", appID)

	// Create user
	var userID uuid.UUID
	email := "endpoint@example.com"
	name := "Endpoint User"
	avatarURL := "https://example.com/avatar.jpg"
	err = database.DB.QueryRow(ctx,
		`INSERT INTO users (app_id, email, name, avatar_url, email_verified)
		 VALUES ($1, $2, $3, $4, $5) RETURNING id`,
		appID,
		email,
		name,
		avatarURL,
		true,
	).Scan(&userID)
	require.NoError(t, err)
	defer database.DB.Exec(ctx, "DELETE FROM users WHERE id = $1", userID)

	// Create identity
	_, err = database.DB.Exec(ctx,
		`INSERT INTO identities (user_id, provider, provider_user_id, provider_email)
		 VALUES ($1, $2, $3, $4)`,
		userID,
		"google",
		"google-endpoint-123",
		email,
	)
	require.NoError(t, err)
	defer database.DB.Exec(ctx, "DELETE FROM identities WHERE user_id = $1", userID)

	// Create session and token
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

	app := setupTestAppWithAuthMiddleware()
	app.Get("/api/v1/users/me", GetMe)

	t.Run("GET /api/v1/users/me returns user profile", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/v1/users/me", nil)
		req.Header.Set("Authorization", "Bearer "+token)

		resp, err := app.Test(req, -1)
		require.NoError(t, err)
		assert.Equal(t, fiber.StatusOK, resp.StatusCode)

		var result map[string]interface{}
		err = json.NewDecoder(resp.Body).Decode(&result)
		require.NoError(t, err)

		// Verify user object
		user, ok := result["user"].(map[string]interface{})
		require.True(t, ok, "response should contain user object")
		assert.Equal(t, userID.String(), user["id"])
		assert.Equal(t, appID.String(), user["app_id"])
		assert.Equal(t, email, user["email"])
		assert.Equal(t, name, user["name"])
		assert.Equal(t, avatarURL, user["avatar_url"])
		assert.Equal(t, true, user["email_verified"])
		assert.NotEmpty(t, user["created_at"])
		assert.NotEmpty(t, user["updated_at"])

		// Verify identities array
		identities, ok := result["identities"].([]interface{})
		require.True(t, ok, "response should contain identities array")
		assert.Equal(t, 1, len(identities))

		identity := identities[0].(map[string]interface{})
		assert.Equal(t, "google", identity["provider"])
		assert.Equal(t, email, identity["provider_email"])
		assert.NotEmpty(t, identity["id"])
		assert.NotEmpty(t, identity["user_id"])
		assert.NotEmpty(t, identity["created_at"])
	})

	t.Run("GET /api/v1/users/me without token returns 401", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/v1/users/me", nil)

		resp, err := app.Test(req, -1)
		require.NoError(t, err)
		assert.Equal(t, fiber.StatusUnauthorized, resp.StatusCode)

		var result map[string]interface{}
		json.NewDecoder(resp.Body).Decode(&result)
		assert.Contains(t, result["error"], "Authorization")
	})
}

// TestUserEndpointPatchMe tests the PATCH /api/v1/users/me endpoint
func TestUserEndpointPatchMe(t *testing.T) {
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
		"Patch Endpoint Test",
		generateAPIKey(),
		[]string{},
		[]string{},
	).Scan(&appID)
	require.NoError(t, err)
	defer database.DB.Exec(ctx, "DELETE FROM applications WHERE id = $1", appID)

	// Create user
	var userID uuid.UUID
	email := "patch@example.com"
	err = database.DB.QueryRow(ctx,
		`INSERT INTO users (app_id, email, name, email_verified)
		 VALUES ($1, $2, $3, $4) RETURNING id`,
		appID,
		email,
		"Original Name",
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

	app := setupTestAppWithAuthMiddleware()
	app.Patch("/api/v1/users/me", UpdateMe)

	t.Run("PATCH /api/v1/users/me updates name", func(t *testing.T) {
		updateReq := models.UpdateUserRequest{
			Name: stringPtr("Updated Name"),
		}

		body, _ := json.Marshal(updateReq)
		req := httptest.NewRequest("PATCH", "/api/v1/users/me", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+token)

		resp, err := app.Test(req, -1)
		require.NoError(t, err)
		assert.Equal(t, fiber.StatusOK, resp.StatusCode)

		var user models.User
		json.NewDecoder(resp.Body).Decode(&user)
		assert.Equal(t, "Updated Name", *user.Name)
		assert.Equal(t, userID, user.ID)
		assert.Equal(t, appID, user.AppID)
	})

	t.Run("PATCH /api/v1/users/me updates email", func(t *testing.T) {
		updateReq := models.UpdateUserRequest{
			Email: stringPtr("updated@example.com"),
		}

		body, _ := json.Marshal(updateReq)
		req := httptest.NewRequest("PATCH", "/api/v1/users/me", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+token)

		resp, err := app.Test(req, -1)
		require.NoError(t, err)
		assert.Equal(t, fiber.StatusOK, resp.StatusCode)

		var user models.User
		json.NewDecoder(resp.Body).Decode(&user)
		assert.Equal(t, "updated@example.com", *user.Email)
	})

	t.Run("PATCH /api/v1/users/me with invalid JSON returns 400", func(t *testing.T) {
		req := httptest.NewRequest("PATCH", "/api/v1/users/me", bytes.NewReader([]byte("invalid json")))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+token)

		resp, err := app.Test(req, -1)
		require.NoError(t, err)
		assert.Equal(t, fiber.StatusBadRequest, resp.StatusCode)

		var result map[string]interface{}
		json.NewDecoder(resp.Body).Decode(&result)
		assert.Contains(t, result["error"], "Invalid request body")
	})

	t.Run("PATCH /api/v1/users/me without token returns 401", func(t *testing.T) {
		updateReq := models.UpdateUserRequest{Name: stringPtr("New Name")}
		body, _ := json.Marshal(updateReq)

		req := httptest.NewRequest("PATCH", "/api/v1/users/me", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")

		resp, err := app.Test(req, -1)
		require.NoError(t, err)
		assert.Equal(t, fiber.StatusUnauthorized, resp.StatusCode)
	})
}

// TestUserEndpointDeleteMe tests the DELETE /api/v1/users/me endpoint
func TestUserEndpointDeleteMe(t *testing.T) {
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
		"Delete Endpoint Test",
		generateAPIKey(),
		[]string{},
		[]string{},
	).Scan(&appID)
	require.NoError(t, err)
	defer database.DB.Exec(ctx, "DELETE FROM applications WHERE id = $1", appID)

	t.Run("DELETE /api/v1/users/me deletes user", func(t *testing.T) {
		// Create user
		var userID uuid.UUID
		email := "delete@example.com"
		err = database.DB.QueryRow(ctx,
			`INSERT INTO users (app_id, email, name, email_verified)
			 VALUES ($1, $2, $3, $4) RETURNING id`,
			appID,
			email,
			"Delete Me",
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
		app.Delete("/api/v1/users/me", DeleteMe)

		req := httptest.NewRequest("DELETE", "/api/v1/users/me", nil)
		req.Header.Set("Authorization", "Bearer "+token)

		resp, err := app.Test(req, -1)
		require.NoError(t, err)
		assert.Equal(t, fiber.StatusNoContent, resp.StatusCode)

		// Verify user was deleted from database
		var count int
		err = database.DB.QueryRow(ctx, "SELECT COUNT(*) FROM users WHERE id = $1", userID).Scan(&count)
		require.NoError(t, err)
		assert.Equal(t, 0, count)
	})

	t.Run("DELETE /api/v1/users/me without token returns 401", func(t *testing.T) {
		app := setupTestAppWithAuthMiddleware()
		app.Delete("/api/v1/users/me", DeleteMe)

		req := httptest.NewRequest("DELETE", "/api/v1/users/me", nil)

		resp, err := app.Test(req, -1)
		require.NoError(t, err)
		assert.Equal(t, fiber.StatusUnauthorized, resp.StatusCode)
	})
}

// TestUserEndpointResponseHeaders tests that correct headers are returned
func TestUserEndpointResponseHeaders(t *testing.T) {
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
		"Headers Test App",
		generateAPIKey(),
		[]string{},
		[]string{},
	).Scan(&appID)
	require.NoError(t, err)
	defer database.DB.Exec(ctx, "DELETE FROM applications WHERE id = $1", appID)

	var userID uuid.UUID
	email := "headers@example.com"
	err = database.DB.QueryRow(ctx,
		`INSERT INTO users (app_id, email, name, email_verified)
		 VALUES ($1, $2, $3, $4) RETURNING id`,
		appID,
		email,
		"Headers Test User",
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
	defer database.DB.Exec(ctx, "DELETE FROM sessions WHERE id = $1", sessionID)

	app := setupTestAppWithAuthMiddleware()
	app.Get("/api/v1/users/me", GetMe)

	req := httptest.NewRequest("GET", "/api/v1/users/me", nil)
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := app.Test(req, -1)
	require.NoError(t, err)
	assert.Equal(t, fiber.StatusOK, resp.StatusCode)
	assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))
}
