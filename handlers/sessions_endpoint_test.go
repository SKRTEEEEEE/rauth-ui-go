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

// TestSessionEndpointValidate tests the POST /api/v1/sessions/validate endpoint
func TestSessionEndpointValidate(t *testing.T) {
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
		"Validate Endpoint Test App",
		generateAPIKey(),
		[]string{"http://localhost:3000/callback"},
		[]string{"http://localhost:3000"},
	).Scan(&appID)
	require.NoError(t, err)
	defer database.DB.Exec(ctx, "DELETE FROM applications WHERE id = $1", appID)

	var userID uuid.UUID
	email := "validate-endpoint@example.com"
	err = database.DB.QueryRow(ctx,
		`INSERT INTO users (app_id, email, name, email_verified)
		 VALUES ($1, $2, $3, $4) RETURNING id`,
		appID,
		email,
		"Validate Endpoint User",
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
		`INSERT INTO sessions (id, user_id, app_id, token_hash, ip_address, user_agent, expires_at, last_used_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, NOW())`,
		sessionID,
		userID,
		appID,
		tokenHash,
		"192.168.1.1",
		"Endpoint Test Agent",
		expiresAt,
	)
	require.NoError(t, err)
	defer database.DB.Exec(ctx, "DELETE FROM sessions WHERE id = $1", sessionID)

	app := setupTestAppWithAuthMiddleware()
	app.Post("/api/v1/sessions/validate", ValidateSession)

	t.Run("POST /api/v1/sessions/validate returns session info", func(t *testing.T) {
		req := httptest.NewRequest("POST", "/api/v1/sessions/validate", nil)
		req.Header.Set("Authorization", "Bearer "+token)

		resp, err := app.Test(req, -1)
		require.NoError(t, err)
		assert.Equal(t, fiber.StatusOK, resp.StatusCode)

		var result map[string]interface{}
		err = json.NewDecoder(resp.Body).Decode(&result)
		require.NoError(t, err)

		assert.Equal(t, true, result["valid"])
		assert.Equal(t, userID.String(), result["user_id"])
		assert.Equal(t, sessionID.String(), result["session_id"])
		assert.NotEmpty(t, result["expires_at"])
	})

	t.Run("POST /api/v1/sessions/validate without token returns 401", func(t *testing.T) {
		req := httptest.NewRequest("POST", "/api/v1/sessions/validate", nil)

		resp, err := app.Test(req, -1)
		require.NoError(t, err)
		assert.Equal(t, fiber.StatusUnauthorized, resp.StatusCode)

		var result map[string]interface{}
		json.NewDecoder(resp.Body).Decode(&result)
		assert.Contains(t, result["error"], "Authorization")
	})
}

// TestSessionEndpointRefresh tests the POST /api/v1/sessions/refresh endpoint
func TestSessionEndpointRefresh(t *testing.T) {
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
		"Refresh Endpoint Test App",
		generateAPIKey(),
		[]string{},
		[]string{},
	).Scan(&appID)
	require.NoError(t, err)
	defer database.DB.Exec(ctx, "DELETE FROM applications WHERE id = $1", appID)

	var userID uuid.UUID
	email := "refresh-endpoint@example.com"
	err = database.DB.QueryRow(ctx,
		`INSERT INTO users (app_id, email, name, email_verified)
		 VALUES ($1, $2, $3, $4) RETURNING id`,
		appID,
		email,
		"Refresh Endpoint User",
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
	app.Post("/api/v1/sessions/refresh", RefreshSession)

	t.Run("POST /api/v1/sessions/refresh returns new token", func(t *testing.T) {
		req := httptest.NewRequest("POST", "/api/v1/sessions/refresh", nil)
		req.Header.Set("Authorization", "Bearer "+token)

		resp, err := app.Test(req, -1)
		require.NoError(t, err)
		assert.Equal(t, fiber.StatusOK, resp.StatusCode)

		var result map[string]interface{}
		err = json.NewDecoder(resp.Body).Decode(&result)
		require.NoError(t, err)

		newToken := result["token"].(string)
		assert.NotEmpty(t, newToken)

		// Verify new token is valid
		claims, err := utils.ValidateJWT(newToken)
		require.NoError(t, err)
		assert.Equal(t, userID, claims.UserID)
		assert.Equal(t, appID, claims.AppID)
		assert.Equal(t, sessionID, claims.SessionID)
	})

	t.Run("POST /api/v1/sessions/refresh without token returns 401", func(t *testing.T) {
		req := httptest.NewRequest("POST", "/api/v1/sessions/refresh", nil)

		resp, err := app.Test(req, -1)
		require.NoError(t, err)
		assert.Equal(t, fiber.StatusUnauthorized, resp.StatusCode)
	})
}

// TestSessionEndpointLogout tests the DELETE /api/v1/sessions/current endpoint
func TestSessionEndpointLogout(t *testing.T) {
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
		"Logout Endpoint Test App",
		generateAPIKey(),
		[]string{},
		[]string{},
	).Scan(&appID)
	require.NoError(t, err)
	defer database.DB.Exec(ctx, "DELETE FROM applications WHERE id = $1", appID)

	t.Run("DELETE /api/v1/sessions/current deletes session", func(t *testing.T) {
		var userID uuid.UUID
		email := "logout-endpoint@example.com"
		err = database.DB.QueryRow(ctx,
			`INSERT INTO users (app_id, email, name, email_verified)
			 VALUES ($1, $2, $3, $4) RETURNING id`,
			appID,
			email,
			"Logout Endpoint User",
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
		app.Delete("/api/v1/sessions/current", LogoutSession)

		req := httptest.NewRequest("DELETE", "/api/v1/sessions/current", nil)
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

	t.Run("DELETE /api/v1/sessions/current without token returns 401", func(t *testing.T) {
		app := setupTestAppWithAuthMiddleware()
		app.Delete("/api/v1/sessions/current", LogoutSession)

		req := httptest.NewRequest("DELETE", "/api/v1/sessions/current", nil)

		resp, err := app.Test(req, -1)
		require.NoError(t, err)
		assert.Equal(t, fiber.StatusUnauthorized, resp.StatusCode)
	})
}

// TestSessionEndpointList tests the GET /api/v1/sessions endpoint
func TestSessionEndpointList(t *testing.T) {
	if err := database.Connect(); err != nil {
		t.Skipf("Skipping test: database not available: %v", err)
	}
	defer database.Close()

	ctx := context.Background()

	var appID uuid.UUID
	err := database.DB.QueryRow(ctx,
		`INSERT INTO applications (name, api_key, allowed_redirect_uris, cors_origins)
		 VALUES ($1, $2, $3, $4) RETURNING id`,
		"List Sessions Endpoint Test App",
		generateAPIKey(),
		[]string{},
		[]string{},
	).Scan(&appID)
	require.NoError(t, err)
	defer database.DB.Exec(ctx, "DELETE FROM applications WHERE id = $1", appID)

	var userID uuid.UUID
	email := "list-endpoint@example.com"
	err = database.DB.QueryRow(ctx,
		`INSERT INTO users (app_id, email, name, email_verified)
		 VALUES ($1, $2, $3, $4) RETURNING id`,
		appID,
		email,
		"List Endpoint User",
		true,
	).Scan(&userID)
	require.NoError(t, err)
	defer database.DB.Exec(ctx, "DELETE FROM users WHERE id = $1", userID)

	// Create multiple sessions
	var tokens []string
	for i := 0; i < 3; i++ {
		sessionID := uuid.New()
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

	app := setupTestAppWithAuthMiddleware()
	app.Get("/api/v1/sessions/", ListMySessions)

	t.Run("GET /api/v1/sessions returns all user sessions", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/v1/sessions/", nil)
		req.Header.Set("Authorization", "Bearer "+tokens[0])

		resp, err := app.Test(req, -1)
		require.NoError(t, err)
		assert.Equal(t, fiber.StatusOK, resp.StatusCode)

		var sessions []models.Session
		err = json.NewDecoder(resp.Body).Decode(&sessions)
		require.NoError(t, err)

		assert.Equal(t, 3, len(sessions))

		// Verify session fields are returned correctly
		for _, session := range sessions {
			assert.Equal(t, userID, session.UserID)
			assert.Equal(t, appID, session.AppID)
			assert.NotEmpty(t, session.ID)
			assert.NotEmpty(t, session.ExpiresAt)
			assert.NotEmpty(t, session.CreatedAt)
			assert.NotEmpty(t, session.LastUsedAt)
		}
	})

	t.Run("GET /api/v1/sessions without token returns 401", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/v1/sessions/", nil)

		resp, err := app.Test(req, -1)
		require.NoError(t, err)
		assert.Equal(t, fiber.StatusUnauthorized, resp.StatusCode)
	})
}

// TestSessionEndpointResponseHeaders tests that correct headers are returned
func TestSessionEndpointResponseHeaders(t *testing.T) {
	if err := database.Connect(); err != nil {
		t.Skipf("Skipping test: database not available: %v", err)
	}
	defer database.Close()

	ctx := context.Background()

	var appID uuid.UUID
	err := database.DB.QueryRow(ctx,
		`INSERT INTO applications (name, api_key, allowed_redirect_uris, cors_origins)
		 VALUES ($1, $2, $3, $4) RETURNING id`,
		"Headers Session Test App",
		generateAPIKey(),
		[]string{},
		[]string{},
	).Scan(&appID)
	require.NoError(t, err)
	defer database.DB.Exec(ctx, "DELETE FROM applications WHERE id = $1", appID)

	var userID uuid.UUID
	email := "headers-session@example.com"
	err = database.DB.QueryRow(ctx,
		`INSERT INTO users (app_id, email, name, email_verified)
		 VALUES ($1, $2, $3, $4) RETURNING id`,
		appID,
		email,
		"Headers Session User",
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
	app.Post("/api/v1/sessions/validate", ValidateSession)

	req := httptest.NewRequest("POST", "/api/v1/sessions/validate", nil)
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := app.Test(req, -1)
	require.NoError(t, err)
	assert.Equal(t, fiber.StatusOK, resp.StatusCode)
	assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))
}
