package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"rauth/database"
	"rauth/middleware"
	"rauth/utils"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestForgotPasswordEndpoint tests the POST /api/v1/auth/forgot-password endpoint
func TestForgotPasswordEndpoint(t *testing.T) {
	if os.Getenv("INTEGRATION_TEST") != "true" {
		t.Skip("Skipping integration test")
	}

	// Initialize database and Redis
	if err := database.Connect(); err != nil {
		t.Fatalf("Failed to connect to database: %v", err)
	}
	if err := database.ConnectRedis(); err != nil {
		t.Fatalf("Failed to connect to Redis: %v", err)
	}

	// Setup Fiber app
	app := fiber.New()
	app.Post("/api/v1/auth/forgot-password", ForgotPassword)

	ctx := context.Background()

	// Create test application
	appID := uuid.New()
	_, err := database.DB.Exec(ctx,
		"INSERT INTO applications (id, name, api_key, allowed_redirect_uris, cors_origins) VALUES ($1, $2, $3, $4, $5)",
		appID, "Test App", "test-key-"+uuid.New().String(), []string{"http://localhost"}, []string{"*"})
	require.NoError(t, err)

	defer func() {
		database.DB.Exec(ctx, "DELETE FROM users WHERE app_id = $1", appID)
		database.DB.Exec(ctx, "DELETE FROM applications WHERE id = $1", appID)
	}()

	t.Run("Successful forgot password request", func(t *testing.T) {
		// Create test user
		email := "endpoint-forgot@example.com"
		userID := uuid.New()
		passwordHash, _ := utils.HashPassword("OldPassword123!")

		_, err := database.DB.Exec(ctx,
			`INSERT INTO users (id, app_id, email, password_hash, name, email_verified, created_at, updated_at)
			 VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
			userID, appID, email, passwordHash, "Endpoint Forgot Test", true, time.Now(), time.Now())
		require.NoError(t, err)

		reqBody := map[string]interface{}{
			"email":  email,
			"app_id": appID.String(),
		}
		body, _ := json.Marshal(reqBody)

		req := httptest.NewRequest("POST", "/api/v1/auth/forgot-password", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")

		// This will fail until implementation exists (TDD Red phase)
		resp, err := app.Test(req, -1)
		require.NoError(t, err)
		assert.Equal(t, 200, resp.StatusCode)

		var response map[string]interface{}
		json.NewDecoder(resp.Body).Decode(&response)
		assert.Equal(t, "Password reset email sent", response["message"])

		// Cleanup
		database.DB.Exec(ctx, "DELETE FROM users WHERE id = $1", userID)
	})

	t.Run("Forgot password with non-existent email returns success", func(t *testing.T) {
		// Security best practice: don't reveal if email exists
		reqBody := map[string]interface{}{
			"email":  "nonexistent@example.com",
			"app_id": appID.String(),
		}
		body, _ := json.Marshal(reqBody)

		req := httptest.NewRequest("POST", "/api/v1/auth/forgot-password", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")

		resp, err := app.Test(req, -1)
		require.NoError(t, err)
		assert.Equal(t, 200, resp.StatusCode)

		var response map[string]interface{}
		json.NewDecoder(resp.Body).Decode(&response)
		assert.Equal(t, "Password reset email sent", response["message"])
	})

	t.Run("Forgot password with missing email returns error", func(t *testing.T) {
		reqBody := map[string]interface{}{
			"app_id": appID.String(),
		}
		body, _ := json.Marshal(reqBody)

		req := httptest.NewRequest("POST", "/api/v1/auth/forgot-password", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")

		resp, err := app.Test(req, -1)
		require.NoError(t, err)
		assert.Equal(t, 400, resp.StatusCode)
	})

	t.Run("Forgot password with invalid email format returns error", func(t *testing.T) {
		reqBody := map[string]interface{}{
			"email":  "invalid-email",
			"app_id": appID.String(),
		}
		body, _ := json.Marshal(reqBody)

		req := httptest.NewRequest("POST", "/api/v1/auth/forgot-password", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")

		resp, err := app.Test(req, -1)
		require.NoError(t, err)
		assert.Equal(t, 400, resp.StatusCode)
	})

	t.Run("Forgot password with missing app_id returns error", func(t *testing.T) {
		reqBody := map[string]interface{}{
			"email": "test@example.com",
		}
		body, _ := json.Marshal(reqBody)

		req := httptest.NewRequest("POST", "/api/v1/auth/forgot-password", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")

		resp, err := app.Test(req, -1)
		require.NoError(t, err)
		assert.Equal(t, 400, resp.StatusCode)
	})
}

// TestResetPasswordEndpoint tests the POST /api/v1/auth/reset-password endpoint
func TestResetPasswordEndpoint(t *testing.T) {
	if os.Getenv("INTEGRATION_TEST") != "true" {
		t.Skip("Skipping integration test")
	}

	// Initialize database and Redis
	if err := database.Connect(); err != nil {
		t.Fatalf("Failed to connect to database: %v", err)
	}
	if err := database.ConnectRedis(); err != nil {
		t.Fatalf("Failed to connect to Redis: %v", err)
	}

	// Setup Fiber app
	app := fiber.New()
	app.Post("/api/v1/auth/reset-password", ResetPassword)

	ctx := context.Background()

	// Create test application
	appID := uuid.New()
	_, err := database.DB.Exec(ctx,
		"INSERT INTO applications (id, name, api_key, allowed_redirect_uris, cors_origins) VALUES ($1, $2, $3, $4, $5)",
		appID, "Test App", "test-key-"+uuid.New().String(), []string{"http://localhost"}, []string{"*"})
	require.NoError(t, err)

	defer func() {
		database.DB.Exec(ctx, "DELETE FROM users WHERE app_id = $1", appID)
		database.DB.Exec(ctx, "DELETE FROM applications WHERE id = $1", appID)
	}()

	t.Run("Successful password reset", func(t *testing.T) {
		// Create test user
		email := "endpoint-reset@example.com"
		userID := uuid.New()
		oldPassword := "OldPassword123!"
		passwordHash, _ := utils.HashPassword(oldPassword)

		_, err := database.DB.Exec(ctx,
			`INSERT INTO users (id, app_id, email, password_hash, name, email_verified, created_at, updated_at)
			 VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
			userID, appID, email, passwordHash, "Endpoint Reset Test", true, time.Now(), time.Now())
		require.NoError(t, err)

		// Generate reset token
		resetToken := uuid.New().String()
		err = database.SetString(ctx, "reset:"+resetToken, email, 1*time.Hour)
		require.NoError(t, err)

		reqBody := map[string]interface{}{
			"token":        resetToken,
			"new_password": "NewSecurePass456!",
		}
		body, _ := json.Marshal(reqBody)

		req := httptest.NewRequest("POST", "/api/v1/auth/reset-password", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")

		// This will fail until implementation exists (TDD Red phase)
		resp, err := app.Test(req, -1)
		require.NoError(t, err)
		assert.Equal(t, 200, resp.StatusCode)

		var response map[string]interface{}
		json.NewDecoder(resp.Body).Decode(&response)
		assert.Equal(t, "Password reset successfully", response["message"])

		// Verify password was changed
		var newPasswordHash string
		err = database.DB.QueryRow(ctx,
			"SELECT password_hash FROM users WHERE id = $1",
			userID).Scan(&newPasswordHash)
		require.NoError(t, err)
		assert.True(t, utils.ComparePassword(newPasswordHash, "NewSecurePass456!"))

		// Cleanup
		database.DB.Exec(ctx, "DELETE FROM users WHERE id = $1", userID)
	})

	t.Run("Reset password with invalid token returns error", func(t *testing.T) {
		reqBody := map[string]interface{}{
			"token":        "invalid-token-12345",
			"new_password": "NewSecurePass456!",
		}
		body, _ := json.Marshal(reqBody)

		req := httptest.NewRequest("POST", "/api/v1/auth/reset-password", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")

		resp, err := app.Test(req, -1)
		require.NoError(t, err)
		assert.Equal(t, 400, resp.StatusCode)
	})

	t.Run("Reset password with missing token returns error", func(t *testing.T) {
		reqBody := map[string]interface{}{
			"new_password": "NewSecurePass456!",
		}
		body, _ := json.Marshal(reqBody)

		req := httptest.NewRequest("POST", "/api/v1/auth/reset-password", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")

		resp, err := app.Test(req, -1)
		require.NoError(t, err)
		assert.Equal(t, 400, resp.StatusCode)
	})

	t.Run("Reset password with missing new_password returns error", func(t *testing.T) {
		reqBody := map[string]interface{}{
			"token": "some-token",
		}
		body, _ := json.Marshal(reqBody)

		req := httptest.NewRequest("POST", "/api/v1/auth/reset-password", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")

		resp, err := app.Test(req, -1)
		require.NoError(t, err)
		assert.Equal(t, 400, resp.StatusCode)
	})

	t.Run("Reset password with weak password returns error", func(t *testing.T) {
		// Create test user
		email := "weak-pass@example.com"
		userID := uuid.New()
		passwordHash, _ := utils.HashPassword("OldPassword123!")

		_, err := database.DB.Exec(ctx,
			`INSERT INTO users (id, app_id, email, password_hash, name, email_verified, created_at, updated_at)
			 VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
			userID, appID, email, passwordHash, "Weak Pass Test", true, time.Now(), time.Now())
		require.NoError(t, err)

		// Generate reset token
		resetToken := uuid.New().String()
		err = database.SetString(ctx, "reset:"+resetToken, email, 1*time.Hour)
		require.NoError(t, err)

		reqBody := map[string]interface{}{
			"token":        resetToken,
			"new_password": "weak", // Too short
		}
		body, _ := json.Marshal(reqBody)

		req := httptest.NewRequest("POST", "/api/v1/auth/reset-password", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")

		resp, err := app.Test(req, -1)
		require.NoError(t, err)
		assert.Equal(t, 400, resp.StatusCode)

		// Cleanup
		database.DB.Exec(ctx, "DELETE FROM users WHERE id = $1", userID)
		database.Delete(ctx, "reset:"+resetToken)
	})

	t.Run("Reset password token can only be used once", func(t *testing.T) {
		// Create test user
		email := "one-time@example.com"
		userID := uuid.New()
		passwordHash, _ := utils.HashPassword("OldPassword123!")

		_, err := database.DB.Exec(ctx,
			`INSERT INTO users (id, app_id, email, password_hash, name, email_verified, created_at, updated_at)
			 VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
			userID, appID, email, passwordHash, "One Time Test", true, time.Now(), time.Now())
		require.NoError(t, err)

		// Generate reset token
		resetToken := uuid.New().String()
		err = database.SetString(ctx, "reset:"+resetToken, email, 1*time.Hour)
		require.NoError(t, err)

		reqBody := map[string]interface{}{
			"token":        resetToken,
			"new_password": "NewSecurePass456!",
		}
		body, _ := json.Marshal(reqBody)

		// First request should succeed
		req1 := httptest.NewRequest("POST", "/api/v1/auth/reset-password", bytes.NewReader(body))
		req1.Header.Set("Content-Type", "application/json")

		resp1, err := app.Test(req1, -1)
		require.NoError(t, err)
		assert.Equal(t, 200, resp1.StatusCode)

		// Second request with same token should fail
		req2 := httptest.NewRequest("POST", "/api/v1/auth/reset-password", bytes.NewReader(body))
		req2.Header.Set("Content-Type", "application/json")

		resp2, err := app.Test(req2, -1)
		require.NoError(t, err)
		assert.Equal(t, 400, resp2.StatusCode)

		// Cleanup
		database.DB.Exec(ctx, "DELETE FROM users WHERE id = $1", userID)
	})
}

// TestChangePasswordEndpoint tests the POST /api/v1/users/me/change-password endpoint
func TestChangePasswordEndpoint(t *testing.T) {
	if os.Getenv("INTEGRATION_TEST") != "true" {
		t.Skip("Skipping integration test")
	}

	// Initialize database
	if err := database.Connect(); err != nil {
		t.Fatalf("Failed to connect to database: %v", err)
	}

	// Setup Fiber app
	app := fiber.New()
	app.Post("/api/v1/users/me/change-password", middleware.RequireAuth, ChangePassword)

	ctx := context.Background()

	// Create test application
	appID := uuid.New()
	_, err := database.DB.Exec(ctx,
		"INSERT INTO applications (id, name, api_key, allowed_redirect_uris, cors_origins) VALUES ($1, $2, $3, $4, $5)",
		appID, "Test App", "test-key-"+uuid.New().String(), []string{"http://localhost"}, []string{"*"})
	require.NoError(t, err)

	defer func() {
		database.DB.Exec(ctx, "DELETE FROM users WHERE app_id = $1", appID)
		database.DB.Exec(ctx, "DELETE FROM applications WHERE id = $1", appID)
	}()

	t.Run("Successful password change", func(t *testing.T) {
		// Create test user
		email := "endpoint-change@example.com"
		userID := uuid.New()
		currentPassword := "CurrentPass123!"
		passwordHash, _ := utils.HashPassword(currentPassword)

		_, err := database.DB.Exec(ctx,
			`INSERT INTO users (id, app_id, email, password_hash, name, email_verified, created_at, updated_at)
			 VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
			userID, appID, email, passwordHash, "Change Pass Test", true, time.Now(), time.Now())
		require.NoError(t, err)

		// Generate JWT token
		sessionID := uuid.New()
		token, err := utils.GenerateJWT(userID, appID, sessionID, email)
		require.NoError(t, err)

		// Create session in database
		tokenHash := utils.HashToken(token)
		expiresAt := time.Now().Add(24 * time.Hour)
		_, err = database.DB.Exec(ctx,
			`INSERT INTO sessions (id, user_id, app_id, token_hash, ip_address, user_agent, expires_at, created_at, last_used_at)
			 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
			sessionID, userID, appID, tokenHash, "127.0.0.1", "test-agent", expiresAt, time.Now(), time.Now())
		require.NoError(t, err)

		reqBody := map[string]interface{}{
			"current_password": currentPassword,
			"new_password":     "NewStrongPass456!",
		}
		body, _ := json.Marshal(reqBody)

		req := httptest.NewRequest("POST", "/api/v1/users/me/change-password", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+token)

		// This will fail until implementation exists (TDD Red phase)
		resp, err := app.Test(req, -1)
		require.NoError(t, err)
		assert.Equal(t, 200, resp.StatusCode)

		var response map[string]interface{}
		json.NewDecoder(resp.Body).Decode(&response)
		assert.Equal(t, "Password changed successfully", response["message"])

		// Verify password was changed
		var newPasswordHash string
		err = database.DB.QueryRow(ctx,
			"SELECT password_hash FROM users WHERE id = $1",
			userID).Scan(&newPasswordHash)
		require.NoError(t, err)
		assert.True(t, utils.ComparePassword(newPasswordHash, "NewStrongPass456!"))

		// Cleanup
		database.DB.Exec(ctx, "DELETE FROM users WHERE id = $1", userID)
	})

	t.Run("Change password without authentication returns 401", func(t *testing.T) {
		reqBody := map[string]interface{}{
			"current_password": "CurrentPass123!",
			"new_password":     "NewStrongPass456!",
		}
		body, _ := json.Marshal(reqBody)

		req := httptest.NewRequest("POST", "/api/v1/users/me/change-password", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")

		resp, err := app.Test(req, -1)
		require.NoError(t, err)
		assert.Equal(t, 401, resp.StatusCode)
	})

	t.Run("Change password with wrong current password returns error", func(t *testing.T) {
		// Create test user
		email := "wrong-current@example.com"
		userID := uuid.New()
		currentPassword := "CurrentPass123!"
		passwordHash, _ := utils.HashPassword(currentPassword)

		_, err := database.DB.Exec(ctx,
			`INSERT INTO users (id, app_id, email, password_hash, name, email_verified, created_at, updated_at)
			 VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
			userID, appID, email, passwordHash, "Wrong Current Test", true, time.Now(), time.Now())
		require.NoError(t, err)

		// Generate JWT token
		sessionID := uuid.New()
		token, err := utils.GenerateJWT(userID, appID, sessionID, email)
		require.NoError(t, err)

		// Create session in database
		tokenHash := utils.HashToken(token)
		expiresAt := time.Now().Add(24 * time.Hour)
		_, err = database.DB.Exec(ctx,
			`INSERT INTO sessions (id, user_id, app_id, token_hash, ip_address, user_agent, expires_at, created_at, last_used_at)
			 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
			sessionID, userID, appID, tokenHash, "127.0.0.1", "test-agent", expiresAt, time.Now(), time.Now())
		require.NoError(t, err)

		reqBody := map[string]interface{}{
			"current_password": "WrongPassword999!",
			"new_password":     "NewStrongPass456!",
		}
		body, _ := json.Marshal(reqBody)

		req := httptest.NewRequest("POST", "/api/v1/users/me/change-password", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+token)

		resp, err := app.Test(req, -1)
		require.NoError(t, err)
		assert.Equal(t, 400, resp.StatusCode)

		// Cleanup
		database.DB.Exec(ctx, "DELETE FROM users WHERE id = $1", userID)
	})

	t.Run("Change password with missing current_password returns error", func(t *testing.T) {
		// Create test user
		email := "missing-current@example.com"
		userID := uuid.New()
		passwordHash, _ := utils.HashPassword("CurrentPass123!")

		_, err := database.DB.Exec(ctx,
			`INSERT INTO users (id, app_id, email, password_hash, name, email_verified, created_at, updated_at)
			 VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
			userID, appID, email, passwordHash, "Missing Current Test", true, time.Now(), time.Now())
		require.NoError(t, err)

		// Generate JWT token
		sessionID := uuid.New()
		token, err := utils.GenerateJWT(userID, appID, sessionID, email)
		require.NoError(t, err)

		// Create session in database
		tokenHash := utils.HashToken(token)
		expiresAt := time.Now().Add(24 * time.Hour)
		_, err = database.DB.Exec(ctx,
			`INSERT INTO sessions (id, user_id, app_id, token_hash, ip_address, user_agent, expires_at, created_at, last_used_at)
			 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
			sessionID, userID, appID, tokenHash, "127.0.0.1", "test-agent", expiresAt, time.Now(), time.Now())
		require.NoError(t, err)

		reqBody := map[string]interface{}{
			"new_password": "NewStrongPass456!",
		}
		body, _ := json.Marshal(reqBody)

		req := httptest.NewRequest("POST", "/api/v1/users/me/change-password", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+token)

		resp, err := app.Test(req, -1)
		require.NoError(t, err)
		assert.Equal(t, 400, resp.StatusCode)

		// Cleanup
		database.DB.Exec(ctx, "DELETE FROM users WHERE id = $1", userID)
	})

	t.Run("Change password with weak new password returns error", func(t *testing.T) {
		// Create test user
		email := "weak-new@example.com"
		userID := uuid.New()
		currentPassword := "CurrentPass123!"
		passwordHash, _ := utils.HashPassword(currentPassword)

		_, err := database.DB.Exec(ctx,
			`INSERT INTO users (id, app_id, email, password_hash, name, email_verified, created_at, updated_at)
			 VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
			userID, appID, email, passwordHash, "Weak New Test", true, time.Now(), time.Now())
		require.NoError(t, err)

		// Generate JWT token
		sessionID := uuid.New()
		token, err := utils.GenerateJWT(userID, appID, sessionID, email)
		require.NoError(t, err)

		// Create session in database
		tokenHash := utils.HashToken(token)
		expiresAt := time.Now().Add(24 * time.Hour)
		_, err = database.DB.Exec(ctx,
			`INSERT INTO sessions (id, user_id, app_id, token_hash, ip_address, user_agent, expires_at, created_at, last_used_at)
			 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
			sessionID, userID, appID, tokenHash, "127.0.0.1", "test-agent", expiresAt, time.Now(), time.Now())
		require.NoError(t, err)

		reqBody := map[string]interface{}{
			"current_password": currentPassword,
			"new_password":     "weak", // Too short
		}
		body, _ := json.Marshal(reqBody)

		req := httptest.NewRequest("POST", "/api/v1/users/me/change-password", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+token)

		resp, err := app.Test(req, -1)
		require.NoError(t, err)
		assert.Equal(t, 400, resp.StatusCode)

		// Cleanup
		database.DB.Exec(ctx, "DELETE FROM users WHERE id = $1", userID)
	})

	t.Run("OAuth users cannot change password", func(t *testing.T) {
		// Create OAuth user (no password_hash)
		email := "oauth-change@example.com"
		userID := uuid.New()

		_, err := database.DB.Exec(ctx,
			`INSERT INTO users (id, app_id, email, password_hash, name, email_verified, created_at, updated_at)
			 VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
			userID, appID, email, nil, "OAuth User", true, time.Now(), time.Now())
		require.NoError(t, err)

		// Generate JWT token
		sessionID := uuid.New()
		token, err := utils.GenerateJWT(userID, appID, sessionID, email)
		require.NoError(t, err)

		// Create session in database
		tokenHash := utils.HashToken(token)
		expiresAt := time.Now().Add(24 * time.Hour)
		_, err = database.DB.Exec(ctx,
			`INSERT INTO sessions (id, user_id, app_id, token_hash, ip_address, user_agent, expires_at, created_at, last_used_at)
			 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
			sessionID, userID, appID, tokenHash, "127.0.0.1", "test-agent", expiresAt, time.Now(), time.Now())
		require.NoError(t, err)

		reqBody := map[string]interface{}{
			"current_password": "anything",
			"new_password":     "NewStrongPass456!",
		}
		body, _ := json.Marshal(reqBody)

		req := httptest.NewRequest("POST", "/api/v1/users/me/change-password", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+token)

		resp, err := app.Test(req, -1)
		require.NoError(t, err)
		assert.Equal(t, 400, resp.StatusCode)

		// Cleanup
		database.DB.Exec(ctx, "DELETE FROM users WHERE id = $1", userID)
	})
}
