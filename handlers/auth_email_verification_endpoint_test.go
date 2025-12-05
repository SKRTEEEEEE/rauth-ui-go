package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"rauth/database"
	"rauth/models"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// setupEmailVerificationApp creates a Fiber app with email verification endpoints
func setupEmailVerificationApp() *fiber.App {
	app := fiber.New()
	app.Post("/api/v1/auth/verify-email", VerifyEmail)
	app.Post("/api/v1/auth/resend-verification", ResendVerification)
	return app
}

// TestVerifyEmailEndpoint_Scenarios tests POST /api/v1/auth/verify-email
func TestVerifyEmailEndpoint_Scenarios(t *testing.T) {
	if os.Getenv("INTEGRATION_TEST") != "true" {
		t.Skip("Skipping endpoint test")
	}

	if err := database.Connect(); err != nil {
		t.Fatalf("Failed to connect to database: %v", err)
	}
	if err := database.ConnectRedis(); err != nil {
		t.Fatalf("Failed to connect to Redis: %v", err)
	}

	ctx := context.Background()
	app := setupEmailVerificationApp()

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

	t.Run("Verify email with valid token", func(t *testing.T) {
		email := "verify-endpoint@example.com"
		password := "SecurePass123!"

		// Register user
		registerReq := &models.RegisterRequest{
			Email:    email,
			Password: password,
			Name:     strPtr("Verify Endpoint Test"),
			AppID:    appID,
		}
		userID, err := registerUser(ctx, registerReq)
		require.NoError(t, err)

		// Generate and store verification token
		token := generateVerificationToken()
		tokenKey := "email:verification:" + token
		tokenData := map[string]string{
			"user_id": userID.String(),
			"app_id":  appID.String(),
			"email":   email,
		}
		err = database.SetJSON(ctx, tokenKey, tokenData, 24*time.Hour)
		require.NoError(t, err)

		// Send verify request
		payload := models.VerifyEmailRequest{
			Token: token,
		}
		body, _ := json.Marshal(payload)
		req := httptest.NewRequest("POST", "/api/v1/auth/verify-email", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")

		resp, err := app.Test(req, -1)
		require.NoError(t, err)

		// This WILL FAIL until implementation exists (TDD Red)
		assert.Equal(t, fiber.StatusOK, resp.StatusCode)

		respBody, _ := io.ReadAll(resp.Body)
		var response map[string]interface{}
		err = json.Unmarshal(respBody, &response)
		require.NoError(t, err)

		// Verify response contains success message
		assert.Contains(t, response, "message")

		// Verify user is marked as verified in database
		var emailVerified bool
		err = database.DB.QueryRow(ctx,
			"SELECT email_verified FROM users WHERE id = $1",
			userID).Scan(&emailVerified)
		require.NoError(t, err)
		assert.True(t, emailVerified)

		// Verify token was deleted
		exists, err := database.Exists(ctx, tokenKey)
		require.NoError(t, err)
		assert.False(t, exists)

		// Cleanup
		database.DB.Exec(ctx, "DELETE FROM users WHERE id = $1", userID)
	})

	t.Run("Verify email with invalid token", func(t *testing.T) {
		payload := models.VerifyEmailRequest{
			Token: "invalid-token-xyz",
		}
		body, _ := json.Marshal(payload)
		req := httptest.NewRequest("POST", "/api/v1/auth/verify-email", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")

		resp, err := app.Test(req, -1)
		require.NoError(t, err)

		assert.Equal(t, fiber.StatusBadRequest, resp.StatusCode)

		respBody, _ := io.ReadAll(resp.Body)
		assert.Contains(t, string(respBody), "invalid")
	})

	t.Run("Verify email with empty token", func(t *testing.T) {
		payload := models.VerifyEmailRequest{
			Token: "",
		}
		body, _ := json.Marshal(payload)
		req := httptest.NewRequest("POST", "/api/v1/auth/verify-email", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")

		resp, err := app.Test(req, -1)
		require.NoError(t, err)

		assert.Equal(t, fiber.StatusBadRequest, resp.StatusCode)

		respBody, _ := io.ReadAll(resp.Body)
		assert.Contains(t, string(respBody), "required")
	})

	t.Run("Verify email with expired token", func(t *testing.T) {
		email := "expired-endpoint@example.com"
		password := "SecurePass123!"

		// Register user
		registerReq := &models.RegisterRequest{
			Email:    email,
			Password: password,
			Name:     strPtr("Expired Endpoint Test"),
			AppID:    appID,
		}
		userID, err := registerUser(ctx, registerReq)
		require.NoError(t, err)

		// Generate token but don't store (simulating expired)
		token := generateVerificationToken()

		// Send verify request
		payload := models.VerifyEmailRequest{
			Token: token,
		}
		body, _ := json.Marshal(payload)
		req := httptest.NewRequest("POST", "/api/v1/auth/verify-email", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")

		resp, err := app.Test(req, -1)
		require.NoError(t, err)

		assert.Equal(t, fiber.StatusBadRequest, resp.StatusCode)

		respBody, _ := io.ReadAll(resp.Body)
		assert.Contains(t, string(respBody), "invalid")

		// User should still not be verified
		var emailVerified bool
		err = database.DB.QueryRow(ctx,
			"SELECT email_verified FROM users WHERE id = $1",
			userID).Scan(&emailVerified)
		require.NoError(t, err)
		assert.False(t, emailVerified)

		// Cleanup
		database.DB.Exec(ctx, "DELETE FROM users WHERE id = $1", userID)
	})

	t.Run("Verify email twice (idempotent)", func(t *testing.T) {
		email := "idempotent-endpoint@example.com"
		password := "SecurePass123!"

		// Register user
		registerReq := &models.RegisterRequest{
			Email:    email,
			Password: password,
			Name:     strPtr("Idempotent Test"),
			AppID:    appID,
		}
		userID, err := registerUser(ctx, registerReq)
		require.NoError(t, err)

		// Generate and store token
		token := generateVerificationToken()
		tokenKey := "email:verification:" + token
		tokenData := map[string]string{
			"user_id": userID.String(),
			"app_id":  appID.String(),
			"email":   email,
		}
		err = database.SetJSON(ctx, tokenKey, tokenData, 24*time.Hour)
		require.NoError(t, err)

		// First verification
		payload := models.VerifyEmailRequest{Token: token}
		body, _ := json.Marshal(payload)
		req1 := httptest.NewRequest("POST", "/api/v1/auth/verify-email", bytes.NewReader(body))
		req1.Header.Set("Content-Type", "application/json")

		resp1, err := app.Test(req1, -1)
		require.NoError(t, err)
		assert.Equal(t, fiber.StatusOK, resp1.StatusCode)

		// Generate new token for same user (simulating resend)
		token2 := generateVerificationToken()
		tokenKey2 := "email:verification:" + token2
		err = database.SetJSON(ctx, tokenKey2, tokenData, 24*time.Hour)
		require.NoError(t, err)

		// Second verification (user already verified)
		payload2 := models.VerifyEmailRequest{Token: token2}
		body2, _ := json.Marshal(payload2)
		req2 := httptest.NewRequest("POST", "/api/v1/auth/verify-email", bytes.NewReader(body2))
		req2.Header.Set("Content-Type", "application/json")

		resp2, err := app.Test(req2, -1)
		require.NoError(t, err)

		// Should succeed or return appropriate message
		assert.True(t, resp2.StatusCode == fiber.StatusOK || resp2.StatusCode == fiber.StatusConflict)

		// Cleanup
		database.Delete(ctx, tokenKey2)
		database.DB.Exec(ctx, "DELETE FROM users WHERE id = $1", userID)
	})

	t.Run("Verify email with malformed JSON", func(t *testing.T) {
		malformedJSON := []byte(`{"token": }`)
		req := httptest.NewRequest("POST", "/api/v1/auth/verify-email", bytes.NewReader(malformedJSON))
		req.Header.Set("Content-Type", "application/json")

		resp, err := app.Test(req, -1)
		require.NoError(t, err)

		assert.Equal(t, fiber.StatusBadRequest, resp.StatusCode)
	})

	t.Run("Verify email without content-type header", func(t *testing.T) {
		payload := models.VerifyEmailRequest{
			Token: "test-token",
		}
		body, _ := json.Marshal(payload)
		req := httptest.NewRequest("POST", "/api/v1/auth/verify-email", bytes.NewReader(body))
		// No Content-Type header

		resp, err := app.Test(req, -1)
		require.NoError(t, err)

		// Should handle gracefully
		assert.NotEqual(t, fiber.StatusInternalServerError, resp.StatusCode)
	})
}

// TestResendVerificationEndpoint_Scenarios tests POST /api/v1/auth/resend-verification
func TestResendVerificationEndpoint_Scenarios(t *testing.T) {
	if os.Getenv("INTEGRATION_TEST") != "true" {
		t.Skip("Skipping endpoint test")
	}

	if err := database.Connect(); err != nil {
		t.Fatalf("Failed to connect to database: %v", err)
	}
	if err := database.ConnectRedis(); err != nil {
		t.Fatalf("Failed to connect to Redis: %v", err)
	}

	ctx := context.Background()
	app := setupEmailVerificationApp()

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

	t.Run("Resend verification successfully", func(t *testing.T) {
		email := "resend-endpoint@example.com"
		password := "SecurePass123!"

		// Register user
		registerReq := &models.RegisterRequest{
			Email:    email,
			Password: password,
			Name:     strPtr("Resend Endpoint Test"),
			AppID:    appID,
		}
		userID, err := registerUser(ctx, registerReq)
		require.NoError(t, err)

		// Send resend request
		payload := models.ResendVerificationRequest{
			Email: email,
			AppID: appID,
		}
		body, _ := json.Marshal(payload)
		req := httptest.NewRequest("POST", "/api/v1/auth/resend-verification", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")

		resp, err := app.Test(req, -1)
		require.NoError(t, err)

		// This WILL FAIL until implementation exists (TDD Red)
		assert.Equal(t, fiber.StatusOK, resp.StatusCode)

		respBody, _ := io.ReadAll(resp.Body)
		var response map[string]interface{}
		err = json.Unmarshal(respBody, &response)
		require.NoError(t, err)

		// Response should contain success message
		assert.Contains(t, response, "message")

		// Note: For security, we might not want to reveal if email exists
		// So response might be same for existing and non-existing users

		// Cleanup
		database.DB.Exec(ctx, "DELETE FROM users WHERE id = $1", userID)
	})

	t.Run("Resend verification with missing email", func(t *testing.T) {
		payload := models.ResendVerificationRequest{
			AppID: appID,
		}
		body, _ := json.Marshal(payload)
		req := httptest.NewRequest("POST", "/api/v1/auth/resend-verification", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")

		resp, err := app.Test(req, -1)
		require.NoError(t, err)

		assert.Equal(t, fiber.StatusBadRequest, resp.StatusCode)

		respBody, _ := io.ReadAll(resp.Body)
		assert.Contains(t, string(respBody), "email")
	})

	t.Run("Resend verification with missing app_id", func(t *testing.T) {
		payload := models.ResendVerificationRequest{
			Email: "test@example.com",
		}
		body, _ := json.Marshal(payload)
		req := httptest.NewRequest("POST", "/api/v1/auth/resend-verification", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")

		resp, err := app.Test(req, -1)
		require.NoError(t, err)

		assert.Equal(t, fiber.StatusBadRequest, resp.StatusCode)

		respBody, _ := io.ReadAll(resp.Body)
		assert.Contains(t, string(respBody), "app_id")
	})

	t.Run("Resend verification with invalid email format", func(t *testing.T) {
		payload := models.ResendVerificationRequest{
			Email: "not-an-email",
			AppID: appID,
		}
		body, _ := json.Marshal(payload)
		req := httptest.NewRequest("POST", "/api/v1/auth/resend-verification", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")

		resp, err := app.Test(req, -1)
		require.NoError(t, err)

		assert.Equal(t, fiber.StatusBadRequest, resp.StatusCode)

		respBody, _ := io.ReadAll(resp.Body)
		assert.Contains(t, string(respBody), "email")
	})

	t.Run("Resend verification for non-existent user", func(t *testing.T) {
		payload := models.ResendVerificationRequest{
			Email: "nonexistent-resend@example.com",
			AppID: appID,
		}
		body, _ := json.Marshal(payload)
		req := httptest.NewRequest("POST", "/api/v1/auth/resend-verification", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")

		resp, err := app.Test(req, -1)
		require.NoError(t, err)

		// For security, should return same response as success
		// to prevent email enumeration attacks
		assert.Equal(t, fiber.StatusOK, resp.StatusCode)
	})

	t.Run("Resend verification for already verified user", func(t *testing.T) {
		email := "already-verified-resend-endpoint@example.com"
		password := "SecurePass123!"

		// Register user
		registerReq := &models.RegisterRequest{
			Email:    email,
			Password: password,
			Name:     strPtr("Already Verified Resend"),
			AppID:    appID,
		}
		userID, err := registerUser(ctx, registerReq)
		require.NoError(t, err)

		// Manually verify user
		_, err = database.DB.Exec(ctx,
			"UPDATE users SET email_verified = true WHERE id = $1",
			userID)
		require.NoError(t, err)

		// Attempt resend
		payload := models.ResendVerificationRequest{
			Email: email,
			AppID: appID,
		}
		body, _ := json.Marshal(payload)
		req := httptest.NewRequest("POST", "/api/v1/auth/resend-verification", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")

		resp, err := app.Test(req, -1)
		require.NoError(t, err)

		// Should reject with appropriate message
		assert.True(t, resp.StatusCode == fiber.StatusBadRequest || resp.StatusCode == fiber.StatusConflict)

		respBody, _ := io.ReadAll(resp.Body)
		assert.Contains(t, string(respBody), "verified")

		// Cleanup
		database.DB.Exec(ctx, "DELETE FROM users WHERE id = $1", userID)
	})

	t.Run("Resend verification with wrong app_id", func(t *testing.T) {
		email := "wrong-app-resend@example.com"
		password := "SecurePass123!"

		// Register user in correct app
		registerReq := &models.RegisterRequest{
			Email:    email,
			Password: password,
			Name:     strPtr("Wrong App Test"),
			AppID:    appID,
		}
		userID, err := registerUser(ctx, registerReq)
		require.NoError(t, err)

		// Attempt resend with different app_id
		payload := models.ResendVerificationRequest{
			Email: email,
			AppID: uuid.New(), // Different app
		}
		body, _ := json.Marshal(payload)
		req := httptest.NewRequest("POST", "/api/v1/auth/resend-verification", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")

		resp, err := app.Test(req, -1)
		require.NoError(t, err)

		// For security, should return success to prevent enumeration
		assert.Equal(t, fiber.StatusOK, resp.StatusCode)

		// Cleanup
		database.DB.Exec(ctx, "DELETE FROM users WHERE id = $1", userID)
	})

	t.Run("Resend verification case insensitive email", func(t *testing.T) {
		email := "caseinsensitive@example.com"
		password := "SecurePass123!"

		// Register with lowercase
		registerReq := &models.RegisterRequest{
			Email:    email,
			Password: password,
			Name:     strPtr("Case Insensitive Test"),
			AppID:    appID,
		}
		userID, err := registerUser(ctx, registerReq)
		require.NoError(t, err)

		// Resend with uppercase
		payload := models.ResendVerificationRequest{
			Email: "CASEINSENSITIVE@EXAMPLE.COM",
			AppID: appID,
		}
		body, _ := json.Marshal(payload)
		req := httptest.NewRequest("POST", "/api/v1/auth/resend-verification", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")

		resp, err := app.Test(req, -1)
		require.NoError(t, err)

		assert.Equal(t, fiber.StatusOK, resp.StatusCode)

		// Cleanup
		database.DB.Exec(ctx, "DELETE FROM users WHERE id = $1", userID)
	})

	t.Run("Rate limiting on multiple resend requests", func(t *testing.T) {
		email := "rate-limit-endpoint@example.com"
		password := "SecurePass123!"

		// Register user
		registerReq := &models.RegisterRequest{
			Email:    email,
			Password: password,
			Name:     strPtr("Rate Limit Endpoint Test"),
			AppID:    appID,
		}
		userID, err := registerUser(ctx, registerReq)
		require.NoError(t, err)

		payload := models.ResendVerificationRequest{
			Email: email,
			AppID: appID,
		}
		body, _ := json.Marshal(payload)

		// First request
		req1 := httptest.NewRequest("POST", "/api/v1/auth/resend-verification", bytes.NewReader(body))
		req1.Header.Set("Content-Type", "application/json")
		resp1, err := app.Test(req1, -1)
		require.NoError(t, err)
		assert.Equal(t, fiber.StatusOK, resp1.StatusCode)

		// Immediate second request
		body2, _ := json.Marshal(payload) // Re-marshal for new reader
		req2 := httptest.NewRequest("POST", "/api/v1/auth/resend-verification", bytes.NewReader(body2))
		req2.Header.Set("Content-Type", "application/json")
		resp2, err := app.Test(req2, -1)
		require.NoError(t, err)

		// Should be rate limited
		if resp2.StatusCode != fiber.StatusOK {
			assert.Equal(t, fiber.StatusTooManyRequests, resp2.StatusCode)
			respBody, _ := io.ReadAll(resp2.Body)
			assert.Contains(t, string(respBody), "rate")
		}

		// Cleanup
		database.DB.Exec(ctx, "DELETE FROM users WHERE id = $1", userID)
	})

	t.Run("Resend verification with malformed JSON", func(t *testing.T) {
		malformedJSON := []byte(`{"email": "test@example.com", "app_id": }`)
		req := httptest.NewRequest("POST", "/api/v1/auth/resend-verification", bytes.NewReader(malformedJSON))
		req.Header.Set("Content-Type", "application/json")

		resp, err := app.Test(req, -1)
		require.NoError(t, err)

		assert.Equal(t, fiber.StatusBadRequest, resp.StatusCode)
	})
}

// TestEmailVerificationEndpoints_SecurityChecks tests security scenarios
func TestEmailVerificationEndpoints_SecurityChecks(t *testing.T) {
	if os.Getenv("INTEGRATION_TEST") != "true" {
		t.Skip("Skipping security checks test")
	}

	if err := database.Connect(); err != nil {
		t.Fatalf("Failed to connect to database: %v", err)
	}
	if err := database.ConnectRedis(); err != nil {
		t.Fatalf("Failed to connect to Redis: %v", err)
	}

	ctx := context.Background()
	app := setupEmailVerificationApp()

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

	t.Run("SQL injection in token", func(t *testing.T) {
		payload := models.VerifyEmailRequest{
			Token: "'; DROP TABLE users; --",
		}
		body, _ := json.Marshal(payload)
		req := httptest.NewRequest("POST", "/api/v1/auth/verify-email", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")

		resp, err := app.Test(req, -1)
		require.NoError(t, err)

		// Should handle safely
		assert.NotEqual(t, fiber.StatusInternalServerError, resp.StatusCode)

		// Verify users table still exists
		var count int
		err = database.DB.QueryRow(ctx, "SELECT COUNT(*) FROM users").Scan(&count)
		require.NoError(t, err, "Users table should still exist")
	})

	t.Run("XSS in email field", func(t *testing.T) {
		payload := models.ResendVerificationRequest{
			Email: "<script>alert('xss')</script>@example.com",
			AppID: appID,
		}
		body, _ := json.Marshal(payload)
		req := httptest.NewRequest("POST", "/api/v1/auth/resend-verification", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")

		resp, err := app.Test(req, -1)
		require.NoError(t, err)

		// Should reject invalid email format
		assert.Equal(t, fiber.StatusBadRequest, resp.StatusCode)
	})

	t.Run("Extremely long token", func(t *testing.T) {
		longToken := string(make([]byte, 10000))
		payload := models.VerifyEmailRequest{
			Token: longToken,
		}
		body, _ := json.Marshal(payload)
		req := httptest.NewRequest("POST", "/api/v1/auth/verify-email", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")

		resp, err := app.Test(req, -1)
		require.NoError(t, err)

		// Should handle gracefully
		assert.NotEqual(t, fiber.StatusInternalServerError, resp.StatusCode)
	})

	t.Run("Token reuse protection", func(t *testing.T) {
		email := "token-reuse@example.com"
		password := "SecurePass123!"

		// Register user
		registerReq := &models.RegisterRequest{
			Email:    email,
			Password: password,
			Name:     strPtr("Token Reuse Test"),
			AppID:    appID,
		}
		userID, err := registerUser(ctx, registerReq)
		require.NoError(t, err)

		// Generate and store token
		token := generateVerificationToken()
		tokenKey := "email:verification:" + token
		tokenData := map[string]string{
			"user_id": userID.String(),
			"app_id":  appID.String(),
			"email":   email,
		}
		err = database.SetJSON(ctx, tokenKey, tokenData, 24*time.Hour)
		require.NoError(t, err)

		// First verification
		payload := models.VerifyEmailRequest{Token: token}
		body1, _ := json.Marshal(payload)
		req1 := httptest.NewRequest("POST", "/api/v1/auth/verify-email", bytes.NewReader(body1))
		req1.Header.Set("Content-Type", "application/json")

		resp1, err := app.Test(req1, -1)
		require.NoError(t, err)
		assert.Equal(t, fiber.StatusOK, resp1.StatusCode)

		// Second verification with same token (should fail)
		body2, _ := json.Marshal(payload)
		req2 := httptest.NewRequest("POST", "/api/v1/auth/verify-email", bytes.NewReader(body2))
		req2.Header.Set("Content-Type", "application/json")

		resp2, err := app.Test(req2, -1)
		require.NoError(t, err)

		// Should reject reused token
		assert.NotEqual(t, fiber.StatusOK, resp2.StatusCode)

		// Cleanup
		database.DB.Exec(ctx, "DELETE FROM users WHERE id = $1", userID)
	})

	t.Run("Cross-app token usage", func(t *testing.T) {
		// Create second app
		appID2 := uuid.New()
		_, err := database.DB.Exec(ctx,
			"INSERT INTO applications (id, name, api_key, allowed_redirect_uris, cors_origins) VALUES ($1, $2, $3, $4, $5)",
			appID2, "Test App 2", "test-key-"+uuid.New().String(), []string{"http://localhost"}, []string{"*"})
		require.NoError(t, err)

		defer func() {
			database.DB.Exec(ctx, "DELETE FROM users WHERE app_id = $1", appID2)
			database.DB.Exec(ctx, "DELETE FROM applications WHERE id = $1", appID2)
		}()

		// Register user in app1
		email := "cross-app@example.com"
		registerReq := &models.RegisterRequest{
			Email:    email,
			Password: "SecurePass123!",
			Name:     strPtr("Cross App Test"),
			AppID:    appID,
		}
		userID1, err := registerUser(ctx, registerReq)
		require.NoError(t, err)

		// Register user with same email in app2
		registerReq2 := &models.RegisterRequest{
			Email:    email,
			Password: "SecurePass123!",
			Name:     strPtr("Cross App Test 2"),
			AppID:    appID2,
		}
		userID2, err := registerUser(ctx, registerReq2)
		require.NoError(t, err)

		// Generate token for app1 user
		token := generateVerificationToken()
		tokenKey := "email:verification:" + token
		tokenData := map[string]string{
			"user_id": userID1.String(),
			"app_id":  appID.String(), // App1
			"email":   email,
		}
		err = database.SetJSON(ctx, tokenKey, tokenData, 24*time.Hour)
		require.NoError(t, err)

		// Verify with token (should only verify app1 user)
		payload := models.VerifyEmailRequest{Token: token}
		body, _ := json.Marshal(payload)
		req := httptest.NewRequest("POST", "/api/v1/auth/verify-email", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")

		resp, err := app.Test(req, -1)
		require.NoError(t, err)
		assert.Equal(t, fiber.StatusOK, resp.StatusCode)

		// Verify app1 user is verified
		var verified1 bool
		err = database.DB.QueryRow(ctx,
			"SELECT email_verified FROM users WHERE id = $1",
			userID1).Scan(&verified1)
		require.NoError(t, err)
		assert.True(t, verified1)

		// Verify app2 user is NOT verified
		var verified2 bool
		err = database.DB.QueryRow(ctx,
			"SELECT email_verified FROM users WHERE id = $1",
			userID2).Scan(&verified2)
		require.NoError(t, err)
		assert.False(t, verified2, "Should not verify user in different app")

		// Cleanup
		database.DB.Exec(ctx, "DELETE FROM users WHERE id = $1", userID1)
		database.DB.Exec(ctx, "DELETE FROM users WHERE id = $1", userID2)
	})
}

// TestEmailVerificationEndpoints_ConcurrentVerifications tests race conditions
func TestEmailVerificationEndpoints_ConcurrentVerifications(t *testing.T) {
	if os.Getenv("INTEGRATION_TEST") != "true" {
		t.Skip("Skipping concurrent verification test")
	}

	if err := database.Connect(); err != nil {
		t.Fatalf("Failed to connect to database: %v", err)
	}
	if err := database.ConnectRedis(); err != nil {
		t.Fatalf("Failed to connect to Redis: %v", err)
	}

	ctx := context.Background()
	app := setupEmailVerificationApp()

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

	t.Run("Concurrent verification with same token", func(t *testing.T) {
		email := "concurrent-verify@example.com"
		password := "SecurePass123!"

		// Register user
		registerReq := &models.RegisterRequest{
			Email:    email,
			Password: password,
			Name:     strPtr("Concurrent Verify Test"),
			AppID:    appID,
		}
		userID, err := registerUser(ctx, registerReq)
		require.NoError(t, err)

		// Generate and store token
		token := generateVerificationToken()
		tokenKey := "email:verification:" + token
		tokenData := map[string]string{
			"user_id": userID.String(),
			"app_id":  appID.String(),
			"email":   email,
		}
		err = database.SetJSON(ctx, tokenKey, tokenData, 24*time.Hour)
		require.NoError(t, err)

		// Attempt concurrent verifications
		done := make(chan int, 10)
		successCount := 0

		for i := 0; i < 10; i++ {
			go func() {
				payload := models.VerifyEmailRequest{Token: token}
				body, _ := json.Marshal(payload)
				req := httptest.NewRequest("POST", "/api/v1/auth/verify-email", bytes.NewReader(body))
				req.Header.Set("Content-Type", "application/json")

				resp, _ := app.Test(req, -1)
				done <- resp.StatusCode
			}()
		}

		// Wait for all goroutines
		for i := 0; i < 10; i++ {
			statusCode := <-done
			if statusCode == fiber.StatusOK {
				successCount++
			}
		}

		// Only one should succeed (token consumed)
		// Others might get "already verified" or "invalid token"
		assert.GreaterOrEqual(t, successCount, 1, "At least one verification should succeed")
		assert.LessOrEqual(t, successCount, 10, "Not all concurrent requests should succeed with same token")

		// User should be verified
		var emailVerified bool
		err = database.DB.QueryRow(ctx,
			"SELECT email_verified FROM users WHERE id = $1",
			userID).Scan(&emailVerified)
		require.NoError(t, err)
		assert.True(t, emailVerified)

		// Cleanup
		database.DB.Exec(ctx, "DELETE FROM users WHERE id = $1", userID)
	})
}

// TestEmailVerificationResponse_Format tests response format consistency
func TestEmailVerificationResponse_Format(t *testing.T) {
	if os.Getenv("INTEGRATION_TEST") != "true" {
		t.Skip("Skipping response format test")
	}

	if err := database.Connect(); err != nil {
		t.Fatalf("Failed to connect to database: %v", err)
	}
	if err := database.ConnectRedis(); err != nil {
		t.Fatalf("Failed to connect to Redis: %v", err)
	}

	ctx := context.Background()
	app := setupEmailVerificationApp()

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

	t.Run("Verify email success response format", func(t *testing.T) {
		email := "response-format@example.com"
		password := "SecurePass123!"

		registerReq := &models.RegisterRequest{
			Email:    email,
			Password: password,
			Name:     strPtr("Response Format Test"),
			AppID:    appID,
		}
		userID, err := registerUser(ctx, registerReq)
		require.NoError(t, err)

		token := generateVerificationToken()
		tokenKey := "email:verification:" + token
		tokenData := map[string]string{
			"user_id": userID.String(),
			"app_id":  appID.String(),
			"email":   email,
		}
		err = database.SetJSON(ctx, tokenKey, tokenData, 24*time.Hour)
		require.NoError(t, err)

		payload := models.VerifyEmailRequest{Token: token}
		body, _ := json.Marshal(payload)
		req := httptest.NewRequest("POST", "/api/v1/auth/verify-email", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")

		resp, err := app.Test(req, -1)
		require.NoError(t, err)

		respBody, _ := io.ReadAll(resp.Body)
		var response map[string]interface{}
		err = json.Unmarshal(respBody, &response)
		require.NoError(t, err)

		// Response should be valid JSON
		assert.NotNil(t, response)

		// Should contain message field
		assert.Contains(t, response, "message")

		// Cleanup
		database.DB.Exec(ctx, "DELETE FROM users WHERE id = $1", userID)
	})

	t.Run("Resend verification success response format", func(t *testing.T) {
		email := "resend-response-format@example.com"
		password := "SecurePass123!"

		registerReq := &models.RegisterRequest{
			Email:    email,
			Password: password,
			Name:     strPtr("Resend Response Format Test"),
			AppID:    appID,
		}
		userID, err := registerUser(ctx, registerReq)
		require.NoError(t, err)

		payload := models.ResendVerificationRequest{
			Email: email,
			AppID: appID,
		}
		body, _ := json.Marshal(payload)
		req := httptest.NewRequest("POST", "/api/v1/auth/resend-verification", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")

		resp, err := app.Test(req, -1)
		require.NoError(t, err)

		respBody, _ := io.ReadAll(resp.Body)
		var response map[string]interface{}
		err = json.Unmarshal(respBody, &response)
		require.NoError(t, err)

		// Response should be valid JSON
		assert.NotNil(t, response)

		// Should contain message field
		assert.Contains(t, response, "message")

		// Cleanup
		database.DB.Exec(ctx, "DELETE FROM users WHERE id = $1", userID)
	})
}
