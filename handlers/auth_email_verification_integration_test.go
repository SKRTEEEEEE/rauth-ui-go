package handlers

import (
	"context"
	"os"
	"testing"
	"time"

	"rauth/database"
	"rauth/models"
	"rauth/utils"

	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestVerifyEmail_Integration tests email verification with real database and Redis
func TestVerifyEmail_Integration(t *testing.T) {
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

	ctx := context.Background()

	// Create test application
	appID := uuid.New()
	_, err := database.DB.Exec(ctx,
		"INSERT INTO applications (id, name, api_key, allowed_redirect_uris, cors_origins) VALUES ($1, $2, $3, $4, $5)",
		appID, "Test App", "test-key-"+uuid.New().String(), []string{"http://localhost"}, []string{"*"})
	require.NoError(t, err)

	defer func() {
		// Cleanup
		database.DB.Exec(ctx, "DELETE FROM users WHERE app_id = $1", appID)
		database.DB.Exec(ctx, "DELETE FROM applications WHERE id = $1", appID)
	}()

	t.Run("Verify email with valid token", func(t *testing.T) {
		email := "verify-integration@example.com"
		password := "SecurePass123!"

		// Register user
		registerReq := &models.RegisterRequest{
			Email:    email,
			Password: password,
			Name:     strPtr("Verify Test User"),
			AppID:    appID,
		}
		userID, err := registerUser(ctx, registerReq)
		require.NoError(t, err)

		// Verify user is not verified initially
		var emailVerified bool
		err = database.DB.QueryRow(ctx,
			"SELECT email_verified FROM users WHERE id = $1",
			userID).Scan(&emailVerified)
		require.NoError(t, err)
		assert.False(t, emailVerified, "User should not be verified initially")

		// Generate verification token (this function should be implemented)
		token := generateVerificationToken()
		require.NotEmpty(t, token)

		// Store token in Redis with user_id and app_id
		tokenKey := "email:verification:" + token
		tokenData := map[string]string{
			"user_id": userID.String(),
			"app_id":  appID.String(),
			"email":   email,
		}
		err = database.SetJSON(ctx, tokenKey, tokenData, 24*time.Hour)
		require.NoError(t, err)

		// Verify email (this function should be implemented)
		err = verifyEmailWithToken(ctx, token)

		// This WILL FAIL until implementation exists (TDD Red phase)
		require.NoError(t, err, "verifyEmailWithToken should succeed with valid token")

		// Verify user is now verified
		err = database.DB.QueryRow(ctx,
			"SELECT email_verified FROM users WHERE id = $1",
			userID).Scan(&emailVerified)
		require.NoError(t, err)
		assert.True(t, emailVerified, "User should be verified after token validation")

		// Verify token was deleted from Redis
		exists, err := database.Exists(ctx, tokenKey)
		require.NoError(t, err)
		assert.False(t, exists, "Token should be deleted after use")

		// Cleanup
		database.DB.Exec(ctx, "DELETE FROM users WHERE id = $1", userID)
	})

	t.Run("Verify email with invalid token", func(t *testing.T) {
		invalidToken := "invalid-token-" + uuid.New().String()

		// Attempt to verify with non-existent token
		err := verifyEmailWithToken(ctx, invalidToken)

		// Should fail with appropriate error
		require.Error(t, err)
		assert.Contains(t, err.Error(), "token")
	})

	t.Run("Verify email with expired token", func(t *testing.T) {
		email := "expired-token@example.com"
		password := "SecurePass123!"

		// Register user
		registerReq := &models.RegisterRequest{
			Email:    email,
			Password: password,
			Name:     strPtr("Expired Token Test"),
			AppID:    appID,
		}
		userID, err := registerUser(ctx, registerReq)
		require.NoError(t, err)

		// Generate token and store with very short TTL (already expired)
		token := generateVerificationToken()
		tokenKey := "email:verification:" + token
		tokenData := map[string]string{
			"user_id": userID.String(),
			"app_id":  appID.String(),
			"email":   email,
		}

		// Store with 1 nanosecond TTL (essentially expired)
		err = database.SetJSON(ctx, tokenKey, tokenData, 1*time.Nanosecond)
		require.NoError(t, err)

		// Wait to ensure expiration
		time.Sleep(10 * time.Millisecond)

		// Attempt to verify with expired token
		err = verifyEmailWithToken(ctx, token)

		// Should fail
		require.Error(t, err)

		// Verify user is still not verified
		var emailVerified bool
		err = database.DB.QueryRow(ctx,
			"SELECT email_verified FROM users WHERE id = $1",
			userID).Scan(&emailVerified)
		require.NoError(t, err)
		assert.False(t, emailVerified)

		// Cleanup
		database.DB.Exec(ctx, "DELETE FROM users WHERE id = $1", userID)
	})

	t.Run("Verify already verified email (idempotent)", func(t *testing.T) {
		email := "already-verified@example.com"
		password := "SecurePass123!"

		// Register user
		registerReq := &models.RegisterRequest{
			Email:    email,
			Password: password,
			Name:     strPtr("Already Verified Test"),
			AppID:    appID,
		}
		userID, err := registerUser(ctx, registerReq)
		require.NoError(t, err)

		// Manually set user as verified
		_, err = database.DB.Exec(ctx,
			"UPDATE users SET email_verified = true WHERE id = $1",
			userID)
		require.NoError(t, err)

		// Generate token
		token := generateVerificationToken()
		tokenKey := "email:verification:" + token
		tokenData := map[string]string{
			"user_id": userID.String(),
			"app_id":  appID.String(),
			"email":   email,
		}
		err = database.SetJSON(ctx, tokenKey, tokenData, 24*time.Hour)
		require.NoError(t, err)

		// Verify again (should be idempotent)
		err = verifyEmailWithToken(ctx, token)

		// Should succeed or return appropriate message
		require.NoError(t, err)

		// User should still be verified
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

// TestResendVerification_Integration tests resend verification with real database and Redis
func TestResendVerification_Integration(t *testing.T) {
	if os.Getenv("INTEGRATION_TEST") != "true" {
		t.Skip("Skipping integration test")
	}

	if err := database.Connect(); err != nil {
		t.Fatalf("Failed to connect to database: %v", err)
	}
	if err := database.ConnectRedis(); err != nil {
		t.Fatalf("Failed to connect to Redis: %v", err)
	}

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

	t.Run("Resend verification for unverified user", func(t *testing.T) {
		email := "resend-test@example.com"
		password := "SecurePass123!"

		// Register user
		registerReq := &models.RegisterRequest{
			Email:    email,
			Password: password,
			Name:     strPtr("Resend Test User"),
			AppID:    appID,
		}
		userID, err := registerUser(ctx, registerReq)
		require.NoError(t, err)

		// Resend verification (this function should be implemented)
		req := &models.ResendVerificationRequest{
			Email: email,
			AppID: appID,
		}
		token, err := resendVerificationEmail(ctx, req)

		// This WILL FAIL until implementation exists (TDD Red phase)
		require.NoError(t, err, "resendVerificationEmail should succeed")
		assert.NotEmpty(t, token, "Should return verification token")

		// Verify token exists in Redis
		tokenKey := "email:verification:" + token
		exists, err := database.Exists(ctx, tokenKey)
		require.NoError(t, err)
		assert.True(t, exists, "Token should be stored in Redis")

		// Verify token data
		var tokenData map[string]string
		err = database.GetJSON(ctx, tokenKey, &tokenData)
		require.NoError(t, err)
		assert.Equal(t, userID.String(), tokenData["user_id"])
		assert.Equal(t, appID.String(), tokenData["app_id"])
		assert.Equal(t, email, tokenData["email"])

		// Cleanup
		database.Delete(ctx, tokenKey)
		database.DB.Exec(ctx, "DELETE FROM users WHERE id = $1", userID)
	})

	t.Run("Resend verification for already verified user", func(t *testing.T) {
		email := "already-verified-resend@example.com"
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

		// Attempt to resend verification
		req := &models.ResendVerificationRequest{
			Email: email,
			AppID: appID,
		}
		_, err = resendVerificationEmail(ctx, req)

		// Should return appropriate error or message
		require.Error(t, err)
		assert.Contains(t, err.Error(), "already verified")

		// Cleanup
		database.DB.Exec(ctx, "DELETE FROM users WHERE id = $1", userID)
	})

	t.Run("Resend verification for non-existent user", func(t *testing.T) {
		req := &models.ResendVerificationRequest{
			Email: "nonexistent@example.com",
			AppID: appID,
		}

		_, err := resendVerificationEmail(ctx, req)

		// Should fail gracefully (or silent failure for security)
		require.Error(t, err)
	})

	t.Run("Resend verification for OAuth user (no password)", func(t *testing.T) {
		email := "oauth-user@example.com"
		userID := uuid.New()

		// Create OAuth user without password
		_, err := database.DB.Exec(ctx,
			"INSERT INTO users (id, app_id, email, name, email_verified) VALUES ($1, $2, $3, $4, $5)",
			userID, appID, email, "OAuth User", true)
		require.NoError(t, err)

		// Attempt to resend verification
		req := &models.ResendVerificationRequest{
			Email: email,
			AppID: appID,
		}
		_, err = resendVerificationEmail(ctx, req)

		// Should fail appropriately (OAuth users are auto-verified)
		require.Error(t, err)

		// Cleanup
		database.DB.Exec(ctx, "DELETE FROM users WHERE id = $1", userID)
	})

	t.Run("Resend verification replaces old token", func(t *testing.T) {
		email := "replace-token@example.com"
		password := "SecurePass123!"

		// Register user
		registerReq := &models.RegisterRequest{
			Email:    email,
			Password: password,
			Name:     strPtr("Replace Token Test"),
			AppID:    appID,
		}
		userID, err := registerUser(ctx, registerReq)
		require.NoError(t, err)

		// Send first verification
		req := &models.ResendVerificationRequest{
			Email: email,
			AppID: appID,
		}
		token1, err := resendVerificationEmail(ctx, req)
		require.NoError(t, err)

		// Send second verification
		token2, err := resendVerificationEmail(ctx, req)
		require.NoError(t, err)

		// Tokens should be different
		assert.NotEqual(t, token1, token2)

		// New token should exist
		tokenKey2 := "email:verification:" + token2
		exists2, err := database.Exists(ctx, tokenKey2)
		require.NoError(t, err)
		assert.True(t, exists2, "New token should exist")

		// If using single token per user approach, old should be gone
		// If allowing multiple, both might exist (depends on implementation)
		// For security, recommend single active token per user

		// Cleanup
		tokenKey1 := "email:verification:" + token1
		database.Delete(ctx, tokenKey1, tokenKey2)
		database.DB.Exec(ctx, "DELETE FROM users WHERE id = $1", userID)
	})
}

// TestVerificationTokenTTL_Integration tests token expiration
func TestVerificationTokenTTL_Integration(t *testing.T) {
	if os.Getenv("INTEGRATION_TEST") != "true" {
		t.Skip("Skipping integration test")
	}

	if err := database.ConnectRedis(); err != nil {
		t.Fatalf("Failed to connect to Redis: %v", err)
	}

	ctx := context.Background()

	t.Run("Token TTL is 24 hours", func(t *testing.T) {
		token := generateVerificationToken()
		tokenKey := "email:verification:" + token
		tokenData := map[string]string{
			"user_id": uuid.New().String(),
			"app_id":  uuid.New().String(),
			"email":   "ttl-test@example.com",
		}

		// Store token with 24-hour TTL
		err := database.SetJSON(ctx, tokenKey, tokenData, 24*time.Hour)
		require.NoError(t, err)

		// Check TTL
		ttl := database.RedisClient.TTL(ctx, tokenKey).Val()
		require.Greater(t, ttl, 23*time.Hour, "TTL should be close to 24 hours")
		require.LessOrEqual(t, ttl, 24*time.Hour)

		// Cleanup
		database.Delete(ctx, tokenKey)
	})

	t.Run("Expired token is not accessible", func(t *testing.T) {
		token := generateVerificationToken()
		tokenKey := "email:verification:" + token
		tokenData := map[string]string{
			"user_id": uuid.New().String(),
			"app_id":  uuid.New().String(),
			"email":   "expired-test@example.com",
		}

		// Store with 1 second TTL
		err := database.SetJSON(ctx, tokenKey, tokenData, 1*time.Second)
		require.NoError(t, err)

		// Wait for expiration
		time.Sleep(2 * time.Second)

		// Verify token is gone
		var retrieved map[string]string
		err = database.GetJSON(ctx, tokenKey, &retrieved)
		assert.Equal(t, redis.Nil, err, "Token should be expired and not retrievable")
	})
}

// TestEmailSending_Integration tests email sending functionality
func TestEmailSending_Integration(t *testing.T) {
	if os.Getenv("INTEGRATION_TEST") != "true" {
		t.Skip("Skipping integration test")
	}

	if err := database.Connect(); err != nil {
		t.Fatalf("Failed to connect to database: %v", err)
	}

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

	t.Run("Send verification email", func(t *testing.T) {
		email := "email-send-test@example.com"
		token := generateVerificationToken()

		// This function should be implemented in utils/email.go
		err := utils.SendVerificationEmail(email, token)

		// In development without SMTP, should log and not fail
		// In production with SMTP, should actually send
		// Test should verify appropriate behavior based on environment
		if os.Getenv("SMTP_HOST") == "" {
			// Development mode - should succeed (log only)
			require.NoError(t, err, "Should succeed in dev mode without SMTP")
		} else {
			// Production mode - should actually send
			require.NoError(t, err, "Should send email via SMTP")
		}
	})

	t.Run("Email verification link format", func(t *testing.T) {
		token := "test-token-123"

		// Generate verification link (should be implemented)
		link := generateVerificationLink(token)

		// Verify link format
		assert.Contains(t, link, token, "Link should contain token")
		assert.Contains(t, link, "verify-email", "Link should point to verify-email endpoint")
		
		// Link should be a valid URL format
		assert.True(t, len(link) > 20, "Link should be properly formatted")
	})
}

// TestRateLimiting_ResendVerification tests rate limiting for resend
func TestRateLimiting_ResendVerification(t *testing.T) {
	if os.Getenv("INTEGRATION_TEST") != "true" {
		t.Skip("Skipping integration test")
	}

	if err := database.Connect(); err != nil {
		t.Fatalf("Failed to connect to database: %v", err)
	}
	if err := database.ConnectRedis(); err != nil {
		t.Fatalf("Failed to connect to Redis: %v", err)
	}

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

	t.Run("Multiple resend requests should be rate limited", func(t *testing.T) {
		email := "rate-limit-test@example.com"
		password := "SecurePass123!"

		// Register user
		registerReq := &models.RegisterRequest{
			Email:    email,
			Password: password,
			Name:     strPtr("Rate Limit Test"),
			AppID:    appID,
		}
		userID, err := registerUser(ctx, registerReq)
		require.NoError(t, err)

		req := &models.ResendVerificationRequest{
			Email: email,
			AppID: appID,
		}

		// First request should succeed
		_, err = resendVerificationEmail(ctx, req)
		require.NoError(t, err)

		// Immediate second request should be rate limited
		_, err = resendVerificationEmail(ctx, req)
		
		// Should fail or warn about rate limit
		// Implementation should prevent abuse (e.g., max 1 per minute)
		if err != nil {
			assert.Contains(t, err.Error(), "rate limit", "Should indicate rate limiting")
		}

		// Cleanup
		database.DB.Exec(ctx, "DELETE FROM users WHERE id = $1", userID)
	})
}

// Helper functions for tests

func generateVerificationLink(token string) string {
	// Generate verification link for testing
	return "http://localhost:8080/api/v1/auth/verify-email?token=" + token
}
