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
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestForgotPassword_Integration tests password reset request with real database and Redis
func TestForgotPassword_Integration(t *testing.T) {
	if os.Getenv("INTEGRATION_TEST") != "true" {
		t.Skip("Skipping integration test")
	}

	// Initialize database connection
	if err := database.Connect(); err != nil {
		t.Fatalf("Failed to connect to database: %v", err)
	}

	// Initialize Redis connection
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

	t.Run("ForgotPassword generates reset token successfully", func(t *testing.T) {
		// Create test user
		email := "reset-test@example.com"
		userID := uuid.New()
		passwordHash, _ := utils.HashPassword("OldPassword123!")

		_, err := database.DB.Exec(ctx,
			`INSERT INTO users (id, app_id, email, password_hash, name, email_verified, created_at, updated_at)
			 VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
			userID, appID, email, passwordHash, "Reset Test User", true, time.Now(), time.Now())
		require.NoError(t, err)

		req := &models.ForgotPasswordRequest{
			Email: email,
			AppID: appID,
		}

		// This will fail until implementation exists (TDD Red phase)
		token, err := forgotPassword(ctx, req)
		require.NoError(t, err)
		assert.NotEmpty(t, token)

		// Verify token was stored in Redis with correct TTL
		storedEmail, err := database.GetString(ctx, "reset:"+token)
		require.NoError(t, err)
		assert.Equal(t, email, storedEmail)

		// Cleanup
		database.DB.Exec(ctx, "DELETE FROM users WHERE id = $1", userID)
		database.Delete(ctx, "reset:"+token)
	})

	t.Run("ForgotPassword doesn't reveal if email doesn't exist", func(t *testing.T) {
		req := &models.ForgotPasswordRequest{
			Email: "nonexistent@example.com",
			AppID: appID,
		}

		// Should succeed even if email doesn't exist (security best practice)
		token, err := forgotPassword(ctx, req)
		require.NoError(t, err)
		// Token should be empty or no-op for non-existent email
		assert.Empty(t, token)
	})

	t.Run("ForgotPassword replaces old token with new one", func(t *testing.T) {
		// Create test user
		email := "replace-token@example.com"
		userID := uuid.New()
		passwordHash, _ := utils.HashPassword("OldPassword123!")

		_, err := database.DB.Exec(ctx,
			`INSERT INTO users (id, app_id, email, password_hash, name, email_verified, created_at, updated_at)
			 VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
			userID, appID, email, passwordHash, "Replace Token Test", true, time.Now(), time.Now())
		require.NoError(t, err)

		req := &models.ForgotPasswordRequest{
			Email: email,
			AppID: appID,
		}

		// Generate first token
		token1, err := forgotPassword(ctx, req)
		require.NoError(t, err)

		time.Sleep(100 * time.Millisecond)

		// Generate second token
		token2, err := forgotPassword(ctx, req)
		require.NoError(t, err)
		assert.NotEqual(t, token1, token2)

		// Old token should be invalid
		_, err = database.GetString(ctx, "reset:"+token1)
		assert.Error(t, err) // Should not exist

		// New token should be valid
		storedEmail, err := database.GetString(ctx, "reset:"+token2)
		require.NoError(t, err)
		assert.Equal(t, email, storedEmail)

		// Cleanup
		database.DB.Exec(ctx, "DELETE FROM users WHERE id = $1", userID)
		database.Delete(ctx, "reset:"+token2)
	})

	t.Run("ForgotPassword token expires after 1 hour", func(t *testing.T) {
		// Create test user
		email := "ttl-test@example.com"
		userID := uuid.New()
		passwordHash, _ := utils.HashPassword("OldPassword123!")

		_, err := database.DB.Exec(ctx,
			`INSERT INTO users (id, app_id, email, password_hash, name, email_verified, created_at, updated_at)
			 VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
			userID, appID, email, passwordHash, "TTL Test User", true, time.Now(), time.Now())
		require.NoError(t, err)

		req := &models.ForgotPasswordRequest{
			Email: email,
			AppID: appID,
		}

		token, err := forgotPassword(ctx, req)
		require.NoError(t, err)

		// Verify TTL is set to approximately 1 hour
		ttl, err := database.RedisClient.TTL(ctx, "reset:"+token).Result()
		require.NoError(t, err)
		assert.Greater(t, ttl, 55*time.Minute) // Allow some variance
		assert.LessOrEqual(t, ttl, 60*time.Minute)

		// Cleanup
		database.DB.Exec(ctx, "DELETE FROM users WHERE id = $1", userID)
		database.Delete(ctx, "reset:"+token)
	})
}

// TestResetPassword_Integration tests password reset with real database and Redis
func TestResetPassword_Integration(t *testing.T) {
	if os.Getenv("INTEGRATION_TEST") != "true" {
		t.Skip("Skipping integration test")
	}

	// Initialize database connection
	if err := database.Connect(); err != nil {
		t.Fatalf("Failed to connect to database: %v", err)
	}

	// Initialize Redis connection
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

	t.Run("ResetPassword updates password successfully", func(t *testing.T) {
		// Create test user
		email := "reset-update@example.com"
		userID := uuid.New()
		oldPassword := "OldPassword123!"
		passwordHash, _ := utils.HashPassword(oldPassword)

		_, err := database.DB.Exec(ctx,
			`INSERT INTO users (id, app_id, email, password_hash, name, email_verified, created_at, updated_at)
			 VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
			userID, appID, email, passwordHash, "Reset Update Test", true, time.Now(), time.Now())
		require.NoError(t, err)

		// Generate reset token
		resetToken := uuid.New().String()
		err = database.SetString(ctx, "reset:"+resetToken, email, 1*time.Hour)
		require.NoError(t, err)

		req := &models.ResetPasswordRequest{
			Token:       resetToken,
			NewPassword: "NewSecurePass456!",
		}

		// This will fail until implementation exists (TDD Red phase)
		err = resetPassword(ctx, req)
		require.NoError(t, err)

		// Verify password was updated
		var newPasswordHash string
		err = database.DB.QueryRow(ctx,
			"SELECT password_hash FROM users WHERE id = $1",
			userID).Scan(&newPasswordHash)
		require.NoError(t, err)

		// Verify new password works
		assert.True(t, utils.ComparePassword(newPasswordHash, req.NewPassword))
		// Verify old password doesn't work
		assert.False(t, utils.ComparePassword(newPasswordHash, oldPassword))

		// Verify token was deleted (one-time use)
		_, err = database.GetString(ctx, "reset:"+resetToken)
		assert.Error(t, err) // Token should not exist

		// Cleanup
		database.DB.Exec(ctx, "DELETE FROM users WHERE id = $1", userID)
	})

	t.Run("ResetPassword invalidates all sessions", func(t *testing.T) {
		// Create test user
		email := "invalidate-sessions@example.com"
		userID := uuid.New()
		passwordHash, _ := utils.HashPassword("OldPassword123!")

		_, err := database.DB.Exec(ctx,
			`INSERT INTO users (id, app_id, email, password_hash, name, email_verified, created_at, updated_at)
			 VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
			userID, appID, email, passwordHash, "Session Test", true, time.Now(), time.Now())
		require.NoError(t, err)

		// Create multiple sessions for the user
		session1ID := uuid.New()
		session2ID := uuid.New()
		tokenHash1 := utils.HashToken("token1")
		tokenHash2 := utils.HashToken("token2")

		_, err = database.DB.Exec(ctx,
			`INSERT INTO sessions (id, user_id, app_id, token_hash, ip_address, user_agent, expires_at, created_at, last_used_at)
			 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
			session1ID, userID, appID, tokenHash1, "127.0.0.1", "test", time.Now().Add(24*time.Hour), time.Now(), time.Now())
		require.NoError(t, err)

		_, err = database.DB.Exec(ctx,
			`INSERT INTO sessions (id, user_id, app_id, token_hash, ip_address, user_agent, expires_at, created_at, last_used_at)
			 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
			session2ID, userID, appID, tokenHash2, "127.0.0.1", "test", time.Now().Add(24*time.Hour), time.Now(), time.Now())
		require.NoError(t, err)

		// Generate reset token
		resetToken := uuid.New().String()
		err = database.SetString(ctx, "reset:"+resetToken, email, 1*time.Hour)
		require.NoError(t, err)

		req := &models.ResetPasswordRequest{
			Token:       resetToken,
			NewPassword: "NewSecurePass456!",
		}

		err = resetPassword(ctx, req)
		require.NoError(t, err)

		// Verify all sessions were deleted
		var sessionCount int
		err = database.DB.QueryRow(ctx,
			"SELECT COUNT(*) FROM sessions WHERE user_id = $1",
			userID).Scan(&sessionCount)
		require.NoError(t, err)
		assert.Equal(t, 0, sessionCount, "All sessions should be invalidated after password reset")

		// Cleanup
		database.DB.Exec(ctx, "DELETE FROM users WHERE id = $1", userID)
	})

	t.Run("ResetPassword fails with invalid token", func(t *testing.T) {
		req := &models.ResetPasswordRequest{
			Token:       "invalid-token-12345",
			NewPassword: "NewSecurePass456!",
		}

		err := resetPassword(ctx, req)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid")
	})

	t.Run("ResetPassword fails with expired token", func(t *testing.T) {
		// Create test user
		email := "expired-token@example.com"
		userID := uuid.New()
		passwordHash, _ := utils.HashPassword("OldPassword123!")

		_, err := database.DB.Exec(ctx,
			`INSERT INTO users (id, app_id, email, password_hash, name, email_verified, created_at, updated_at)
			 VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
			userID, appID, email, passwordHash, "Expired Token Test", true, time.Now(), time.Now())
		require.NoError(t, err)

		// Generate reset token with very short TTL
		resetToken := uuid.New().String()
		err = database.SetString(ctx, "reset:"+resetToken, email, 1*time.Millisecond)
		require.NoError(t, err)

		// Wait for token to expire
		time.Sleep(10 * time.Millisecond)

		req := &models.ResetPasswordRequest{
			Token:       resetToken,
			NewPassword: "NewSecurePass456!",
		}

		err = resetPassword(ctx, req)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid")

		// Cleanup
		database.DB.Exec(ctx, "DELETE FROM users WHERE id = $1", userID)
	})

	t.Run("ResetPassword token can only be used once", func(t *testing.T) {
		// Create test user
		email := "one-time-token@example.com"
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

		req := &models.ResetPasswordRequest{
			Token:       resetToken,
			NewPassword: "NewSecurePass456!",
		}

		// First use should succeed
		err = resetPassword(ctx, req)
		require.NoError(t, err)

		// Second use should fail (token deleted after first use)
		req.NewPassword = "AnotherPassword789!"
		err = resetPassword(ctx, req)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid")

		// Cleanup
		database.DB.Exec(ctx, "DELETE FROM users WHERE id = $1", userID)
	})
}

// TestChangePassword_Integration tests authenticated password change with real database
func TestChangePassword_Integration(t *testing.T) {
	if os.Getenv("INTEGRATION_TEST") != "true" {
		t.Skip("Skipping integration test")
	}

	// Initialize database connection
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
		// Cleanup
		database.DB.Exec(ctx, "DELETE FROM users WHERE app_id = $1", appID)
		database.DB.Exec(ctx, "DELETE FROM applications WHERE id = $1", appID)
	}()

	t.Run("ChangePassword updates password successfully", func(t *testing.T) {
		// Create test user
		email := "change-pass@example.com"
		userID := uuid.New()
		currentPassword := "CurrentPass123!"
		passwordHash, _ := utils.HashPassword(currentPassword)

		_, err := database.DB.Exec(ctx,
			`INSERT INTO users (id, app_id, email, password_hash, name, email_verified, created_at, updated_at)
			 VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
			userID, appID, email, passwordHash, "Change Pass Test", true, time.Now(), time.Now())
		require.NoError(t, err)

		req := &models.ChangePasswordRequest{
			CurrentPassword: currentPassword,
			NewPassword:     "NewStrongPass456!",
		}

		// This will fail until implementation exists (TDD Red phase)
		err = changePassword(ctx, userID, req)
		require.NoError(t, err)

		// Verify password was updated
		var newPasswordHash string
		err = database.DB.QueryRow(ctx,
			"SELECT password_hash FROM users WHERE id = $1",
			userID).Scan(&newPasswordHash)
		require.NoError(t, err)

		// Verify new password works
		assert.True(t, utils.ComparePassword(newPasswordHash, req.NewPassword))
		// Verify old password doesn't work
		assert.False(t, utils.ComparePassword(newPasswordHash, currentPassword))

		// Cleanup
		database.DB.Exec(ctx, "DELETE FROM users WHERE id = $1", userID)
	})

	t.Run("ChangePassword fails with wrong current password", func(t *testing.T) {
		// Create test user
		email := "wrong-pass@example.com"
		userID := uuid.New()
		currentPassword := "CurrentPass123!"
		passwordHash, _ := utils.HashPassword(currentPassword)

		_, err := database.DB.Exec(ctx,
			`INSERT INTO users (id, app_id, email, password_hash, name, email_verified, created_at, updated_at)
			 VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
			userID, appID, email, passwordHash, "Wrong Pass Test", true, time.Now(), time.Now())
		require.NoError(t, err)

		req := &models.ChangePasswordRequest{
			CurrentPassword: "WrongPassword999!",
			NewPassword:     "NewStrongPass456!",
		}

		err = changePassword(ctx, userID, req)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "current password is incorrect")

		// Cleanup
		database.DB.Exec(ctx, "DELETE FROM users WHERE id = $1", userID)
	})

	t.Run("ChangePassword fails for OAuth users without password", func(t *testing.T) {
		// Create OAuth user (no password_hash)
		email := "oauth-user@example.com"
		userID := uuid.New()

		_, err := database.DB.Exec(ctx,
			`INSERT INTO users (id, app_id, email, password_hash, name, email_verified, created_at, updated_at)
			 VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
			userID, appID, email, nil, "OAuth User", true, time.Now(), time.Now())
		require.NoError(t, err)

		req := &models.ChangePasswordRequest{
			CurrentPassword: "anything",
			NewPassword:     "NewStrongPass456!",
		}

		err = changePassword(ctx, userID, req)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "password")

		// Cleanup
		database.DB.Exec(ctx, "DELETE FROM users WHERE id = $1", userID)
	})

	t.Run("ChangePassword invalidates all sessions", func(t *testing.T) {
		// Create test user
		email := "invalidate-change@example.com"
		userID := uuid.New()
		currentPassword := "CurrentPass123!"
		passwordHash, _ := utils.HashPassword(currentPassword)

		_, err := database.DB.Exec(ctx,
			`INSERT INTO users (id, app_id, email, password_hash, name, email_verified, created_at, updated_at)
			 VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
			userID, appID, email, passwordHash, "Invalidate Test", true, time.Now(), time.Now())
		require.NoError(t, err)

		// Create sessions
		session1ID := uuid.New()
		session2ID := uuid.New()
		tokenHash1 := utils.HashToken("token1")
		tokenHash2 := utils.HashToken("token2")

		_, err = database.DB.Exec(ctx,
			`INSERT INTO sessions (id, user_id, app_id, token_hash, ip_address, user_agent, expires_at, created_at, last_used_at)
			 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
			session1ID, userID, appID, tokenHash1, "127.0.0.1", "test", time.Now().Add(24*time.Hour), time.Now(), time.Now())
		require.NoError(t, err)

		_, err = database.DB.Exec(ctx,
			`INSERT INTO sessions (id, user_id, app_id, token_hash, ip_address, user_agent, expires_at, created_at, last_used_at)
			 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
			session2ID, userID, appID, tokenHash2, "127.0.0.1", "test", time.Now().Add(24*time.Hour), time.Now(), time.Now())
		require.NoError(t, err)

		req := &models.ChangePasswordRequest{
			CurrentPassword: currentPassword,
			NewPassword:     "NewStrongPass456!",
		}

		err = changePassword(ctx, userID, req)
		require.NoError(t, err)

		// Verify all sessions were deleted
		var sessionCount int
		err = database.DB.QueryRow(ctx,
			"SELECT COUNT(*) FROM sessions WHERE user_id = $1",
			userID).Scan(&sessionCount)
		require.NoError(t, err)
		assert.Equal(t, 0, sessionCount, "All sessions should be invalidated after password change")

		// Cleanup
		database.DB.Exec(ctx, "DELETE FROM users WHERE id = $1", userID)
	})
}
