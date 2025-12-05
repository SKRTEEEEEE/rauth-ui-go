package handlers

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"rauth/database"
	"rauth/models"
	"rauth/utils"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// Constants for email verification
const (
	verificationTokenTTL     = 24 * time.Hour
	verificationTokenPrefix  = "email:verification:"
	resendRateLimitPrefix    = "email:resend:ratelimit:"
	resendRateLimitWindow    = 1 * time.Minute
	verificationTokenLength  = 32
)

// VerifyEmail handles email verification with token
// POST /api/v1/auth/verify-email
func VerifyEmail(c *fiber.Ctx) error {
	var req models.VerifyEmailRequest

	// Parse request body
	if err := c.BodyParser(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Invalid request body",
		})
	}

	// Validate request
	if err := validateVerifyEmailRequest(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": err.Error(),
		})
	}

	ctx := context.Background()

	// Verify the email with token
	err := verifyEmailWithToken(ctx, req.Token)
	if err != nil {
		if strings.Contains(err.Error(), "invalid") || strings.Contains(err.Error(), "expired") {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error": err.Error(),
			})
		}
		if strings.Contains(err.Error(), "already verified") {
			return c.Status(fiber.StatusConflict).JSON(fiber.Map{
				"message": "Email is already verified",
			})
		}
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to verify email",
		})
	}

	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"message": "Email verified successfully",
	})
}

// ResendVerification handles resending verification email
// POST /api/v1/auth/resend-verification
func ResendVerification(c *fiber.Ctx) error {
	var req models.ResendVerificationRequest

	// Parse request body
	if err := c.BodyParser(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Invalid request body",
		})
	}

	// Validate request
	if err := validateResendVerificationRequest(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": err.Error(),
		})
	}

	ctx := context.Background()

	// Check rate limiting
	email := normalizeEmail(req.Email)
	rateLimitKey := resendRateLimitPrefix + email + ":" + req.AppID.String()
	
	exists, err := database.Exists(ctx, rateLimitKey)
	if err == nil && exists {
		return c.Status(fiber.StatusTooManyRequests).JSON(fiber.Map{
			"error": "Please wait before requesting another verification email",
		})
	}

	// Resend verification email
	_, err = resendVerificationEmail(ctx, &req)
	if err != nil {
		if strings.Contains(err.Error(), "already verified") {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error": "Email is already verified",
			})
		}
		if strings.Contains(err.Error(), "not found") {
			// For security, return success even if user not found
			// to prevent email enumeration attacks
			return c.Status(fiber.StatusOK).JSON(fiber.Map{
				"message": "If the email exists, a verification email has been sent",
			})
		}
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to send verification email",
		})
	}

	// Set rate limit
	_ = database.SetString(ctx, rateLimitKey, "1", resendRateLimitWindow)

	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"message": "Verification email sent successfully",
	})
}

// validateVerifyEmailRequest validates the verify email request
func validateVerifyEmailRequest(req *models.VerifyEmailRequest) error {
	if req.Token == "" {
		return errors.New("token is required")
	}
	return nil
}

// validateResendVerificationRequest validates the resend verification request
func validateResendVerificationRequest(req *models.ResendVerificationRequest) error {
	if req.Email == "" {
		return errors.New("email is required")
	}
	if req.AppID == uuid.Nil {
		return errors.New("app_id is required")
	}
	if err := validateEmail(req.Email); err != nil {
		return err
	}
	return nil
}

// generateVerificationToken generates a cryptographically secure random token
func generateVerificationToken() string {
	bytes := make([]byte, verificationTokenLength)
	if _, err := rand.Read(bytes); err != nil {
		// Fallback to UUID if crypto/rand fails
		return uuid.New().String()
	}
	return hex.EncodeToString(bytes)
}

// normalizeEmail normalizes email to lowercase
func normalizeEmail(email string) string {
	return strings.ToLower(strings.TrimSpace(email))
}

// verifyEmailWithToken verifies an email using a verification token
func verifyEmailWithToken(ctx context.Context, token string) error {
	// Get token data from Redis
	tokenKey := verificationTokenPrefix + token
	var tokenData map[string]string
	err := database.GetJSON(ctx, tokenKey, &tokenData)
	if err != nil {
		return errors.New("invalid or expired verification token")
	}

	// Extract user_id and app_id from token data
	userIDStr, ok := tokenData["user_id"]
	if !ok {
		return errors.New("invalid token data")
	}
	
	appIDStr, ok := tokenData["app_id"]
	if !ok {
		return errors.New("invalid token data")
	}

	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		return errors.New("invalid user_id in token")
	}

	appID, err := uuid.Parse(appIDStr)
	if err != nil {
		return errors.New("invalid app_id in token")
	}

	// Check if user exists and is not already verified
	var emailVerified bool
	err = database.DB.QueryRow(ctx,
		"SELECT email_verified FROM users WHERE id = $1 AND app_id = $2",
		userID, appID).Scan(&emailVerified)

	if err == pgx.ErrNoRows {
		// Delete invalid token
		_ = database.Delete(ctx, tokenKey)
		return errors.New("user not found")
	}
	if err != nil {
		return fmt.Errorf("failed to fetch user: %w", err)
	}

	// If already verified, delete token and return
	if emailVerified {
		_ = database.Delete(ctx, tokenKey)
		return nil // Idempotent - succeed silently
	}

	// Update user to verified
	_, err = database.DB.Exec(ctx,
		"UPDATE users SET email_verified = true, updated_at = $1 WHERE id = $2",
		time.Now(), userID)

	if err != nil {
		return fmt.Errorf("failed to update user: %w", err)
	}

	// Delete token after successful verification (one-time use)
	_ = database.Delete(ctx, tokenKey)

	return nil
}

// resendVerificationEmail generates a new verification token and sends email
func resendVerificationEmail(ctx context.Context, req *models.ResendVerificationRequest) (string, error) {
	// Normalize email
	email := normalizeEmail(req.Email)

	// Fetch user
	var userID uuid.UUID
	var emailVerified bool
	var passwordHash *string

	err := database.DB.QueryRow(ctx,
		"SELECT id, email_verified, password_hash FROM users WHERE LOWER(email) = $1 AND app_id = $2",
		email, req.AppID).Scan(&userID, &emailVerified, &passwordHash)

	if err == pgx.ErrNoRows {
		return "", errors.New("user not found")
	}
	if err != nil {
		return "", fmt.Errorf("failed to fetch user: %w", err)
	}

	// Check if user is email/password user (not OAuth)
	if passwordHash == nil || *passwordHash == "" {
		return "", errors.New("user not found") // OAuth users don't need verification
	}

	// Check if already verified
	if emailVerified {
		return "", errors.New("email is already verified")
	}

	// Generate new verification token
	token := generateVerificationToken()

	// Store token in Redis with user_id, app_id, and email
	tokenKey := verificationTokenPrefix + token
	tokenData := map[string]string{
		"user_id": userID.String(),
		"app_id":  req.AppID.String(),
		"email":   email,
	}
	err = database.SetJSON(ctx, tokenKey, tokenData, verificationTokenTTL)
	if err != nil {
		return "", fmt.Errorf("failed to store verification token: %w", err)
	}

	// Send verification email
	err = utils.SendVerificationEmail(email, token)
	if err != nil {
		// Log error but don't fail (email might be sent later via queue)
		fmt.Printf("Warning: Failed to send verification email: %v\n", err)
	}

	return token, nil
}
