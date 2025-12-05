package handlers

import (
	"context"
	"errors"
	"fmt"
	"net/mail"
	"strings"
	"time"

	"rauth/database"
	"rauth/models"
	"rauth/utils"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// Register handles user registration with email/password
func Register(c *fiber.Ctx) error {
	var req models.RegisterRequest

	// Parse request body
	if err := c.BodyParser(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Invalid request body",
		})
	}

	// Validate request
	if err := validateRegisterRequest(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": err.Error(),
		})
	}

	// Register user
	ctx := context.Background()
	userID, err := registerUser(ctx, &req)
	if err != nil {
		if strings.Contains(err.Error(), "already exists") {
			return c.Status(fiber.StatusConflict).JSON(fiber.Map{
				"error": err.Error(),
			})
		}
		if strings.Contains(err.Error(), "not found") {
			return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
				"error": err.Error(),
			})
		}
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to register user",
		})
	}

	// Create session ID
	sessionID := uuid.New()

	// Generate JWT token
	token, err := utils.GenerateJWT(userID, req.AppID, sessionID, req.Email)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to generate token",
		})
	}

	// Create session
	if err := createSession(ctx, sessionID, userID, req.AppID, token, c); err != nil {
		// Log error but don't fail registration
		fmt.Printf("Warning: Failed to create session: %v\n", err)
	}

	return c.Status(fiber.StatusCreated).JSON(fiber.Map{
		"token":   token,
		"user_id": userID,
	})
}

// Login handles user login with email/password
func Login(c *fiber.Ctx) error {
	var req models.LoginRequest

	// Parse request body
	if err := c.BodyParser(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Invalid request body",
		})
	}

	// Validate request
	if err := validateLoginRequest(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": err.Error(),
		})
	}

	// Login user
	ctx := context.Background()
	userID, err := loginUser(ctx, &req)
	if err != nil {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"error": err.Error(),
		})
	}

	// Create session ID
	sessionID := uuid.New()

	// Generate JWT token
	token, err := utils.GenerateJWT(userID, req.AppID, sessionID, req.Email)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to generate token",
		})
	}

	// Create session
	if err := createSession(ctx, sessionID, userID, req.AppID, token, c); err != nil {
		// Log error but don't fail login
		fmt.Printf("Warning: Failed to create session: %v\n", err)
	}

	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"token":   token,
		"user_id": userID,
	})
}

// validateRegisterRequest validates the registration request
func validateRegisterRequest(req *models.RegisterRequest) error {
	if req.Email == "" {
		return errors.New("email is required")
	}
	if req.Password == "" {
		return errors.New("password is required")
	}
	if req.AppID == uuid.Nil {
		return errors.New("app_id is required")
	}

	if err := validateEmail(req.Email); err != nil {
		return err
	}

	if err := validatePassword(req.Password); err != nil {
		return err
	}

	return nil
}

// validateLoginRequest validates the login request
func validateLoginRequest(req *models.LoginRequest) error {
	if req.Email == "" {
		return errors.New("email is required")
	}
	if req.Password == "" {
		return errors.New("password is required")
	}
	if req.AppID == uuid.Nil {
		return errors.New("app_id is required")
	}

	return nil
}

// validateEmail validates email format
func validateEmail(email string) error {
	if email == "" {
		return errors.New("email is required")
	}

	_, err := mail.ParseAddress(email)
	if err != nil {
		return errors.New("invalid email format")
	}

	return nil
}

// validatePassword validates password requirements
func validatePassword(password string) error {
	if len(password) < 8 {
		return errors.New("password must be at least 8 characters long")
	}

	return nil
}

// registerUser registers a new user in the database
func registerUser(ctx context.Context, req *models.RegisterRequest) (uuid.UUID, error) {
	// Verify application exists
	var appExists bool
	err := database.DB.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM applications WHERE id = $1)", req.AppID).Scan(&appExists)
	if err != nil {
		return uuid.Nil, fmt.Errorf("failed to verify application: %w", err)
	}
	if !appExists {
		return uuid.Nil, errors.New("application not found")
	}

	// Normalize email to lowercase for case-insensitive uniqueness
	email := strings.ToLower(req.Email)

	// Check if user already exists
	var existingUserID uuid.UUID
	err = database.DB.QueryRow(ctx,
		"SELECT id FROM users WHERE LOWER(email) = $1 AND app_id = $2",
		email, req.AppID).Scan(&existingUserID)

	if err == nil {
		return uuid.Nil, errors.New("user with this email already exists")
	}
	if err != pgx.ErrNoRows {
		return uuid.Nil, fmt.Errorf("failed to check existing user: %w", err)
	}

	// Hash password
	passwordHash, err := utils.HashPassword(req.Password)
	if err != nil {
		return uuid.Nil, fmt.Errorf("failed to hash password: %w", err)
	}

	// Insert user
	userID := uuid.New()
	_, err = database.DB.Exec(ctx,
		`INSERT INTO users (id, app_id, email, password_hash, name, email_verified, created_at, updated_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
		userID, req.AppID, email, passwordHash, req.Name, false, time.Now(), time.Now())

	if err != nil {
		return uuid.Nil, fmt.Errorf("failed to create user: %w", err)
	}

	return userID, nil
}

// loginUser authenticates a user and returns the user ID
func loginUser(ctx context.Context, req *models.LoginRequest) (uuid.UUID, error) {
	// Normalize email to lowercase for case-insensitive lookup
	email := strings.ToLower(req.Email)

	// Fetch user by email and app_id
	var userID uuid.UUID
	var passwordHash *string

	err := database.DB.QueryRow(ctx,
		"SELECT id, password_hash FROM users WHERE LOWER(email) = $1 AND app_id = $2",
		email, req.AppID).Scan(&userID, &passwordHash)

	if err == pgx.ErrNoRows {
		return uuid.Nil, errors.New("invalid credentials")
	}
	if err != nil {
		return uuid.Nil, fmt.Errorf("failed to fetch user: %w", err)
	}

	// Check if user has a password (OAuth users won't have password_hash)
	if passwordHash == nil || *passwordHash == "" {
		return uuid.Nil, errors.New("invalid credentials")
	}

	// Compare password
	if !utils.ComparePassword(*passwordHash, req.Password) {
		return uuid.Nil, errors.New("invalid credentials")
	}

	return userID, nil
}

// createSession creates a session for the user
func createSession(ctx context.Context, sessionID, userID, appID uuid.UUID, token string, c *fiber.Ctx) error {
	// Hash the token for storage
	tokenHash := utils.HashToken(token)

	// Get IP and User-Agent
	ipAddress := c.IP()
	userAgent := string(c.Request().Header.UserAgent())

	// Set expiration to 24 hours
	expiresAt := time.Now().Add(24 * time.Hour)

	// Insert session
	_, err := database.DB.Exec(ctx,
		`INSERT INTO sessions (id, user_id, app_id, token_hash, ip_address, user_agent, expires_at, created_at, last_used_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
		sessionID, userID, appID, tokenHash, ipAddress, userAgent, expiresAt, time.Now(), time.Now())

	if err != nil {
		return fmt.Errorf("failed to create session: %w", err)
	}

	return nil
}

// ForgotPassword handles password reset requests
func ForgotPassword(c *fiber.Ctx) error {
	var req models.ForgotPasswordRequest

	// Parse request body
	if err := c.BodyParser(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Invalid request body",
		})
	}

	// Validate request
	if req.Email == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "email is required",
		})
	}
	if req.AppID == uuid.Nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "app_id is required",
		})
	}
	if err := validateEmail(req.Email); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": err.Error(),
		})
	}

	// Process forgot password (don't reveal if email exists)
	ctx := context.Background()
	_, _ = forgotPassword(ctx, &req)

	// Always return success to prevent email enumeration
	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"message": "Password reset email sent",
	})
}

// ResetPassword handles password reset confirmation
func ResetPassword(c *fiber.Ctx) error {
	var req models.ResetPasswordRequest

	// Parse request body
	if err := c.BodyParser(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Invalid request body",
		})
	}

	// Validate request
	if req.Token == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "token is required",
		})
	}
	if req.NewPassword == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "new_password is required",
		})
	}
	if err := validatePassword(req.NewPassword); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": err.Error(),
		})
	}

	// Reset password
	ctx := context.Background()
	if err := resetPassword(ctx, &req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": err.Error(),
		})
	}

	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"message": "Password reset successfully",
	})
}

// forgotPassword generates a reset token and sends email
func forgotPassword(ctx context.Context, req *models.ForgotPasswordRequest) (string, error) {
	// Normalize email to lowercase
	email := strings.ToLower(req.Email)

	// Check if user exists
	var userID uuid.UUID
	err := database.DB.QueryRow(ctx,
		"SELECT id FROM users WHERE LOWER(email) = $1 AND app_id = $2",
		email, req.AppID).Scan(&userID)

	if err == pgx.ErrNoRows {
		// Don't reveal that email doesn't exist (security best practice)
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("failed to fetch user: %w", err)
	}

	// Delete any existing reset tokens for this email (cleanup old tokens)
	// Use pattern matching to find all reset tokens for this user
	iter := database.RedisClient.Scan(ctx, 0, "reset:*", 0).Iterator()
	for iter.Next(ctx) {
		key := iter.Val()
		existingEmail, err := database.GetString(ctx, key)
		if err == nil && strings.ToLower(existingEmail) == email {
			database.Delete(ctx, key)
		}
	}

	// Generate reset token
	resetToken := uuid.New().String()

	// Store token in Redis with 1 hour expiration
	err = database.SetString(ctx, "reset:"+resetToken, email, 1*time.Hour)
	if err != nil {
		return "", fmt.Errorf("failed to store reset token: %w", err)
	}

	// TODO: Send email with reset link
	// For now, just log the token (in production, send email)
	fmt.Printf("Password reset token for %s: %s\n", email, resetToken)

	return resetToken, nil
}

// resetPassword validates token and updates password
func resetPassword(ctx context.Context, req *models.ResetPasswordRequest) error {
	// Verify reset token exists in Redis
	email, err := database.GetString(ctx, "reset:"+req.Token)
	if err != nil {
		return errors.New("invalid or expired reset token")
	}

	// Get user by email
	var userID uuid.UUID
	var appID uuid.UUID
	err = database.DB.QueryRow(ctx,
		"SELECT id, app_id FROM users WHERE LOWER(email) = $1",
		strings.ToLower(email)).Scan(&userID, &appID)

	if err == pgx.ErrNoRows {
		return errors.New("user not found")
	}
	if err != nil {
		return fmt.Errorf("failed to fetch user: %w", err)
	}

	// Hash new password
	passwordHash, err := utils.HashPassword(req.NewPassword)
	if err != nil {
		return fmt.Errorf("failed to hash password: %w", err)
	}

	// Update password
	_, err = database.DB.Exec(ctx,
		"UPDATE users SET password_hash = $1, updated_at = $2 WHERE id = $3",
		passwordHash, time.Now(), userID)
	if err != nil {
		return fmt.Errorf("failed to update password: %w", err)
	}

	// Invalidate all sessions for this user
	_, err = database.DB.Exec(ctx,
		"DELETE FROM sessions WHERE user_id = $1",
		userID)
	if err != nil {
		return fmt.Errorf("failed to invalidate sessions: %w", err)
	}

	// Delete the reset token (one-time use)
	err = database.Delete(ctx, "reset:"+req.Token)
	if err != nil {
		return fmt.Errorf("failed to delete reset token: %w", err)
	}

	return nil
}
