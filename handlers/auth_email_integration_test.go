package handlers

import (
	"context"
	"os"
	"testing"

	"rauth/database"
	"rauth/models"
	"rauth/utils"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestRegisterUser_Integration tests registration with real database
func TestRegisterUser_Integration(t *testing.T) {
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

	t.Run("Register new user successfully", func(t *testing.T) {
		req := &models.RegisterRequest{
			Email:    "integration-test@example.com",
			Password: "SecurePass123!",
			Name:     strPtr("Integration Test User"),
			AppID:    appID,
		}

		userID, err := registerUser(ctx, req)

		// This will fail until implementation exists (TDD Red phase)
		require.NoError(t, err)
		assert.NotEqual(t, uuid.Nil, userID)

		// Verify user exists in database
		var email string
		var passwordHash string
		err = database.DB.QueryRow(ctx,
			"SELECT email, password_hash FROM users WHERE id = $1 AND app_id = $2",
			userID, appID).Scan(&email, &passwordHash)
		require.NoError(t, err)
		assert.Equal(t, req.Email, email)
		assert.NotEmpty(t, passwordHash)

		// Verify password is hashed (not plain text)
		assert.NotEqual(t, req.Password, passwordHash)
		assert.True(t, utils.ComparePassword(passwordHash, req.Password))

		// Cleanup this specific user
		database.DB.Exec(ctx, "DELETE FROM users WHERE id = $1", userID)
	})

	t.Run("Register duplicate email in same app fails", func(t *testing.T) {
		email := "duplicate-integration@example.com"

		req1 := &models.RegisterRequest{
			Email:    email,
			Password: "SecurePass123!",
			Name:     strPtr("First User"),
			AppID:    appID,
		}

		userID1, err := registerUser(ctx, req1)
		require.NoError(t, err)

		req2 := &models.RegisterRequest{
			Email:    email,
			Password: "DifferentPass456!",
			Name:     strPtr("Second User"),
			AppID:    appID,
		}

		_, err = registerUser(ctx, req2)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "already exists")

		// Cleanup
		database.DB.Exec(ctx, "DELETE FROM users WHERE id = $1", userID1)
	})

	t.Run("Same email can be registered in different apps", func(t *testing.T) {
		email := "multi-app@example.com"

		// Create second test application
		appID2 := uuid.New()
		_, err := database.DB.Exec(ctx,
			"INSERT INTO applications (id, name, api_key, allowed_redirect_uris, cors_origins) VALUES ($1, $2, $3, $4, $5)",
			appID2, "Test App 2", "test-key-"+uuid.New().String(), []string{"http://localhost"}, []string{"*"})
		require.NoError(t, err)

		defer func() {
			database.DB.Exec(ctx, "DELETE FROM users WHERE app_id = $1", appID2)
			database.DB.Exec(ctx, "DELETE FROM applications WHERE id = $1", appID2)
		}()

		// Register same email in first app
		req1 := &models.RegisterRequest{
			Email:    email,
			Password: "SecurePass123!",
			Name:     strPtr("User in App 1"),
			AppID:    appID,
		}
		userID1, err := registerUser(ctx, req1)
		require.NoError(t, err)

		// Register same email in second app (should succeed)
		req2 := &models.RegisterRequest{
			Email:    email,
			Password: "DifferentPass456!",
			Name:     strPtr("User in App 2"),
			AppID:    appID2,
		}
		userID2, err := registerUser(ctx, req2)
		require.NoError(t, err)
		assert.NotEqual(t, userID1, userID2)

		// Cleanup
		database.DB.Exec(ctx, "DELETE FROM users WHERE id = $1", userID1)
		database.DB.Exec(ctx, "DELETE FROM users WHERE id = $1", userID2)
	})

	t.Run("Register without name", func(t *testing.T) {
		req := &models.RegisterRequest{
			Email:    "noname@example.com",
			Password: "SecurePass123!",
			Name:     nil, // No name provided
			AppID:    appID,
		}

		userID, err := registerUser(ctx, req)
		require.NoError(t, err)

		// Verify user was created with null name
		var name *string
		err = database.DB.QueryRow(ctx,
			"SELECT name FROM users WHERE id = $1",
			userID).Scan(&name)
		require.NoError(t, err)
		assert.Nil(t, name)

		// Cleanup
		database.DB.Exec(ctx, "DELETE FROM users WHERE id = $1", userID)
	})

	t.Run("Email verified defaults to false", func(t *testing.T) {
		req := &models.RegisterRequest{
			Email:    "verify-test@example.com",
			Password: "SecurePass123!",
			Name:     strPtr("Verify Test"),
			AppID:    appID,
		}

		userID, err := registerUser(ctx, req)
		require.NoError(t, err)

		// Verify email_verified is false by default
		var emailVerified bool
		err = database.DB.QueryRow(ctx,
			"SELECT email_verified FROM users WHERE id = $1",
			userID).Scan(&emailVerified)
		require.NoError(t, err)
		assert.False(t, emailVerified)

		// Cleanup
		database.DB.Exec(ctx, "DELETE FROM users WHERE id = $1", userID)
	})
}

// TestLoginUser_Integration tests login with real database
func TestLoginUser_Integration(t *testing.T) {
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

	t.Run("Login with correct credentials", func(t *testing.T) {
		email := "login-success@example.com"
		password := "SecurePass123!"

		// Register user first
		registerReq := &models.RegisterRequest{
			Email:    email,
			Password: password,
			Name:     strPtr("Login Test User"),
			AppID:    appID,
		}
		registeredUserID, err := registerUser(ctx, registerReq)
		require.NoError(t, err)

		// Login
		loginReq := &models.LoginRequest{
			Email:    email,
			Password: password,
			AppID:    appID,
		}
		loggedUserID, err := loginUser(ctx, loginReq)

		// This will fail until implementation exists (TDD Red phase)
		require.NoError(t, err)
		assert.Equal(t, registeredUserID, loggedUserID)

		// Cleanup
		database.DB.Exec(ctx, "DELETE FROM users WHERE id = $1", registeredUserID)
	})

	t.Run("Login with wrong password", func(t *testing.T) {
		email := "login-wrong-pass@example.com"
		password := "CorrectPass123!"

		// Register user
		registerReq := &models.RegisterRequest{
			Email:    email,
			Password: password,
			Name:     strPtr("Wrong Pass Test"),
			AppID:    appID,
		}
		userID, err := registerUser(ctx, registerReq)
		require.NoError(t, err)

		// Try to login with wrong password
		loginReq := &models.LoginRequest{
			Email:    email,
			Password: "WrongPassword456!",
			AppID:    appID,
		}
		_, err = loginUser(ctx, loginReq)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid credentials")

		// Cleanup
		database.DB.Exec(ctx, "DELETE FROM users WHERE id = $1", userID)
	})

	t.Run("Login with non-existent email", func(t *testing.T) {
		loginReq := &models.LoginRequest{
			Email:    "nonexistent@example.com",
			Password: "AnyPassword123!",
			AppID:    appID,
		}

		_, err := loginUser(ctx, loginReq)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid credentials")
	})

	t.Run("Login to wrong app", func(t *testing.T) {
		email := "login-wrong-app@example.com"
		password := "SecurePass123!"

		// Register user in app1
		registerReq := &models.RegisterRequest{
			Email:    email,
			Password: password,
			Name:     strPtr("Wrong App Test"),
			AppID:    appID,
		}
		userID, err := registerUser(ctx, registerReq)
		require.NoError(t, err)

		// Try to login to different app
		loginReq := &models.LoginRequest{
			Email:    email,
			Password: password,
			AppID:    uuid.New(), // Different app
		}
		_, err = loginUser(ctx, loginReq)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid credentials")

		// Cleanup
		database.DB.Exec(ctx, "DELETE FROM users WHERE id = $1", userID)
	})

	t.Run("OAuth user without password cannot login", func(t *testing.T) {
		email := "oauth-only@example.com"
		userID := uuid.New()

		// Create OAuth user without password_hash
		_, err := database.DB.Exec(ctx,
			"INSERT INTO users (id, app_id, email, name, email_verified) VALUES ($1, $2, $3, $4, $5)",
			userID, appID, email, "OAuth User", true)
		require.NoError(t, err)

		// Try to login with password
		loginReq := &models.LoginRequest{
			Email:    email,
			Password: "AnyPassword123!",
			AppID:    appID,
		}
		_, err = loginUser(ctx, loginReq)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid credentials")

		// Cleanup
		database.DB.Exec(ctx, "DELETE FROM users WHERE id = $1", userID)
	})

	t.Run("Case insensitive email login", func(t *testing.T) {
		email := "case-test@example.com"
		password := "SecurePass123!"

		// Register with lowercase email
		registerReq := &models.RegisterRequest{
			Email:    email,
			Password: password,
			Name:     strPtr("Case Test User"),
			AppID:    appID,
		}
		userID, err := registerUser(ctx, registerReq)
		require.NoError(t, err)

		// Login with different case
		loginReq := &models.LoginRequest{
			Email:    "CASE-TEST@EXAMPLE.COM",
			Password: password,
			AppID:    appID,
		}
		loggedUserID, err := loginUser(ctx, loginReq)
		require.NoError(t, err)
		assert.Equal(t, userID, loggedUserID)

		// Cleanup
		database.DB.Exec(ctx, "DELETE FROM users WHERE id = $1", userID)
	})

	t.Run("Password comparison is case sensitive", func(t *testing.T) {
		email := "case-pass-test@example.com"
		password := "SecurePass123!"

		// Register
		registerReq := &models.RegisterRequest{
			Email:    email,
			Password: password,
			Name:     strPtr("Case Pass Test"),
			AppID:    appID,
		}
		userID, err := registerUser(ctx, registerReq)
		require.NoError(t, err)

		// Try login with wrong case password
		loginReq := &models.LoginRequest{
			Email:    email,
			Password: "securepass123!", // Different case
			AppID:    appID,
		}
		_, err = loginUser(ctx, loginReq)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid credentials")

		// Cleanup
		database.DB.Exec(ctx, "DELETE FROM users WHERE id = $1", userID)
	})
}

// TestRegisterAndLogin_Session tests that login creates a session
func TestRegisterAndLogin_Session(t *testing.T) {
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
		database.DB.Exec(ctx, "DELETE FROM sessions WHERE app_id = $1", appID)
		database.DB.Exec(ctx, "DELETE FROM users WHERE app_id = $1", appID)
		database.DB.Exec(ctx, "DELETE FROM applications WHERE id = $1", appID)
	}()

	email := "session-test@example.com"
	password := "SecurePass123!"

	// Register user
	registerReq := &models.RegisterRequest{
		Email:    email,
		Password: password,
		Name:     strPtr("Session Test User"),
		AppID:    appID,
	}
	userID, err := registerUser(ctx, registerReq)
	require.NoError(t, err)

	// Login (should create session)
	loginReq := &models.LoginRequest{
		Email:    email,
		Password: password,
		AppID:    appID,
	}
	loggedUserID, err := loginUser(ctx, loginReq)
	require.NoError(t, err)
	assert.Equal(t, userID, loggedUserID)

	// Verify session was created
	// This test will fail until session creation is implemented
	var sessionCount int
	err = database.DB.QueryRow(ctx,
		"SELECT COUNT(*) FROM sessions WHERE user_id = $1 AND app_id = $2",
		userID, appID).Scan(&sessionCount)
	require.NoError(t, err)
	assert.Greater(t, sessionCount, 0, "Session should be created on login")
}

// TestPasswordHashing_Integration verifies bcrypt is used correctly
func TestPasswordHashing_Integration(t *testing.T) {
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

	password := "TestPassword123!"

	req := &models.RegisterRequest{
		Email:    "hash-test@example.com",
		Password: password,
		Name:     strPtr("Hash Test"),
		AppID:    appID,
	}

	userID, err := registerUser(ctx, req)
	require.NoError(t, err)

	// Retrieve password hash from database
	var passwordHash string
	err = database.DB.QueryRow(ctx,
		"SELECT password_hash FROM users WHERE id = $1",
		userID).Scan(&passwordHash)
	require.NoError(t, err)

	// Verify it's a bcrypt hash
	assert.True(t, len(passwordHash) > 50, "Bcrypt hash should be > 50 characters")
	assert.Contains(t, passwordHash, "$2a$", "Should use bcrypt format")

	// Verify password can be verified with the hash
	assert.True(t, utils.ComparePassword(passwordHash, password))
	assert.False(t, utils.ComparePassword(passwordHash, "wrong-password"))

	// Cleanup
	database.DB.Exec(ctx, "DELETE FROM users WHERE id = $1", userID)
}
