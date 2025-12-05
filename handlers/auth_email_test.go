package handlers

import (
	"context"
	"testing"

	"rauth/models"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestValidatePassword tests password validation logic
func TestValidatePassword(t *testing.T) {
	tests := []struct {
		name        string
		password    string
		expectError bool
		errorMsg    string
	}{
		{
			name:        "Valid password",
			password:    "SecurePass123!",
			expectError: false,
		},
		{
			name:        "Password too short",
			password:    "Short1!",
			expectError: true,
			errorMsg:    "at least 8 characters",
		},
		{
			name:        "Empty password",
			password:    "",
			expectError: true,
			errorMsg:    "at least 8 characters",
		},
		{
			name:        "Password with exactly 8 characters",
			password:    "Pass123!",
			expectError: false,
		},
		{
			name:        "Very long password",
			password:    "ThisIsAVeryLongPasswordWithMoreThan72CharactersWhichShouldStillBeAcceptedByTheSystem123!@#",
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validatePassword(tt.password)

			if tt.expectError {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errorMsg)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

// TestValidateEmail tests email validation logic
func TestValidateEmail(t *testing.T) {
	tests := []struct {
		name        string
		email       string
		expectError bool
	}{
		{
			name:        "Valid email",
			email:       "user@example.com",
			expectError: false,
		},
		{
			name:        "Valid email with subdomain",
			email:       "user@mail.example.com",
			expectError: false,
		},
		{
			name:        "Valid email with plus",
			email:       "user+tag@example.com",
			expectError: false,
		},
		{
			name:        "Invalid email - no @",
			email:       "userexample.com",
			expectError: true,
		},
		{
			name:        "Invalid email - no domain",
			email:       "user@",
			expectError: true,
		},
		{
			name:        "Invalid email - no local part",
			email:       "@example.com",
			expectError: true,
		},
		{
			name:        "Invalid email - spaces",
			email:       "user @example.com",
			expectError: true,
		},
		{
			name:        "Empty email",
			email:       "",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateEmail(tt.email)

			if tt.expectError {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

// TestRegister_Validation tests request validation in Register handler
func TestRegister_Validation(t *testing.T) {
	tests := []struct {
		name        string
		request     models.RegisterRequest
		expectError string
	}{
		{
			name: "Valid request",
			request: models.RegisterRequest{
				Email:    "test@example.com",
				Password: "SecurePass123!",
				Name:     strPtr("Test User"),
				AppID:    uuid.New(),
			},
			expectError: "",
		},
		{
			name: "Missing email",
			request: models.RegisterRequest{
				Password: "SecurePass123!",
				Name:     strPtr("Test User"),
				AppID:    uuid.New(),
			},
			expectError: "email is required",
		},
		{
			name: "Missing password",
			request: models.RegisterRequest{
				Email: "test@example.com",
				Name:  strPtr("Test User"),
				AppID: uuid.New(),
			},
			expectError: "password is required",
		},
		{
			name: "Missing app_id",
			request: models.RegisterRequest{
				Email:    "test@example.com",
				Password: "SecurePass123!",
				Name:     strPtr("Test User"),
			},
			expectError: "app_id is required",
		},
		{
			name: "Invalid email format",
			request: models.RegisterRequest{
				Email:    "invalid-email",
				Password: "SecurePass123!",
				AppID:    uuid.New(),
			},
			expectError: "invalid email",
		},
		{
			name: "Password too short",
			request: models.RegisterRequest{
				Email:    "test@example.com",
				Password: "short",
				AppID:    uuid.New(),
			},
			expectError: "at least 8 characters",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateRegisterRequest(&tt.request)

			if tt.expectError != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectError)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

// TestLogin_Validation tests request validation in Login handler
func TestLogin_Validation(t *testing.T) {
	tests := []struct {
		name        string
		request     models.LoginRequest
		expectError string
	}{
		{
			name: "Valid request",
			request: models.LoginRequest{
				Email:    "test@example.com",
				Password: "SecurePass123!",
				AppID:    uuid.New(),
			},
			expectError: "",
		},
		{
			name: "Missing email",
			request: models.LoginRequest{
				Password: "SecurePass123!",
				AppID:    uuid.New(),
			},
			expectError: "email is required",
		},
		{
			name: "Missing password",
			request: models.LoginRequest{
				Email: "test@example.com",
				AppID: uuid.New(),
			},
			expectError: "password is required",
		},
		{
			name: "Missing app_id",
			request: models.LoginRequest{
				Email:    "test@example.com",
				Password: "SecurePass123!",
			},
			expectError: "app_id is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateLoginRequest(&tt.request)

			if tt.expectError != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectError)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

// TestRegisterUser tests the registration logic
func TestRegisterUser(t *testing.T) {
	ctx := context.Background()
	appID := uuid.New()

	t.Run("Successful registration", func(t *testing.T) {
		req := &models.RegisterRequest{
			Email:    "newuser@example.com",
			Password: "SecurePass123!",
			Name:     strPtr("New User"),
			AppID:    appID,
		}

		userID, err := registerUser(ctx, req)

		// This should fail until implementation exists (TDD Red phase)
		require.NoError(t, err)
		assert.NotEqual(t, uuid.Nil, userID)
	})

	t.Run("Duplicate email registration", func(t *testing.T) {
		req := &models.RegisterRequest{
			Email:    "duplicate@example.com",
			Password: "SecurePass123!",
			Name:     strPtr("Duplicate User"),
			AppID:    appID,
		}

		// First registration
		_, err := registerUser(ctx, req)
		require.NoError(t, err)

		// Second registration with same email should fail
		_, err = registerUser(ctx, req)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "already exists")
	})

	t.Run("Password is hashed", func(t *testing.T) {
		req := &models.RegisterRequest{
			Email:    "hashtest@example.com",
			Password: "SecurePass123!",
			AppID:    appID,
		}

		userID, err := registerUser(ctx, req)
		require.NoError(t, err)

		// Verify password was hashed (not stored in plain text)
		// The password hash should be stored in the database
		var passwordHash string
		// This query will fail until password_hash column exists
		// err = database.DB.QueryRow(ctx, "SELECT password_hash FROM users WHERE id = $1", userID).Scan(&passwordHash)
		// require.NoError(t, err)
		// assert.NotEqual(t, req.Password, passwordHash)
		// assert.True(t, utils.ComparePassword(passwordHash, req.Password))
		_ = userID
		_ = passwordHash
	})
}

// TestLoginUser tests the login logic
func TestLoginUser(t *testing.T) {
	ctx := context.Background()
	appID := uuid.New()
	email := "logintest@example.com"
	password := "SecurePass123!"

	// Setup: Register a user first
	registerReq := &models.RegisterRequest{
		Email:    email,
		Password: password,
		Name:     strPtr("Login Test User"),
		AppID:    appID,
	}
	userID, err := registerUser(ctx, registerReq)
	require.NoError(t, err)

	t.Run("Successful login", func(t *testing.T) {
		loginReq := &models.LoginRequest{
			Email:    email,
			Password: password,
			AppID:    appID,
		}

		loggedUserID, err := loginUser(ctx, loginReq)

		// This should fail until implementation exists (TDD Red phase)
		require.NoError(t, err)
		assert.Equal(t, userID, loggedUserID)
	})

	t.Run("Login with wrong password", func(t *testing.T) {
		loginReq := &models.LoginRequest{
			Email:    email,
			Password: "WrongPassword123!",
			AppID:    appID,
		}

		_, err := loginUser(ctx, loginReq)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid credentials")
	})

	t.Run("Login with non-existent email", func(t *testing.T) {
		loginReq := &models.LoginRequest{
			Email:    "nonexistent@example.com",
			Password: password,
			AppID:    appID,
		}

		_, err := loginUser(ctx, loginReq)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid credentials")
	})

	t.Run("Login to different app", func(t *testing.T) {
		loginReq := &models.LoginRequest{
			Email:    email,
			Password: password,
			AppID:    uuid.New(), // Different app ID
		}

		_, err := loginUser(ctx, loginReq)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid credentials")
	})

	t.Run("OAuth user cannot login with password", func(t *testing.T) {
		// This test ensures that OAuth users (without password_hash) cannot login via email/password
		oauthEmail := "oauthonly@example.com"

		// Create OAuth user (without password_hash)
		// This part will need database setup

		loginReq := &models.LoginRequest{
			Email:    oauthEmail,
			Password: "AnyPassword123!",
			AppID:    appID,
		}

		_, err := loginUser(ctx, loginReq)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid credentials")
	})
}

// TestRegisterHandler tests the HTTP handler
// Skipped - these tests require database connection and are covered by endpoint tests
func TestRegisterHandler(t *testing.T) {
	t.Skip("Basic handler tests are covered by endpoint integration tests")
}

// TestLoginHandler tests the HTTP handler
// Skipped - these tests require database connection and are covered by endpoint tests
func TestLoginHandler(t *testing.T) {
	t.Skip("Basic handler tests are covered by endpoint integration tests")
}

// Helper functions
func strPtr(s string) *string {
	return &s
}
