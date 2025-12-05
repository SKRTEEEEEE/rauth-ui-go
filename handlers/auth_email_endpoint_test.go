package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http/httptest"
	"os"
	"testing"

	"rauth/database"
	"rauth/models"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// setupEmailAuthApp creates a Fiber app with email auth endpoints
func setupEmailAuthApp() *fiber.App {
	app := fiber.New()
	app.Post("/api/v1/auth/register", Register)
	app.Post("/api/v1/auth/login", Login)
	return app
}

// TestRegisterEndpoint_Scenarios tests real-world registration scenarios
func TestRegisterEndpoint_Scenarios(t *testing.T) {
	if os.Getenv("INTEGRATION_TEST") != "true" {
		t.Skip("Skipping endpoint test")
	}

	if err := database.Connect(); err != nil {
		t.Fatalf("Failed to connect to database: %v", err)
	}

	ctx := context.Background()
	app := setupEmailAuthApp()

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

	tests := []struct {
		name           string
		payload        models.RegisterRequest
		expectStatus   int
		expectContains string
		checkDB        bool
	}{
		{
			name: "Successful registration",
			payload: models.RegisterRequest{
				Email:    "endpoint-success@example.com",
				Password: "SecurePass123!",
				Name:     strPtr("Endpoint Test User"),
				AppID:    appID,
			},
			expectStatus:   fiber.StatusCreated,
			expectContains: "token",
			checkDB:        true,
		},
		{
			name: "Registration without name",
			payload: models.RegisterRequest{
				Email:    "endpoint-noname@example.com",
				Password: "SecurePass123!",
				Name:     nil,
				AppID:    appID,
			},
			expectStatus:   fiber.StatusCreated,
			expectContains: "token",
			checkDB:        true,
		},
		{
			name: "Missing email",
			payload: models.RegisterRequest{
				Password: "SecurePass123!",
				Name:     strPtr("Test User"),
				AppID:    appID,
			},
			expectStatus:   fiber.StatusBadRequest,
			expectContains: "email",
		},
		{
			name: "Missing password",
			payload: models.RegisterRequest{
				Email: "test@example.com",
				Name:  strPtr("Test User"),
				AppID: appID,
			},
			expectStatus:   fiber.StatusBadRequest,
			expectContains: "password",
		},
		{
			name: "Missing app_id",
			payload: models.RegisterRequest{
				Email:    "test@example.com",
				Password: "SecurePass123!",
				Name:     strPtr("Test User"),
			},
			expectStatus:   fiber.StatusBadRequest,
			expectContains: "app_id",
		},
		{
			name: "Invalid email format",
			payload: models.RegisterRequest{
				Email:    "not-an-email",
				Password: "SecurePass123!",
				Name:     strPtr("Test User"),
				AppID:    appID,
			},
			expectStatus:   fiber.StatusBadRequest,
			expectContains: "email",
		},
		{
			name: "Password too short",
			payload: models.RegisterRequest{
				Email:    "short-pass@example.com",
				Password: "Short1!",
				Name:     strPtr("Test User"),
				AppID:    appID,
			},
			expectStatus:   fiber.StatusBadRequest,
			expectContains: "8 characters",
		},
		{
			name: "Duplicate email in same app",
			payload: models.RegisterRequest{
				Email:    "endpoint-success@example.com", // Already registered in first test
				Password: "DifferentPass456!",
				Name:     strPtr("Another User"),
				AppID:    appID,
			},
			expectStatus:   fiber.StatusConflict,
			expectContains: "already exists",
		},
		{
			name: "Invalid app_id",
			payload: models.RegisterRequest{
				Email:    "invalid-app@example.com",
				Password: "SecurePass123!",
				Name:     strPtr("Test User"),
				AppID:    uuid.New(), // Non-existent app
			},
			expectStatus:   fiber.StatusNotFound,
			expectContains: "not found",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Prepare request body
			body, err := json.Marshal(tt.payload)
			require.NoError(t, err)

			req := httptest.NewRequest("POST", "/api/v1/auth/register", bytes.NewReader(body))
			req.Header.Set("Content-Type", "application/json")

			resp, err := app.Test(req, -1)
			require.NoError(t, err)

			assert.Equal(t, tt.expectStatus, resp.StatusCode)

			respBody, _ := io.ReadAll(resp.Body)
			assert.Contains(t, string(respBody), tt.expectContains)

			if tt.checkDB && tt.expectStatus == fiber.StatusCreated {
				// Verify user was created in database
				var userID uuid.UUID
				err := database.DB.QueryRow(ctx,
					"SELECT id FROM users WHERE email = $1 AND app_id = $2",
					tt.payload.Email, tt.payload.AppID).Scan(&userID)
				require.NoError(t, err)
				assert.NotEqual(t, uuid.Nil, userID)

				// Verify JWT token is in response
				var response map[string]interface{}
				err = json.Unmarshal(respBody, &response)
				require.NoError(t, err)
				assert.Contains(t, response, "token")
				assert.NotEmpty(t, response["token"])
			}
		})
	}
}

// TestLoginEndpoint_Scenarios tests real-world login scenarios
func TestLoginEndpoint_Scenarios(t *testing.T) {
	if os.Getenv("INTEGRATION_TEST") != "true" {
		t.Skip("Skipping endpoint test")
	}

	if err := database.Connect(); err != nil {
		t.Fatalf("Failed to connect to database: %v", err)
	}

	ctx := context.Background()
	app := setupEmailAuthApp()

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

	// Setup: Register a user for login tests
	testEmail := "login-endpoint@example.com"
	testPassword := "SecurePass123!"
	registerReq := models.RegisterRequest{
		Email:    testEmail,
		Password: testPassword,
		Name:     strPtr("Login Test User"),
		AppID:    appID,
	}
	_, err = registerUser(ctx, &registerReq)
	require.NoError(t, err)

	tests := []struct {
		name           string
		payload        models.LoginRequest
		expectStatus   int
		expectContains string
		checkSession   bool
	}{
		{
			name: "Successful login",
			payload: models.LoginRequest{
				Email:    testEmail,
				Password: testPassword,
				AppID:    appID,
			},
			expectStatus:   fiber.StatusOK,
			expectContains: "token",
			checkSession:   true,
		},
		{
			name: "Login with wrong password",
			payload: models.LoginRequest{
				Email:    testEmail,
				Password: "WrongPassword123!",
				AppID:    appID,
			},
			expectStatus:   fiber.StatusUnauthorized,
			expectContains: "invalid credentials",
		},
		{
			name: "Login with non-existent email",
			payload: models.LoginRequest{
				Email:    "nonexistent@example.com",
				Password: testPassword,
				AppID:    appID,
			},
			expectStatus:   fiber.StatusUnauthorized,
			expectContains: "invalid credentials",
		},
		{
			name: "Login to wrong app",
			payload: models.LoginRequest{
				Email:    testEmail,
				Password: testPassword,
				AppID:    uuid.New(),
			},
			expectStatus:   fiber.StatusUnauthorized,
			expectContains: "invalid credentials",
		},
		{
			name: "Missing email",
			payload: models.LoginRequest{
				Password: testPassword,
				AppID:    appID,
			},
			expectStatus:   fiber.StatusBadRequest,
			expectContains: "email",
		},
		{
			name: "Missing password",
			payload: models.LoginRequest{
				Email: testEmail,
				AppID: appID,
			},
			expectStatus:   fiber.StatusBadRequest,
			expectContains: "password",
		},
		{
			name: "Missing app_id",
			payload: models.LoginRequest{
				Email:    testEmail,
				Password: testPassword,
			},
			expectStatus:   fiber.StatusBadRequest,
			expectContains: "app_id",
		},
		{
			name: "Case insensitive email",
			payload: models.LoginRequest{
				Email:    "LOGIN-ENDPOINT@EXAMPLE.COM",
				Password: testPassword,
				AppID:    appID,
			},
			expectStatus:   fiber.StatusOK,
			expectContains: "token",
			checkSession:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Prepare request body
			body, err := json.Marshal(tt.payload)
			require.NoError(t, err)

			req := httptest.NewRequest("POST", "/api/v1/auth/login", bytes.NewReader(body))
			req.Header.Set("Content-Type", "application/json")

			resp, err := app.Test(req, -1)
			require.NoError(t, err)

			assert.Equal(t, tt.expectStatus, resp.StatusCode)

			respBody, _ := io.ReadAll(resp.Body)
			assert.Contains(t, string(respBody), tt.expectContains)

			if tt.checkSession && tt.expectStatus == fiber.StatusOK {
				// Verify JWT token is in response
				var response map[string]interface{}
				err = json.Unmarshal(respBody, &response)
				require.NoError(t, err)
				assert.Contains(t, response, "token")
				assert.NotEmpty(t, response["token"])

				// Verify session was created
				var sessionCount int
				err = database.DB.QueryRow(ctx,
					"SELECT COUNT(*) FROM sessions WHERE app_id = $1",
					appID).Scan(&sessionCount)
				require.NoError(t, err)
				assert.Greater(t, sessionCount, 0)
			}
		})
	}
}

// TestRegisterEndpoint_SecurityChecks tests security validations
func TestRegisterEndpoint_SecurityChecks(t *testing.T) {
	if os.Getenv("INTEGRATION_TEST") != "true" {
		t.Skip("Skipping security checks test")
	}

	if err := database.Connect(); err != nil {
		t.Fatalf("Failed to connect to database: %v", err)
	}

	ctx := context.Background()
	app := setupEmailAuthApp()

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

	t.Run("SQL Injection in email", func(t *testing.T) {
		payload := models.RegisterRequest{
			Email:    "test@example.com' OR '1'='1",
			Password: "SecurePass123!",
			Name:     strPtr("SQL Injection Test"),
			AppID:    appID,
		}

		body, _ := json.Marshal(payload)
		req := httptest.NewRequest("POST", "/api/v1/auth/register", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")

		resp, err := app.Test(req, -1)
		require.NoError(t, err)

		// Should reject invalid email format
		assert.Equal(t, fiber.StatusBadRequest, resp.StatusCode)
	})

	t.Run("XSS in name", func(t *testing.T) {
		maliciousName := "<script>alert('xss')</script>"
		payload := models.RegisterRequest{
			Email:    "xss-test@example.com",
			Password: "SecurePass123!",
			Name:     &maliciousName,
			AppID:    appID,
		}

		body, _ := json.Marshal(payload)
		req := httptest.NewRequest("POST", "/api/v1/auth/register", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")

		resp, err := app.Test(req, -1)
		require.NoError(t, err)

		// Should accept but sanitize or store safely
		// The actual XSS prevention happens at rendering time
		assert.True(t, resp.StatusCode == fiber.StatusCreated || resp.StatusCode == fiber.StatusBadRequest)
	})

	t.Run("Very long email", func(t *testing.T) {
		longEmail := string(make([]byte, 300)) + "@example.com"
		payload := models.RegisterRequest{
			Email:    longEmail,
			Password: "SecurePass123!",
			AppID:    appID,
		}

		body, _ := json.Marshal(payload)
		req := httptest.NewRequest("POST", "/api/v1/auth/register", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")

		resp, err := app.Test(req, -1)
		require.NoError(t, err)

		// Should handle gracefully (either accept or reject with proper error)
		assert.NotEqual(t, fiber.StatusInternalServerError, resp.StatusCode)
	})

	t.Run("Very long password", func(t *testing.T) {
		longPassword := string(make([]byte, 200)) + "Secure123!"
		payload := models.RegisterRequest{
			Email:    "long-pass@example.com",
			Password: longPassword,
			AppID:    appID,
		}

		body, _ := json.Marshal(payload)
		req := httptest.NewRequest("POST", "/api/v1/auth/register", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")

		resp, err := app.Test(req, -1)
		require.NoError(t, err)

		// bcrypt has max input length of 72 bytes
		// Should handle gracefully
		assert.NotEqual(t, fiber.StatusInternalServerError, resp.StatusCode)
	})
}

// TestLoginEndpoint_BruteForceProtection tests rate limiting scenarios
func TestLoginEndpoint_BruteForceProtection(t *testing.T) {
	if os.Getenv("INTEGRATION_TEST") != "true" {
		t.Skip("Skipping brute force protection test")
	}

	if err := database.Connect(); err != nil {
		t.Fatalf("Failed to connect to database: %v", err)
	}

	ctx := context.Background()
	app := setupEmailAuthApp()

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

	// Register a user
	testEmail := "brute-force-test@example.com"
	testPassword := "SecurePass123!"
	registerReq := models.RegisterRequest{
		Email:    testEmail,
		Password: testPassword,
		Name:     strPtr("Brute Force Test"),
		AppID:    appID,
	}
	_, err = registerUser(ctx, &registerReq)
	require.NoError(t, err)

	t.Run("Multiple failed login attempts", func(t *testing.T) {
		// Attempt multiple failed logins
		for i := 0; i < 10; i++ {
			payload := models.LoginRequest{
				Email:    testEmail,
				Password: "WrongPassword" + string(rune(i)),
				AppID:    appID,
			}

			body, _ := json.Marshal(payload)
			req := httptest.NewRequest("POST", "/api/v1/auth/login", bytes.NewReader(body))
			req.Header.Set("Content-Type", "application/json")

			resp, err := app.Test(req, -1)
			require.NoError(t, err)

			// All should fail with unauthorized
			assert.Equal(t, fiber.StatusUnauthorized, resp.StatusCode)

			// Future: Check if rate limiting kicks in after N attempts
			// For now, just verify all attempts return consistent error
		}

		// Successful login should still work after failed attempts
		payload := models.LoginRequest{
			Email:    testEmail,
			Password: testPassword,
			AppID:    appID,
		}

		body, _ := json.Marshal(payload)
		req := httptest.NewRequest("POST", "/api/v1/auth/login", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")

		resp, err := app.Test(req, -1)
		require.NoError(t, err)

		assert.Equal(t, fiber.StatusOK, resp.StatusCode)
	})
}

// TestEmailAuth_ConcurrentRegistrations tests race conditions
func TestEmailAuth_ConcurrentRegistrations(t *testing.T) {
	if os.Getenv("INTEGRATION_TEST") != "true" {
		t.Skip("Skipping concurrent registration test")
	}

	if err := database.Connect(); err != nil {
		t.Fatalf("Failed to connect to database: %v", err)
	}

	ctx := context.Background()
	app := setupEmailAuthApp()

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

	// Try to register same email concurrently
	email := "concurrent@example.com"
	done := make(chan int, 10)
	successCount := 0

	for i := 0; i < 10; i++ {
		go func() {
			payload := models.RegisterRequest{
				Email:    email,
				Password: "SecurePass123!",
				Name:     strPtr("Concurrent Test"),
				AppID:    appID,
			}

			body, _ := json.Marshal(payload)
			req := httptest.NewRequest("POST", "/api/v1/auth/register", bytes.NewReader(body))
			req.Header.Set("Content-Type", "application/json")

			resp, _ := app.Test(req, -1)
			done <- resp.StatusCode
		}()
	}

	// Wait for all goroutines
	for i := 0; i < 10; i++ {
		statusCode := <-done
		if statusCode == fiber.StatusCreated {
			successCount++
		}
	}

	// Only one registration should succeed
	assert.Equal(t, 1, successCount, "Only one concurrent registration should succeed")
}

// TestJWTTokenResponse tests that JWT is returned correctly
func TestJWTTokenResponse(t *testing.T) {
	if os.Getenv("INTEGRATION_TEST") != "true" {
		t.Skip("Skipping JWT token response test")
	}

	if err := database.Connect(); err != nil {
		t.Fatalf("Failed to connect to database: %v", err)
	}

	ctx := context.Background()
	app := setupEmailAuthApp()

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

	// Register
	registerPayload := models.RegisterRequest{
		Email:    "jwt-test@example.com",
		Password: "SecurePass123!",
		Name:     strPtr("JWT Test"),
		AppID:    appID,
	}

	body, _ := json.Marshal(registerPayload)
	req := httptest.NewRequest("POST", "/api/v1/auth/register", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	resp, err := app.Test(req, -1)
	require.NoError(t, err)
	assert.Equal(t, fiber.StatusCreated, resp.StatusCode)

	// Parse response
	respBody, _ := io.ReadAll(resp.Body)
	var response map[string]interface{}
	err = json.Unmarshal(respBody, &response)
	require.NoError(t, err)

	// Verify JWT structure
	assert.Contains(t, response, "token")
	token := response["token"].(string)
	assert.NotEmpty(t, token)

	// JWT should have 3 parts (header.payload.signature)
	// This is a basic check - full JWT validation should be done with utils.VerifyJWT
	assert.Greater(t, len(token), 20)
}
