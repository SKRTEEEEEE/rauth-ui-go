package middleware

import (
	"context"
	"io"
	"net/http/httptest"
	"testing"
	"time"

	"rauth/database"
	"rauth/models"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestRequireAPIKey_Integration_ValidAPIKey tests the middleware with a real database
func TestRequireAPIKey_Integration_ValidAPIKey(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test")
	}

	// Ensure database is connected
	if database.DB == nil {
		t.Skip("Database not connected")
	}

	ctx := context.Background()

	// Create a test application with dynamically generated test API key
	// NOTE: This is a test key generated at runtime, not a hardcoded secret
	testApp := models.Application{
		ID:                  uuid.New(),
		Name:                "Integration Test App",
		APIKey:              "integration-test-key-" + uuid.New().String(),
		AllowedRedirectURIs: []string{"http://localhost:3000/callback"},
		CORSOrigins:         []string{"http://localhost:3000"},
		CreatedAt:           time.Now(),
		UpdatedAt:           time.Now(),
	}

	// Insert test application
	insertQuery := `
		INSERT INTO applications (id, name, api_key, allowed_redirect_uris, cors_origins, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
	`
	_, err := database.DB.Exec(ctx, insertQuery,
		testApp.ID,
		testApp.Name,
		testApp.APIKey,
		testApp.AllowedRedirectURIs,
		testApp.CORSOrigins,
		testApp.CreatedAt,
		testApp.UpdatedAt,
	)
	require.NoError(t, err)

	// Cleanup after test
	defer func() {
		deleteQuery := `DELETE FROM applications WHERE id = $1`
		database.DB.Exec(ctx, deleteQuery, testApp.ID)
	}()

	// Create Fiber app with middleware
	app := fiber.New()

	app.Get("/test", RequireAPIKey, func(c *fiber.Ctx) error {
		retrievedApp, err := GetApplication(c)
		if err != nil {
			return err
		}

		return c.JSON(fiber.Map{
			"id":   retrievedApp.ID.String(),
			"name": retrievedApp.Name,
		})
	})

	// Test with valid API key
	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("X-API-Key", testApp.APIKey)
	resp, err := app.Test(req)

	require.NoError(t, err)
	assert.Equal(t, fiber.StatusOK, resp.StatusCode)

	body, _ := io.ReadAll(resp.Body)
	assert.Contains(t, string(body), testApp.ID.String())
	assert.Contains(t, string(body), testApp.Name)
}

// TestRequireAPIKey_Integration_InvalidAPIKey tests with invalid API key
func TestRequireAPIKey_Integration_InvalidAPIKey(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test")
	}

	// Ensure database is connected
	if database.DB == nil {
		t.Skip("Database not connected")
	}

	// Create Fiber app with middleware
	app := fiber.New()

	app.Get("/test", RequireAPIKey, func(c *fiber.Ctx) error {
		return c.SendString("success")
	})

	// Test with invalid API key (not a real secret, just a test string)
	fakeAPIKey := "invalid-test-key-" + uuid.New().String()
	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("X-API-Key", fakeAPIKey)
	resp, err := app.Test(req)

	require.NoError(t, err)
	assert.Equal(t, fiber.StatusUnauthorized, resp.StatusCode)

	body, _ := io.ReadAll(resp.Body)
	assert.Contains(t, string(body), "Invalid API key")
}

// TestRequireAPIKey_Integration_GetApplicationID tests GetApplicationID helper
func TestRequireAPIKey_Integration_GetApplicationID(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test")
	}

	// Ensure database is connected
	if database.DB == nil {
		t.Skip("Database not connected")
	}

	ctx := context.Background()

	// Create a test application
	testApp := models.Application{
		ID:                  uuid.New(),
		Name:                "Test GetApplicationID",
		APIKey:              "test-get-app-id-" + uuid.New().String(),
		AllowedRedirectURIs: []string{"http://localhost:3000/callback"},
		CORSOrigins:         []string{"http://localhost:3000"},
		CreatedAt:           time.Now(),
		UpdatedAt:           time.Now(),
	}

	// Insert test application
	insertQuery := `
		INSERT INTO applications (id, name, api_key, allowed_redirect_uris, cors_origins, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
	`
	_, err := database.DB.Exec(ctx, insertQuery,
		testApp.ID,
		testApp.Name,
		testApp.APIKey,
		testApp.AllowedRedirectURIs,
		testApp.CORSOrigins,
		testApp.CreatedAt,
		testApp.UpdatedAt,
	)
	require.NoError(t, err)

	// Cleanup after test
	defer func() {
		deleteQuery := `DELETE FROM applications WHERE id = $1`
		database.DB.Exec(ctx, deleteQuery, testApp.ID)
	}()

	// Create Fiber app with middleware
	app := fiber.New()

	app.Get("/test", RequireAPIKey, func(c *fiber.Ctx) error {
		appID, err := GetApplicationID(c)
		if err != nil {
			return err
		}

		return c.JSON(fiber.Map{
			"app_id": appID.String(),
		})
	})

	// Test with valid API key
	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("X-API-Key", testApp.APIKey)
	resp, err := app.Test(req)

	require.NoError(t, err)
	assert.Equal(t, fiber.StatusOK, resp.StatusCode)

	body, _ := io.ReadAll(resp.Body)
	assert.Contains(t, string(body), testApp.ID.String())
}

// TestRequireAPIKey_Integration_MultipleRequests tests multiple concurrent requests
func TestRequireAPIKey_Integration_MultipleRequests(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test")
	}

	// Ensure database is connected
	if database.DB == nil {
		t.Skip("Database not connected")
	}

	ctx := context.Background()

	// Create two test applications
	testApp1 := models.Application{
		ID:                  uuid.New(),
		Name:                "Multi Test App 1",
		APIKey:              "multi-test-key-1-" + uuid.New().String(),
		AllowedRedirectURIs: []string{"http://localhost:3000/callback"},
		CORSOrigins:         []string{"http://localhost:3000"},
		CreatedAt:           time.Now(),
		UpdatedAt:           time.Now(),
	}

	testApp2 := models.Application{
		ID:                  uuid.New(),
		Name:                "Multi Test App 2",
		APIKey:              "multi-test-key-2-" + uuid.New().String(),
		AllowedRedirectURIs: []string{"http://localhost:4000/callback"},
		CORSOrigins:         []string{"http://localhost:4000"},
		CreatedAt:           time.Now(),
		UpdatedAt:           time.Now(),
	}

	// Insert test applications
	insertQuery := `
		INSERT INTO applications (id, name, api_key, allowed_redirect_uris, cors_origins, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
	`

	_, err := database.DB.Exec(ctx, insertQuery,
		testApp1.ID, testApp1.Name, testApp1.APIKey,
		testApp1.AllowedRedirectURIs, testApp1.CORSOrigins,
		testApp1.CreatedAt, testApp1.UpdatedAt,
	)
	require.NoError(t, err)

	_, err = database.DB.Exec(ctx, insertQuery,
		testApp2.ID, testApp2.Name, testApp2.APIKey,
		testApp2.AllowedRedirectURIs, testApp2.CORSOrigins,
		testApp2.CreatedAt, testApp2.UpdatedAt,
	)
	require.NoError(t, err)

	// Cleanup after test
	defer func() {
		deleteQuery := `DELETE FROM applications WHERE id = $1`
		database.DB.Exec(ctx, deleteQuery, testApp1.ID)
		database.DB.Exec(ctx, deleteQuery, testApp2.ID)
	}()

	// Create Fiber app with middleware
	app := fiber.New()

	app.Get("/test", RequireAPIKey, func(c *fiber.Ctx) error {
		retrievedApp, err := GetApplication(c)
		if err != nil {
			return err
		}

		return c.JSON(fiber.Map{
			"id":   retrievedApp.ID.String(),
			"name": retrievedApp.Name,
		})
	})

	// Test with first API key
	req1 := httptest.NewRequest("GET", "/test", nil)
	req1.Header.Set("X-API-Key", testApp1.APIKey)
	resp1, err := app.Test(req1)

	require.NoError(t, err)
	assert.Equal(t, fiber.StatusOK, resp1.StatusCode)

	body1, _ := io.ReadAll(resp1.Body)
	assert.Contains(t, string(body1), testApp1.ID.String())
	assert.Contains(t, string(body1), testApp1.Name)

	// Test with second API key
	req2 := httptest.NewRequest("GET", "/test", nil)
	req2.Header.Set("X-API-Key", testApp2.APIKey)
	resp2, err := app.Test(req2)

	require.NoError(t, err)
	assert.Equal(t, fiber.StatusOK, resp2.StatusCode)

	body2, _ := io.ReadAll(resp2.Body)
	assert.Contains(t, string(body2), testApp2.ID.String())
	assert.Contains(t, string(body2), testApp2.Name)
}
