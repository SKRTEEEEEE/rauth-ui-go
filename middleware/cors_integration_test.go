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

// TestDynamicCORS_Integration_AppIDFromQueryParam tests retrieving app from query parameter
func TestDynamicCORS_Integration_AppIDFromQueryParam(t *testing.T) {
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
		Name:                "CORS Test App Query",
		APIKey:              "cors-test-key-" + uuid.New().String(),
		AllowedRedirectURIs: []string{"http://localhost:3000/callback"},
		CORSOrigins:         []string{"http://localhost:3000", "https://app.example.com"},
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

	// Create Fiber app with CORS middleware
	app := fiber.New()

	app.Get("/test", DynamicCORS(), func(c *fiber.Ctx) error {
		return c.SendString("success")
	})

	// Test with allowed origin and app_id in query
	req := httptest.NewRequest("GET", "/test?app_id="+testApp.ID.String(), nil)
	req.Header.Set("Origin", "http://localhost:3000")
	resp, err := app.Test(req)

	require.NoError(t, err)
	assert.Equal(t, fiber.StatusOK, resp.StatusCode)
	assert.Equal(t, "http://localhost:3000", resp.Header.Get("Access-Control-Allow-Origin"))
	assert.Equal(t, "true", resp.Header.Get("Access-Control-Allow-Credentials"))

	// Test with disallowed origin
	req = httptest.NewRequest("GET", "/test?app_id="+testApp.ID.String(), nil)
	req.Header.Set("Origin", "http://evil.com")
	resp, err = app.Test(req)

	require.NoError(t, err)
	assert.Equal(t, fiber.StatusForbidden, resp.StatusCode)
	assert.Empty(t, resp.Header.Get("Access-Control-Allow-Origin"))

	body, _ := io.ReadAll(resp.Body)
	assert.Contains(t, string(body), "Origin not allowed")
}

// TestDynamicCORS_Integration_AppIDFromHeader tests retrieving app from X-App-ID header
func TestDynamicCORS_Integration_AppIDFromHeader(t *testing.T) {
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
		Name:                "CORS Test App Header",
		APIKey:              "cors-test-key-" + uuid.New().String(),
		AllowedRedirectURIs: []string{"http://localhost:3000/callback"},
		CORSOrigins:         []string{"https://production.com"},
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

	// Create Fiber app with CORS middleware
	app := fiber.New()

	app.Get("/test", DynamicCORS(), func(c *fiber.Ctx) error {
		return c.SendString("success")
	})

	// Test with allowed origin and app_id in header
	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("X-App-ID", testApp.ID.String())
	req.Header.Set("Origin", "https://production.com")
	resp, err := app.Test(req)

	require.NoError(t, err)
	assert.Equal(t, fiber.StatusOK, resp.StatusCode)
	assert.Equal(t, "https://production.com", resp.Header.Get("Access-Control-Allow-Origin"))
	assert.Equal(t, "true", resp.Header.Get("Access-Control-Allow-Credentials"))
}

// TestDynamicCORS_Integration_InvalidAppID tests with invalid app_id
func TestDynamicCORS_Integration_InvalidAppID(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test")
	}

	// Ensure database is connected
	if database.DB == nil {
		t.Skip("Database not connected")
	}

	// Create Fiber app with CORS middleware
	app := fiber.New()

	app.Get("/test", DynamicCORS(), func(c *fiber.Ctx) error {
		return c.SendString("success")
	})

	// Test with invalid UUID
	invalidID := uuid.New().String()
	req := httptest.NewRequest("GET", "/test?app_id="+invalidID, nil)
	req.Header.Set("Origin", "http://localhost:3000")
	resp, err := app.Test(req)

	require.NoError(t, err)
	// Should fall back to development mode or reject
	// Depends on implementation: could be 403 or allow in dev mode
	assert.NotEqual(t, fiber.StatusInternalServerError, resp.StatusCode)
}

// TestDynamicCORS_Integration_PreflightWithApp tests OPTIONS preflight with real application
func TestDynamicCORS_Integration_PreflightWithApp(t *testing.T) {
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
		Name:                "CORS Preflight Test App",
		APIKey:              "cors-preflight-key-" + uuid.New().String(),
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

	// Create Fiber app with CORS middleware
	app := fiber.New()

	app.Options("/test", DynamicCORS(), func(c *fiber.Ctx) error {
		return c.SendString("should not reach here")
	})

	// Test preflight request
	req := httptest.NewRequest("OPTIONS", "/test?app_id="+testApp.ID.String(), nil)
	req.Header.Set("Origin", "http://localhost:3000")
	req.Header.Set("Access-Control-Request-Method", "POST")
	req.Header.Set("Access-Control-Request-Headers", "Content-Type, Authorization")
	resp, err := app.Test(req)

	require.NoError(t, err)
	assert.Equal(t, fiber.StatusNoContent, resp.StatusCode)
	assert.Equal(t, "http://localhost:3000", resp.Header.Get("Access-Control-Allow-Origin"))
	assert.Contains(t, resp.Header.Get("Access-Control-Allow-Methods"), "POST")
	assert.NotEmpty(t, resp.Header.Get("Access-Control-Allow-Headers"))
	assert.Equal(t, "3600", resp.Header.Get("Access-Control-Max-Age"))
}

// TestDynamicCORS_Integration_WildcardOrigin tests application with wildcard origin
func TestDynamicCORS_Integration_WildcardOrigin(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test")
	}

	// Ensure database is connected
	if database.DB == nil {
		t.Skip("Database not connected")
	}

	ctx := context.Background()

	// Create a test application with wildcard origin
	testApp := models.Application{
		ID:                  uuid.New(),
		Name:                "CORS Wildcard Test App",
		APIKey:              "cors-wildcard-key-" + uuid.New().String(),
		AllowedRedirectURIs: []string{"http://localhost:3000/callback"},
		CORSOrigins:         []string{"*"},
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

	// Create Fiber app with CORS middleware
	app := fiber.New()

	app.Get("/test", DynamicCORS(), func(c *fiber.Ctx) error {
		return c.SendString("success")
	})

	// Test with any origin - should be allowed
	testOrigins := []string{
		"http://localhost:3000",
		"https://production.com",
		"http://random-domain.net",
	}

	for _, origin := range testOrigins {
		req := httptest.NewRequest("GET", "/test?app_id="+testApp.ID.String(), nil)
		req.Header.Set("Origin", origin)
		resp, err := app.Test(req)

		require.NoError(t, err)
		assert.Equal(t, fiber.StatusOK, resp.StatusCode, "Origin %s should be allowed with wildcard", origin)
		assert.Equal(t, origin, resp.Header.Get("Access-Control-Allow-Origin"))
	}
}

// TestDynamicCORS_Integration_AppIDPriority tests priority: query > header
func TestDynamicCORS_Integration_AppIDPriority(t *testing.T) {
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
		Name:                "CORS Priority Test App 1",
		APIKey:              "cors-priority-key-1-" + uuid.New().String(),
		AllowedRedirectURIs: []string{"http://localhost:3000/callback"},
		CORSOrigins:         []string{"http://app1.com"},
		CreatedAt:           time.Now(),
		UpdatedAt:           time.Now(),
	}

	testApp2 := models.Application{
		ID:                  uuid.New(),
		Name:                "CORS Priority Test App 2",
		APIKey:              "cors-priority-key-2-" + uuid.New().String(),
		AllowedRedirectURIs: []string{"http://localhost:3000/callback"},
		CORSOrigins:         []string{"http://app2.com"},
		CreatedAt:           time.Now(),
		UpdatedAt:           time.Now(),
	}

	// Insert test applications
	insertQuery := `
		INSERT INTO applications (id, name, api_key, allowed_redirect_uris, cors_origins, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
	`
	_, err := database.DB.Exec(ctx, insertQuery,
		testApp1.ID,
		testApp1.Name,
		testApp1.APIKey,
		testApp1.AllowedRedirectURIs,
		testApp1.CORSOrigins,
		testApp1.CreatedAt,
		testApp1.UpdatedAt,
	)
	require.NoError(t, err)

	_, err = database.DB.Exec(ctx, insertQuery,
		testApp2.ID,
		testApp2.Name,
		testApp2.APIKey,
		testApp2.AllowedRedirectURIs,
		testApp2.CORSOrigins,
		testApp2.CreatedAt,
		testApp2.UpdatedAt,
	)
	require.NoError(t, err)

	// Cleanup after test
	defer func() {
		deleteQuery := `DELETE FROM applications WHERE id = $1`
		database.DB.Exec(ctx, deleteQuery, testApp1.ID)
		database.DB.Exec(ctx, deleteQuery, testApp2.ID)
	}()

	// Create Fiber app with CORS middleware
	app := fiber.New()

	app.Get("/test", DynamicCORS(), func(c *fiber.Ctx) error {
		return c.SendString("success")
	})

	// Test with both query param and header - query should take priority
	req := httptest.NewRequest("GET", "/test?app_id="+testApp1.ID.String(), nil)
	req.Header.Set("X-App-ID", testApp2.ID.String())
	req.Header.Set("Origin", "http://app1.com")
	resp, err := app.Test(req)

	require.NoError(t, err)
	assert.Equal(t, fiber.StatusOK, resp.StatusCode)
	assert.Equal(t, "http://app1.com", resp.Header.Get("Access-Control-Allow-Origin"))

	// app2's origin should be rejected when using app1's ID
	req = httptest.NewRequest("GET", "/test?app_id="+testApp1.ID.String(), nil)
	req.Header.Set("X-App-ID", testApp2.ID.String())
	req.Header.Set("Origin", "http://app2.com")
	resp, err = app.Test(req)

	require.NoError(t, err)
	assert.Equal(t, fiber.StatusForbidden, resp.StatusCode)
}

// TestDynamicCORS_Integration_EmptyOriginsList tests app with empty origins
func TestDynamicCORS_Integration_EmptyOriginsList(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test")
	}

	// Ensure database is connected
	if database.DB == nil {
		t.Skip("Database not connected")
	}

	ctx := context.Background()

	// Create a test application with empty origins
	testApp := models.Application{
		ID:                  uuid.New(),
		Name:                "CORS Empty Origins App",
		APIKey:              "cors-empty-key-" + uuid.New().String(),
		AllowedRedirectURIs: []string{"http://localhost:3000/callback"},
		CORSOrigins:         []string{},
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

	// Create Fiber app with CORS middleware
	app := fiber.New()

	app.Get("/test", DynamicCORS(), func(c *fiber.Ctx) error {
		return c.SendString("success")
	})

	// Test with any origin - should be rejected
	req := httptest.NewRequest("GET", "/test?app_id="+testApp.ID.String(), nil)
	req.Header.Set("Origin", "http://localhost:3000")
	resp, err := app.Test(req)

	require.NoError(t, err)
	assert.Equal(t, fiber.StatusForbidden, resp.StatusCode)
	assert.Empty(t, resp.Header.Get("Access-Control-Allow-Origin"))
}

// TestDynamicCORS_Integration_MalformedAppID tests with malformed app_id
func TestDynamicCORS_Integration_MalformedAppID(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test")
	}

	// Ensure database is connected
	if database.DB == nil {
		t.Skip("Database not connected")
	}

	// Create Fiber app with CORS middleware
	app := fiber.New()

	app.Get("/test", DynamicCORS(), func(c *fiber.Ctx) error {
		return c.SendString("success")
	})

	// Test with malformed UUID
	req := httptest.NewRequest("GET", "/test?app_id=not-a-valid-uuid", nil)
	req.Header.Set("Origin", "http://localhost:3000")
	resp, err := app.Test(req)

	require.NoError(t, err)
	// Implementation should handle gracefully - either allow (dev mode) or reject
	assert.NotEqual(t, fiber.StatusInternalServerError, resp.StatusCode)
}
