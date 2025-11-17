package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http/httptest"
	"testing"

	"rauth/database"
	"rauth/models"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// setupOAuthTestApp crea una aplicación de prueba con proveedores OAuth
func setupOAuthTestApp(t *testing.T) (*models.Application, func()) {
	ctx := context.Background()

	// Crear aplicación de prueba
	var app models.Application
	query := `
		INSERT INTO applications (name, api_key, allowed_redirect_uris, cors_origins)
		VALUES ($1, $2, $3, $4)
		RETURNING id, name, api_key, allowed_redirect_uris, cors_origins, created_at, updated_at
	`

	err := database.DB.QueryRow(ctx, query,
		"OAuth Test App",
		"oauth-test-key-"+uuid.New().String(),
		[]string{"http://localhost:3000/callback"},
		[]string{"http://localhost:3000"},
	).Scan(
		&app.ID,
		&app.Name,
		&app.APIKey,
		&app.AllowedRedirectURIs,
		&app.CORSOrigins,
		&app.CreatedAt,
		&app.UpdatedAt,
	)
	require.NoError(t, err, "Failed to create test application")

	// Crear proveedores OAuth (deshabilitados por defecto)
	providersQuery := `
		INSERT INTO oauth_providers (app_id, provider, enabled)
		VALUES ($1, $2, false)
	`

	for _, provider := range models.ValidProviders() {
		_, err = database.DB.Exec(ctx, providersQuery, app.ID, provider)
		require.NoError(t, err, "Failed to create OAuth provider")
	}

	// Cleanup function
	cleanup := func() {
		database.DB.Exec(ctx, "DELETE FROM applications WHERE id = $1", app.ID)
	}

	return &app, cleanup
}

func TestListOAuthProviders(t *testing.T) {
	// Skip if database not available
	if err := database.Connect(); err != nil {
		t.Skipf("Skipping integration test: database not available: %v", err)
	}
	defer database.Close()

	app, cleanup := setupOAuthTestApp(t)
	defer cleanup()

	// Create Fiber app
	fiberApp := fiber.New()
	fiberApp.Get("/api/v1/admin/apps/:id/oauth", ListOAuthProviders)

	// Test: List OAuth providers
	t.Run("Success - List all providers", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/v1/admin/apps/"+app.ID.String()+"/oauth", nil)
		req.Header.Set("Content-Type", "application/json")

		resp, err := fiberApp.Test(req, -1)
		require.NoError(t, err)
		assert.Equal(t, fiber.StatusOK, resp.StatusCode)

		var providers []models.OAuthProvider
		err = json.NewDecoder(resp.Body).Decode(&providers)
		require.NoError(t, err)

		// Should have all 4 providers (google, github, facebook, microsoft)
		assert.Len(t, providers, 4)

		// All should be disabled by default
		for _, provider := range providers {
			assert.False(t, provider.Enabled, "Provider %s should be disabled by default", provider.Provider)
			assert.Equal(t, app.ID, provider.AppID)
		}
	})

	// Test: Invalid app ID
	t.Run("Error - Invalid app ID", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/v1/admin/apps/invalid-id/oauth", nil)
		req.Header.Set("Content-Type", "application/json")

		resp, err := fiberApp.Test(req, -1)
		require.NoError(t, err)
		assert.Equal(t, fiber.StatusBadRequest, resp.StatusCode)

		var errorResp map[string]string
		err = json.NewDecoder(resp.Body).Decode(&errorResp)
		require.NoError(t, err)
		assert.Contains(t, errorResp["error"], "Invalid application ID")
	})

	// Test: Non-existent app ID
	t.Run("Success - Non-existent app returns empty list", func(t *testing.T) {
		nonExistentID := uuid.New().String()
		req := httptest.NewRequest("GET", "/api/v1/admin/apps/"+nonExistentID+"/oauth", nil)
		req.Header.Set("Content-Type", "application/json")

		resp, err := fiberApp.Test(req, -1)
		require.NoError(t, err)
		assert.Equal(t, fiber.StatusOK, resp.StatusCode)

		var providers []models.OAuthProvider
		err = json.NewDecoder(resp.Body).Decode(&providers)
		require.NoError(t, err)
		assert.Len(t, providers, 0)
	})
}

func TestToggleOAuthProvider(t *testing.T) {
	// Skip if database not available
	if err := database.Connect(); err != nil {
		t.Skipf("Skipping integration test: database not available: %v", err)
	}
	defer database.Close()

	app, cleanup := setupOAuthTestApp(t)
	defer cleanup()

	// Create Fiber app
	fiberApp := fiber.New()
	fiberApp.Patch("/api/v1/admin/apps/:id/oauth/:provider", ToggleOAuthProvider)

	// Test: Enable Google OAuth
	t.Run("Success - Enable Google provider", func(t *testing.T) {
		reqBody := map[string]bool{"enabled": true}
		bodyBytes, _ := json.Marshal(reqBody)

		req := httptest.NewRequest("PATCH", "/api/v1/admin/apps/"+app.ID.String()+"/oauth/google", bytes.NewReader(bodyBytes))
		req.Header.Set("Content-Type", "application/json")

		resp, err := fiberApp.Test(req, -1)
		require.NoError(t, err)
		assert.Equal(t, fiber.StatusOK, resp.StatusCode)

		var provider models.OAuthProvider
		err = json.NewDecoder(resp.Body).Decode(&provider)
		require.NoError(t, err)

		assert.Equal(t, "google", provider.Provider)
		assert.True(t, provider.Enabled)
		assert.Equal(t, app.ID, provider.AppID)
	})

	// Test: Disable provider
	t.Run("Success - Disable GitHub provider", func(t *testing.T) {
		// First enable it
		ctx := context.Background()
		_, err := database.DB.Exec(ctx,
			"UPDATE oauth_providers SET enabled = true WHERE app_id = $1 AND provider = $2",
			app.ID, "github")
		require.NoError(t, err)

		// Now disable it
		reqBody := map[string]bool{"enabled": false}
		bodyBytes, _ := json.Marshal(reqBody)

		req := httptest.NewRequest("PATCH", "/api/v1/admin/apps/"+app.ID.String()+"/oauth/github", bytes.NewReader(bodyBytes))
		req.Header.Set("Content-Type", "application/json")

		resp, err := fiberApp.Test(req, -1)
		require.NoError(t, err)
		assert.Equal(t, fiber.StatusOK, resp.StatusCode)

		var provider models.OAuthProvider
		err = json.NewDecoder(resp.Body).Decode(&provider)
		require.NoError(t, err)

		assert.Equal(t, "github", provider.Provider)
		assert.False(t, provider.Enabled)
	})

	// Test: Invalid provider name
	t.Run("Error - Invalid provider name", func(t *testing.T) {
		reqBody := map[string]bool{"enabled": true}
		bodyBytes, _ := json.Marshal(reqBody)

		req := httptest.NewRequest("PATCH", "/api/v1/admin/apps/"+app.ID.String()+"/oauth/invalid", bytes.NewReader(bodyBytes))
		req.Header.Set("Content-Type", "application/json")

		resp, err := fiberApp.Test(req, -1)
		require.NoError(t, err)
		assert.Equal(t, fiber.StatusBadRequest, resp.StatusCode)

		var errorResp map[string]string
		err = json.NewDecoder(resp.Body).Decode(&errorResp)
		require.NoError(t, err)
		assert.Contains(t, errorResp["error"], "Invalid provider")
	})

	// Test: Invalid app ID
	t.Run("Error - Invalid app ID", func(t *testing.T) {
		reqBody := map[string]bool{"enabled": true}
		bodyBytes, _ := json.Marshal(reqBody)

		req := httptest.NewRequest("PATCH", "/api/v1/admin/apps/invalid-id/oauth/google", bytes.NewReader(bodyBytes))
		req.Header.Set("Content-Type", "application/json")

		resp, err := fiberApp.Test(req, -1)
		require.NoError(t, err)
		assert.Equal(t, fiber.StatusBadRequest, resp.StatusCode)

		var errorResp map[string]string
		err = json.NewDecoder(resp.Body).Decode(&errorResp)
		require.NoError(t, err)
		assert.Contains(t, errorResp["error"], "Invalid application ID")
	})

	// Test: Non-existent app
	t.Run("Error - Provider not found for non-existent app", func(t *testing.T) {
		nonExistentID := uuid.New()
		reqBody := map[string]bool{"enabled": true}
		bodyBytes, _ := json.Marshal(reqBody)

		req := httptest.NewRequest("PATCH", "/api/v1/admin/apps/"+nonExistentID.String()+"/oauth/google", bytes.NewReader(bodyBytes))
		req.Header.Set("Content-Type", "application/json")

		resp, err := fiberApp.Test(req, -1)
		require.NoError(t, err)
		assert.Equal(t, fiber.StatusNotFound, resp.StatusCode)

		var errorResp map[string]string
		err = json.NewDecoder(resp.Body).Decode(&errorResp)
		require.NoError(t, err)
		assert.Contains(t, errorResp["error"], "Provider configuration not found")
	})

	// Test: Invalid request body
	t.Run("Error - Invalid request body", func(t *testing.T) {
		req := httptest.NewRequest("PATCH", "/api/v1/admin/apps/"+app.ID.String()+"/oauth/google", bytes.NewReader([]byte("invalid json")))
		req.Header.Set("Content-Type", "application/json")

		resp, err := fiberApp.Test(req, -1)
		require.NoError(t, err)
		assert.Equal(t, fiber.StatusBadRequest, resp.StatusCode)

		var errorResp map[string]string
		err = json.NewDecoder(resp.Body).Decode(&errorResp)
		require.NoError(t, err)
		assert.Contains(t, errorResp["error"], "Invalid request body")
	})

	// Test: Enable all providers
	t.Run("Success - Enable all providers", func(t *testing.T) {
		providers := []string{"google", "github", "facebook", "microsoft"}

		for _, providerName := range providers {
			reqBody := map[string]bool{"enabled": true}
			bodyBytes, _ := json.Marshal(reqBody)

			req := httptest.NewRequest("PATCH", "/api/v1/admin/apps/"+app.ID.String()+"/oauth/"+providerName, bytes.NewReader(bodyBytes))
			req.Header.Set("Content-Type", "application/json")

			resp, err := fiberApp.Test(req, -1)
			require.NoError(t, err)
			assert.Equal(t, fiber.StatusOK, resp.StatusCode, "Failed to enable %s", providerName)

			var provider models.OAuthProvider
			err = json.NewDecoder(resp.Body).Decode(&provider)
			require.NoError(t, err)
			assert.True(t, provider.Enabled, "Provider %s should be enabled", providerName)
		}
	})
}

func TestOAuthProviderToggleIntegration(t *testing.T) {
	// Skip if database not available
	if err := database.Connect(); err != nil {
		t.Skipf("Skipping integration test: database not available: %v", err)
	}
	defer database.Close()

	app, cleanup := setupOAuthTestApp(t)
	defer cleanup()

	// Create Fiber app with both routes
	fiberApp := fiber.New()
	fiberApp.Get("/api/v1/admin/apps/:id/oauth", ListOAuthProviders)
	fiberApp.Patch("/api/v1/admin/apps/:id/oauth/:provider", ToggleOAuthProvider)

	// Test: Complete workflow
	t.Run("Integration - List, enable, and verify", func(t *testing.T) {
		// Step 1: List providers (all should be disabled)
		req := httptest.NewRequest("GET", "/api/v1/admin/apps/"+app.ID.String()+"/oauth", nil)
		resp, err := fiberApp.Test(req, -1)
		require.NoError(t, err)
		assert.Equal(t, fiber.StatusOK, resp.StatusCode)

		var providers []models.OAuthProvider
		err = json.NewDecoder(resp.Body).Decode(&providers)
		require.NoError(t, err)
		assert.Len(t, providers, 4)

		// Step 2: Enable Google
		reqBody := map[string]bool{"enabled": true}
		bodyBytes, _ := json.Marshal(reqBody)
		req = httptest.NewRequest("PATCH", "/api/v1/admin/apps/"+app.ID.String()+"/oauth/google", bytes.NewReader(bodyBytes))
		req.Header.Set("Content-Type", "application/json")

		resp, err = fiberApp.Test(req, -1)
		require.NoError(t, err)
		assert.Equal(t, fiber.StatusOK, resp.StatusCode)

		// Step 3: List again and verify Google is enabled
		req = httptest.NewRequest("GET", "/api/v1/admin/apps/"+app.ID.String()+"/oauth", nil)
		resp, err = fiberApp.Test(req, -1)
		require.NoError(t, err)
		assert.Equal(t, fiber.StatusOK, resp.StatusCode)

		providers = []models.OAuthProvider{}
		err = json.NewDecoder(resp.Body).Decode(&providers)
		require.NoError(t, err)

		googleEnabled := false
		for _, p := range providers {
			if p.Provider == "google" {
				googleEnabled = p.Enabled
			}
		}
		assert.True(t, googleEnabled, "Google should be enabled")
	})
}
