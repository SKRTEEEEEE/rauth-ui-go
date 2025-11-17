package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"testing"

	"rauth/database"
	"rauth/middleware"
	"rauth/models"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestAdminEndpointsIntegration tests the complete admin API flow
func TestAdminEndpointsIntegration(t *testing.T) {
	// Skip if database not available
	if err := database.Connect(); err != nil {
		t.Skipf("Skipping integration test: database not available: %v", err)
	}
	defer database.Close()

	// Setup Fiber app with admin routes
	app := fiber.New()
	adminRoutes := app.Group("/api/v1/admin")
	adminRoutes.Use(middleware.RequireAPIKey)

	adminRoutes.Post("/apps", CreateApp)
	adminRoutes.Get("/apps", ListApps)
	adminRoutes.Get("/apps/:id", GetApp)
	adminRoutes.Patch("/apps/:id", UpdateApp)
	adminRoutes.Delete("/apps/:id", DeleteApp)
	adminRoutes.Get("/apps/:id/users", ListAppUsers)

	ctx := context.Background()

	// Create a test application to use for API key authentication
	testAPIKey := generateAPIKey()
	var testAppID uuid.UUID
	err := database.DB.QueryRow(ctx,
		`INSERT INTO applications (name, api_key, allowed_redirect_uris, cors_origins)
		 VALUES ($1, $2, $3, $4) RETURNING id`,
		"Test Auth App",
		testAPIKey,
		[]string{},
		[]string{},
	).Scan(&testAppID)
	require.NoError(t, err)

	defer database.DB.Exec(ctx, "DELETE FROM applications WHERE id = $1", testAppID)

	t.Run("Complete CRUD Flow", func(t *testing.T) {
		// Step 1: Create a new application
		createReq := models.CreateApplicationRequest{
			Name:                "Integration Test App",
			AllowedRedirectURIs: []string{"http://localhost:3000/callback", "http://localhost:3000/auth"},
			CORSOrigins:         []string{"http://localhost:3000"},
		}

		body, _ := json.Marshal(createReq)
		req := httptest.NewRequest("POST", "/api/v1/admin/apps", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-API-Key", testAPIKey)

		resp, err := app.Test(req, -1)
		require.NoError(t, err)
		assert.Equal(t, fiber.StatusCreated, resp.StatusCode)

		var createdApp models.Application
		json.NewDecoder(resp.Body).Decode(&createdApp)

		assert.NotEmpty(t, createdApp.ID)
		assert.Equal(t, "Integration Test App", createdApp.Name)
		assert.NotEmpty(t, createdApp.APIKey)
		assert.Equal(t, 64, len(createdApp.APIKey))
		assert.Contains(t, createdApp.AllowedRedirectURIs, "http://localhost:3000/callback")
		assert.Contains(t, createdApp.CORSOrigins, "http://localhost:3000")

		appID := createdApp.ID.String()

		// Cleanup at the end
		defer database.DB.Exec(ctx, "DELETE FROM applications WHERE id = $1", createdApp.ID)

		// Step 2: Verify OAuth providers were created
		var providerCount int
		err = database.DB.QueryRow(ctx,
			"SELECT COUNT(*) FROM oauth_providers WHERE app_id = $1",
			createdApp.ID,
		).Scan(&providerCount)
		require.NoError(t, err)
		assert.Equal(t, len(models.ValidProviders()), providerCount)

		// Step 3: List all applications (should include our new app)
		req = httptest.NewRequest("GET", "/api/v1/admin/apps", nil)
		req.Header.Set("X-API-Key", testAPIKey)

		resp, err = app.Test(req, -1)
		require.NoError(t, err)
		assert.Equal(t, fiber.StatusOK, resp.StatusCode)

		var apps []models.Application
		json.NewDecoder(resp.Body).Decode(&apps)
		assert.GreaterOrEqual(t, len(apps), 1)

		// Find our app in the list
		found := false
		for _, a := range apps {
			if a.ID == createdApp.ID {
				found = true
				break
			}
		}
		assert.True(t, found, "Created app should be in list")

		// Step 4: Get specific application
		req = httptest.NewRequest("GET", "/api/v1/admin/apps/"+appID, nil)
		req.Header.Set("X-API-Key", testAPIKey)

		resp, err = app.Test(req, -1)
		require.NoError(t, err)
		assert.Equal(t, fiber.StatusOK, resp.StatusCode)

		var fetchedApp models.Application
		json.NewDecoder(resp.Body).Decode(&fetchedApp)
		assert.Equal(t, createdApp.ID, fetchedApp.ID)
		assert.Equal(t, createdApp.Name, fetchedApp.Name)

		// Step 5: Update application
		newName := "Updated Integration Test App"
		newRedirectURIs := []string{"http://localhost:4000/callback"}
		updateReq := models.UpdateApplicationRequest{
			Name:                &newName,
			AllowedRedirectURIs: &newRedirectURIs,
		}

		body, _ = json.Marshal(updateReq)
		req = httptest.NewRequest("PATCH", "/api/v1/admin/apps/"+appID, bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-API-Key", testAPIKey)

		resp, err = app.Test(req, -1)
		require.NoError(t, err)
		assert.Equal(t, fiber.StatusOK, resp.StatusCode)

		var updatedApp models.Application
		json.NewDecoder(resp.Body).Decode(&updatedApp)
		assert.Equal(t, "Updated Integration Test App", updatedApp.Name)
		assert.Contains(t, updatedApp.AllowedRedirectURIs, "http://localhost:4000/callback")

		// Step 6: Create test users for the app
		var userIDs []uuid.UUID
		for i := 0; i < 3; i++ {
			var userID uuid.UUID
			email := fmt.Sprintf("testuser%d@example.com", i)
			err := database.DB.QueryRow(ctx,
				`INSERT INTO users (app_id, email, name, email_verified)
				 VALUES ($1, $2, $3, $4) RETURNING id`,
				createdApp.ID,
				email,
				fmt.Sprintf("Test User %d", i),
				true,
			).Scan(&userID)
			require.NoError(t, err)
			userIDs = append(userIDs, userID)
		}

		defer func() {
			for _, id := range userIDs {
				database.DB.Exec(ctx, "DELETE FROM users WHERE id = $1", id)
			}
		}()

		// Step 7: List users of the application
		req = httptest.NewRequest("GET", "/api/v1/admin/apps/"+appID+"/users", nil)
		req.Header.Set("X-API-Key", testAPIKey)

		resp, err = app.Test(req, -1)
		require.NoError(t, err)
		assert.Equal(t, fiber.StatusOK, resp.StatusCode)

		var users []models.User
		json.NewDecoder(resp.Body).Decode(&users)
		assert.Equal(t, 3, len(users))

		// Verify all users belong to our app
		for _, user := range users {
			assert.Equal(t, createdApp.ID, user.AppID)
			assert.NotNil(t, user.Email)
			assert.NotNil(t, user.Name)
		}

		// Step 8: Delete application
		req = httptest.NewRequest("DELETE", "/api/v1/admin/apps/"+appID, nil)
		req.Header.Set("X-API-Key", testAPIKey)

		resp, err = app.Test(req, -1)
		require.NoError(t, err)
		assert.Equal(t, fiber.StatusNoContent, resp.StatusCode)

		// Step 9: Verify deletion - app should not exist
		req = httptest.NewRequest("GET", "/api/v1/admin/apps/"+appID, nil)
		req.Header.Set("X-API-Key", testAPIKey)

		resp, err = app.Test(req, -1)
		require.NoError(t, err)
		assert.Equal(t, fiber.StatusNotFound, resp.StatusCode)

		// Verify CASCADE delete worked - users should be deleted
		var userCount int
		err = database.DB.QueryRow(ctx,
			"SELECT COUNT(*) FROM users WHERE app_id = $1",
			createdApp.ID,
		).Scan(&userCount)
		require.NoError(t, err)
		assert.Equal(t, 0, userCount, "Users should be cascade deleted")

		// Verify OAuth providers were cascade deleted
		err = database.DB.QueryRow(ctx,
			"SELECT COUNT(*) FROM oauth_providers WHERE app_id = $1",
			createdApp.ID,
		).Scan(&providerCount)
		require.NoError(t, err)
		assert.Equal(t, 0, providerCount, "OAuth providers should be cascade deleted")
	})

	t.Run("API Key Authentication", func(t *testing.T) {
		// Test without API key
		req := httptest.NewRequest("GET", "/api/v1/admin/apps", nil)
		resp, err := app.Test(req, -1)
		require.NoError(t, err)
		assert.Equal(t, fiber.StatusUnauthorized, resp.StatusCode)

		// Test with invalid API key
		req = httptest.NewRequest("GET", "/api/v1/admin/apps", nil)
		req.Header.Set("X-API-Key", "invalid-key")
		resp, err = app.Test(req, -1)
		require.NoError(t, err)
		assert.Equal(t, fiber.StatusUnauthorized, resp.StatusCode)

		// Test with valid API key
		req = httptest.NewRequest("GET", "/api/v1/admin/apps", nil)
		req.Header.Set("X-API-Key", testAPIKey)
		resp, err = app.Test(req, -1)
		require.NoError(t, err)
		assert.Equal(t, fiber.StatusOK, resp.StatusCode)
	})

	t.Run("Error Handling", func(t *testing.T) {
		// Test creating app with empty name
		createReq := models.CreateApplicationRequest{
			Name: "",
		}

		body, _ := json.Marshal(createReq)
		req := httptest.NewRequest("POST", "/api/v1/admin/apps", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-API-Key", testAPIKey)

		resp, err := app.Test(req, -1)
		require.NoError(t, err)
		assert.Equal(t, fiber.StatusBadRequest, resp.StatusCode)

		var errResp map[string]interface{}
		json.NewDecoder(resp.Body).Decode(&errResp)
		assert.Contains(t, errResp["error"], "Name is required")

		// Test getting app with invalid UUID
		req = httptest.NewRequest("GET", "/api/v1/admin/apps/invalid-uuid", nil)
		req.Header.Set("X-API-Key", testAPIKey)

		resp, err = app.Test(req, -1)
		require.NoError(t, err)
		assert.Equal(t, fiber.StatusBadRequest, resp.StatusCode)

		json.NewDecoder(resp.Body).Decode(&errResp)
		assert.Contains(t, errResp["error"], "Invalid application ID")

		// Test getting non-existent app
		nonExistentID := uuid.New().String()
		req = httptest.NewRequest("GET", "/api/v1/admin/apps/"+nonExistentID, nil)
		req.Header.Set("X-API-Key", testAPIKey)

		resp, err = app.Test(req, -1)
		require.NoError(t, err)
		assert.Equal(t, fiber.StatusNotFound, resp.StatusCode)

		json.NewDecoder(resp.Body).Decode(&errResp)
		assert.Contains(t, errResp["error"], "Application not found")
	})

	t.Run("Update Partial Fields", func(t *testing.T) {
		// Create test app
		createReq := models.CreateApplicationRequest{
			Name:                "Partial Update Test",
			AllowedRedirectURIs: []string{"http://localhost:3000/callback"},
			CORSOrigins:         []string{"http://localhost:3000"},
		}

		body, _ := json.Marshal(createReq)
		req := httptest.NewRequest("POST", "/api/v1/admin/apps", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-API-Key", testAPIKey)

		resp, err := app.Test(req, -1)
		require.NoError(t, err)

		var createdApp models.Application
		json.NewDecoder(resp.Body).Decode(&createdApp)

		defer database.DB.Exec(ctx, "DELETE FROM applications WHERE id = $1", createdApp.ID)

		// Update only name, leave other fields unchanged
		newName := "Only Name Updated"
		updateReq := models.UpdateApplicationRequest{
			Name: &newName,
		}

		body, _ = json.Marshal(updateReq)
		req = httptest.NewRequest("PATCH", "/api/v1/admin/apps/"+createdApp.ID.String(), bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-API-Key", testAPIKey)

		resp, err = app.Test(req, -1)
		require.NoError(t, err)
		assert.Equal(t, fiber.StatusOK, resp.StatusCode)

		var updatedApp models.Application
		json.NewDecoder(resp.Body).Decode(&updatedApp)

		// Name should be updated
		assert.Equal(t, "Only Name Updated", updatedApp.Name)
		// Other fields should remain unchanged
		assert.Equal(t, createdApp.AllowedRedirectURIs, updatedApp.AllowedRedirectURIs)
		assert.Equal(t, createdApp.CORSOrigins, updatedApp.CORSOrigins)
		assert.Equal(t, createdApp.APIKey, updatedApp.APIKey)
	})

	t.Run("List Users Pagination Limit", func(t *testing.T) {
		// Create app
		createReq := models.CreateApplicationRequest{
			Name: "Pagination Test App",
		}

		body, _ := json.Marshal(createReq)
		req := httptest.NewRequest("POST", "/api/v1/admin/apps", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-API-Key", testAPIKey)

		resp, err := app.Test(req, -1)
		require.NoError(t, err)

		var createdApp models.Application
		json.NewDecoder(resp.Body).Decode(&createdApp)

		defer database.DB.Exec(ctx, "DELETE FROM applications WHERE id = $1", createdApp.ID)

		// Create 101 users (more than limit of 100)
		var userIDs []uuid.UUID
		for i := 0; i < 101; i++ {
			var userID uuid.UUID
			email := fmt.Sprintf("paginationuser%d@test.com", i)
			err := database.DB.QueryRow(ctx,
				`INSERT INTO users (app_id, email, name, email_verified)
				 VALUES ($1, $2, $3, $4) RETURNING id`,
				createdApp.ID,
				email,
				fmt.Sprintf("Pagination User %d", i),
				true,
			).Scan(&userID)
			if err == nil {
				userIDs = append(userIDs, userID)
			}
		}

		defer func() {
			for _, id := range userIDs {
				database.DB.Exec(ctx, "DELETE FROM users WHERE id = $1", id)
			}
		}()

		// List users - should be limited to 100
		req = httptest.NewRequest("GET", "/api/v1/admin/apps/"+createdApp.ID.String()+"/users", nil)
		req.Header.Set("X-API-Key", testAPIKey)

		resp, err = app.Test(req, -1)
		require.NoError(t, err)
		assert.Equal(t, fiber.StatusOK, resp.StatusCode)

		var users []models.User
		json.NewDecoder(resp.Body).Decode(&users)

		// Should return maximum 100 users
		assert.LessOrEqual(t, len(users), 100)
	})
}
