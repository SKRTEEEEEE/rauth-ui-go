package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http/httptest"
	"testing"

	"rauth/database"
	"rauth/models"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestGenerateAPIKey tests the API key generation
func TestGenerateAPIKey(t *testing.T) {
	key1 := generateAPIKey()
	key2 := generateAPIKey()

	// Should generate unique keys
	assert.NotEqual(t, key1, key2)

	// Should be 64 characters (32 bytes hex encoded)
	assert.Equal(t, 64, len(key1))
	assert.Equal(t, 64, len(key2))
}

// TestCreateApp tests the CreateApp handler
func TestCreateApp(t *testing.T) {
	// Setup test database
	if err := database.Connect(); err != nil {
		t.Skipf("Skipping test: database not available: %v", err)
	}
	defer database.Close()

	app := fiber.New()
	app.Post("/apps", CreateApp)

	tests := []struct {
		name           string
		requestBody    models.CreateApplicationRequest
		expectedStatus int
		checkResponse  func(t *testing.T, resp map[string]interface{})
	}{
		{
			name: "valid request",
			requestBody: models.CreateApplicationRequest{
				Name:                "Test App",
				AllowedRedirectURIs: []string{"http://localhost:3000/callback"},
				CORSOrigins:         []string{"http://localhost:3000"},
			},
			expectedStatus: fiber.StatusCreated,
			checkResponse: func(t *testing.T, resp map[string]interface{}) {
				assert.NotEmpty(t, resp["id"])
				assert.Equal(t, "Test App", resp["name"])
				assert.NotEmpty(t, resp["api_key"])
				assert.Equal(t, 64, len(resp["api_key"].(string)))
			},
		},
		{
			name: "missing name",
			requestBody: models.CreateApplicationRequest{
				AllowedRedirectURIs: []string{"http://localhost:3000/callback"},
			},
			expectedStatus: fiber.StatusBadRequest,
			checkResponse: func(t *testing.T, resp map[string]interface{}) {
				assert.Contains(t, resp["error"], "Name is required")
			},
		},
		{
			name:           "invalid JSON",
			requestBody:    models.CreateApplicationRequest{},
			expectedStatus: fiber.StatusBadRequest,
			checkResponse: func(t *testing.T, resp map[string]interface{}) {
				// Will be tested with malformed JSON in integration test
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body, _ := json.Marshal(tt.requestBody)
			req := httptest.NewRequest("POST", "/apps", bytes.NewReader(body))
			req.Header.Set("Content-Type", "application/json")

			resp, err := app.Test(req, -1)
			require.NoError(t, err)
			assert.Equal(t, tt.expectedStatus, resp.StatusCode)

			var result map[string]interface{}
			json.NewDecoder(resp.Body).Decode(&result)

			if tt.checkResponse != nil {
				tt.checkResponse(t, result)
			}

			// Cleanup: delete created app
			if tt.expectedStatus == fiber.StatusCreated {
				if id, ok := result["id"].(string); ok {
					appID, _ := uuid.Parse(id)
					database.DB.Exec(context.Background(), "DELETE FROM applications WHERE id = $1", appID)
				}
			}
		})
	}
}

// TestListApps tests the ListApps handler
func TestListApps(t *testing.T) {
	if err := database.Connect(); err != nil {
		t.Skipf("Skipping test: database not available: %v", err)
	}
	defer database.Close()

	// Create test apps
	ctx := context.Background()
	var appIDs []uuid.UUID

	for i := 0; i < 3; i++ {
		var appID uuid.UUID
		err := database.DB.QueryRow(ctx,
			`INSERT INTO applications (name, api_key, allowed_redirect_uris, cors_origins)
			 VALUES ($1, $2, $3, $4) RETURNING id`,
			fmt.Sprintf("Test App %d", i),
			generateAPIKey(),
			[]string{},
			[]string{},
		).Scan(&appID)
		require.NoError(t, err)
		appIDs = append(appIDs, appID)
	}

	// Cleanup
	defer func() {
		for _, id := range appIDs {
			database.DB.Exec(ctx, "DELETE FROM applications WHERE id = $1", id)
		}
	}()

	app := fiber.New()
	app.Get("/apps", ListApps)

	req := httptest.NewRequest("GET", "/apps", nil)
	resp, err := app.Test(req, -1)
	require.NoError(t, err)

	assert.Equal(t, fiber.StatusOK, resp.StatusCode)

	var apps []models.Application
	json.NewDecoder(resp.Body).Decode(&apps)

	// Should return at least the 3 apps we created
	assert.GreaterOrEqual(t, len(apps), 3)
}

// TestGetApp tests the GetApp handler
func TestGetApp(t *testing.T) {
	if err := database.Connect(); err != nil {
		t.Skipf("Skipping test: database not available: %v", err)
	}
	defer database.Close()

	ctx := context.Background()

	// Create test app
	var appID uuid.UUID
	err := database.DB.QueryRow(ctx,
		`INSERT INTO applications (name, api_key, allowed_redirect_uris, cors_origins)
		 VALUES ($1, $2, $3, $4) RETURNING id`,
		"Test App",
		generateAPIKey(),
		[]string{"http://localhost:3000/callback"},
		[]string{"http://localhost:3000"},
	).Scan(&appID)
	require.NoError(t, err)

	defer database.DB.Exec(ctx, "DELETE FROM applications WHERE id = $1", appID)

	app := fiber.New()
	app.Get("/apps/:id", GetApp)

	tests := []struct {
		name           string
		appID          string
		expectedStatus int
		checkResponse  func(t *testing.T, resp map[string]interface{})
	}{
		{
			name:           "valid app ID",
			appID:          appID.String(),
			expectedStatus: fiber.StatusOK,
			checkResponse: func(t *testing.T, resp map[string]interface{}) {
				assert.Equal(t, "Test App", resp["name"])
				assert.NotEmpty(t, resp["api_key"])
			},
		},
		{
			name:           "invalid UUID",
			appID:          "invalid-uuid",
			expectedStatus: fiber.StatusBadRequest,
			checkResponse: func(t *testing.T, resp map[string]interface{}) {
				assert.Contains(t, resp["error"], "Invalid application ID")
			},
		},
		{
			name:           "non-existent app",
			appID:          uuid.New().String(),
			expectedStatus: fiber.StatusNotFound,
			checkResponse: func(t *testing.T, resp map[string]interface{}) {
				assert.Contains(t, resp["error"], "Application not found")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/apps/"+tt.appID, nil)
			resp, err := app.Test(req, -1)
			require.NoError(t, err)

			assert.Equal(t, tt.expectedStatus, resp.StatusCode)

			var result map[string]interface{}
			json.NewDecoder(resp.Body).Decode(&result)
			tt.checkResponse(t, result)
		})
	}
}

// TestUpdateApp tests the UpdateApp handler
func TestUpdateApp(t *testing.T) {
	if err := database.Connect(); err != nil {
		t.Skipf("Skipping test: database not available: %v", err)
	}
	defer database.Close()

	ctx := context.Background()

	// Create test app
	var appID uuid.UUID
	originalName := "Test App"
	err := database.DB.QueryRow(ctx,
		`INSERT INTO applications (name, api_key, allowed_redirect_uris, cors_origins)
		 VALUES ($1, $2, $3, $4) RETURNING id`,
		originalName,
		generateAPIKey(),
		[]string{"http://localhost:3000/callback"},
		[]string{"http://localhost:3000"},
	).Scan(&appID)
	require.NoError(t, err)

	defer database.DB.Exec(ctx, "DELETE FROM applications WHERE id = $1", appID)

	app := fiber.New()
	app.Patch("/apps/:id", UpdateApp)

	tests := []struct {
		name           string
		appID          string
		requestBody    models.UpdateApplicationRequest
		expectedStatus int
		checkResponse  func(t *testing.T, resp map[string]interface{})
	}{
		{
			name:  "update name only",
			appID: appID.String(),
			requestBody: models.UpdateApplicationRequest{
				Name: stringPtr("Updated App Name"),
			},
			expectedStatus: fiber.StatusOK,
			checkResponse: func(t *testing.T, resp map[string]interface{}) {
				assert.Equal(t, "Updated App Name", resp["name"])
			},
		},
		{
			name:  "update redirect URIs",
			appID: appID.String(),
			requestBody: models.UpdateApplicationRequest{
				AllowedRedirectURIs: &[]string{"http://newdomain.com/callback"},
			},
			expectedStatus: fiber.StatusOK,
			checkResponse: func(t *testing.T, resp map[string]interface{}) {
				uris := resp["allowed_redirect_uris"].([]interface{})
				assert.Contains(t, uris, "http://newdomain.com/callback")
			},
		},
		{
			name:           "invalid app ID",
			appID:          "invalid-uuid",
			requestBody:    models.UpdateApplicationRequest{},
			expectedStatus: fiber.StatusBadRequest,
			checkResponse: func(t *testing.T, resp map[string]interface{}) {
				assert.Contains(t, resp["error"], "Invalid application ID")
			},
		},
		{
			name:           "non-existent app",
			appID:          uuid.New().String(),
			requestBody:    models.UpdateApplicationRequest{},
			expectedStatus: fiber.StatusNotFound,
			checkResponse: func(t *testing.T, resp map[string]interface{}) {
				assert.Contains(t, resp["error"], "Application not found")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body, _ := json.Marshal(tt.requestBody)
			req := httptest.NewRequest("PATCH", "/apps/"+tt.appID, bytes.NewReader(body))
			req.Header.Set("Content-Type", "application/json")

			resp, err := app.Test(req, -1)
			require.NoError(t, err)

			assert.Equal(t, tt.expectedStatus, resp.StatusCode)

			var result map[string]interface{}
			json.NewDecoder(resp.Body).Decode(&result)
			tt.checkResponse(t, result)
		})
	}
}

// TestDeleteApp tests the DeleteApp handler
func TestDeleteApp(t *testing.T) {
	if err := database.Connect(); err != nil {
		t.Skipf("Skipping test: database not available: %v", err)
	}
	defer database.Close()

	ctx := context.Background()

	app := fiber.New()
	app.Delete("/apps/:id", DeleteApp)

	tests := []struct {
		name           string
		setupApp       bool
		appID          func() string
		expectedStatus int
		checkResponse  func(t *testing.T, body string)
	}{
		{
			name:     "delete existing app",
			setupApp: true,
			appID: func() string {
				var id uuid.UUID
				database.DB.QueryRow(ctx,
					`INSERT INTO applications (name, api_key, allowed_redirect_uris, cors_origins)
					 VALUES ($1, $2, $3, $4) RETURNING id`,
					"To Delete",
					generateAPIKey(),
					[]string{},
					[]string{},
				).Scan(&id)
				return id.String()
			},
			expectedStatus: fiber.StatusNoContent,
			checkResponse: func(t *testing.T, body string) {
				assert.Empty(t, body)
			},
		},
		{
			name:     "delete non-existent app",
			setupApp: false,
			appID: func() string {
				return uuid.New().String()
			},
			expectedStatus: fiber.StatusNotFound,
			checkResponse: func(t *testing.T, body string) {
				var result map[string]interface{}
				json.Unmarshal([]byte(body), &result)
				assert.Contains(t, result["error"], "Application not found")
			},
		},
		{
			name:     "invalid UUID",
			setupApp: false,
			appID: func() string {
				return "invalid-uuid"
			},
			expectedStatus: fiber.StatusBadRequest,
			checkResponse: func(t *testing.T, body string) {
				var result map[string]interface{}
				json.Unmarshal([]byte(body), &result)
				assert.Contains(t, result["error"], "Invalid application ID")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			appID := tt.appID()

			req := httptest.NewRequest("DELETE", "/apps/"+appID, nil)
			resp, err := app.Test(req, -1)
			require.NoError(t, err)

			assert.Equal(t, tt.expectedStatus, resp.StatusCode)

			bodyBytes := make([]byte, 0)
			if resp.Body != nil {
				bodyBytes, _ = io.ReadAll(resp.Body)
			}
			tt.checkResponse(t, string(bodyBytes))
		})
	}
}

// TestListAppUsers tests the ListAppUsers handler
func TestListAppUsers(t *testing.T) {
	if err := database.Connect(); err != nil {
		t.Skipf("Skipping test: database not available: %v", err)
	}
	defer database.Close()

	ctx := context.Background()

	// Create test app
	var appID uuid.UUID
	err := database.DB.QueryRow(ctx,
		`INSERT INTO applications (name, api_key, allowed_redirect_uris, cors_origins)
		 VALUES ($1, $2, $3, $4) RETURNING id`,
		"Test App",
		generateAPIKey(),
		[]string{},
		[]string{},
	).Scan(&appID)
	require.NoError(t, err)

	defer database.DB.Exec(ctx, "DELETE FROM applications WHERE id = $1", appID)

	// Create test users
	var userIDs []uuid.UUID
	for i := 0; i < 5; i++ {
		var userID uuid.UUID
		email := fmt.Sprintf("user%d@test.com", i)
		err := database.DB.QueryRow(ctx,
			`INSERT INTO users (app_id, email, name, email_verified)
			 VALUES ($1, $2, $3, $4) RETURNING id`,
			appID,
			email,
			fmt.Sprintf("User %d", i),
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

	app := fiber.New()
	app.Get("/apps/:id/users", ListAppUsers)

	tests := []struct {
		name           string
		appID          string
		expectedStatus int
		checkResponse  func(t *testing.T, resp []models.User)
	}{
		{
			name:           "list users of existing app",
			appID:          appID.String(),
			expectedStatus: fiber.StatusOK,
			checkResponse: func(t *testing.T, users []models.User) {
				assert.Equal(t, 5, len(users))
				// Verify users belong to correct app
				for _, user := range users {
					assert.Equal(t, appID, user.AppID)
				}
			},
		},
		{
			name:           "invalid app ID",
			appID:          "invalid-uuid",
			expectedStatus: fiber.StatusBadRequest,
			checkResponse:  nil,
		},
		{
			name:           "non-existent app",
			appID:          uuid.New().String(),
			expectedStatus: fiber.StatusOK,
			checkResponse: func(t *testing.T, users []models.User) {
				assert.Equal(t, 0, len(users))
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/apps/"+tt.appID+"/users", nil)
			resp, err := app.Test(req, -1)
			require.NoError(t, err)

			assert.Equal(t, tt.expectedStatus, resp.StatusCode)

			if tt.checkResponse != nil {
				var users []models.User
				json.NewDecoder(resp.Body).Decode(&users)
				tt.checkResponse(t, users)
			}
		})
	}
}

// Helper functions
func stringPtr(s string) *string {
	return &s
}
