package main

import (
	"io"
	"net/http/httptest"
	"testing"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"github.com/gofiber/fiber/v2/middleware/logger"
	"github.com/stretchr/testify/assert"
)

// setupTestApp creates a test Fiber app with the same configuration as main
func setupTestApp() *fiber.App {
	app := fiber.New(fiber.Config{
		AppName: "RAuth v1.0",
		ErrorHandler: func(c *fiber.Ctx, err error) error {
			code := fiber.StatusInternalServerError
			if e, ok := err.(*fiber.Error); ok {
				code = e.Code
			}
			return c.Status(code).JSON(fiber.Map{
				"error": err.Error(),
			})
		},
	})

	// Middleware
	app.Use(logger.New())
	app.Use(cors.New())

	// Health check endpoint
	app.Get("/health", func(c *fiber.Ctx) error {
		return c.JSON(fiber.Map{
			"status":  "ok",
			"service": "rauth",
		})
	})

	return app
}

func TestHealthEndpoint(t *testing.T) {
	app := setupTestApp()

	// Test cases
	tests := []struct {
		name           string
		method         string
		route          string
		expectedStatus int
		expectedBody   string
	}{
		{
			name:           "Health check returns 200 OK",
			method:         "GET",
			route:          "/health",
			expectedStatus: 200,
			expectedBody:   `{"status":"ok","service":"rauth"}`,
		},
		{
			name:           "Health check only accepts GET",
			method:         "POST",
			route:          "/health",
			expectedStatus: 405,
			expectedBody:   "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(tt.method, tt.route, nil)
			resp, err := app.Test(req, -1)

			assert.NoError(t, err)
			assert.Equal(t, tt.expectedStatus, resp.StatusCode)

			if tt.expectedBody != "" {
				body, err := io.ReadAll(resp.Body)
				assert.NoError(t, err)
				assert.JSONEq(t, tt.expectedBody, string(body))
			}
		})
	}
}

func TestCORSMiddleware(t *testing.T) {
	app := setupTestApp()

	req := httptest.NewRequest("OPTIONS", "/health", nil)
	req.Header.Set("Origin", "http://example.com")
	req.Header.Set("Access-Control-Request-Method", "GET")

	resp, err := app.Test(req, -1)

	assert.NoError(t, err)
	assert.Equal(t, 204, resp.StatusCode)
	assert.NotEmpty(t, resp.Header.Get("Access-Control-Allow-Origin"))
}

func TestErrorHandler(t *testing.T) {
	app := setupTestApp()

	// Add a route that returns an error
	app.Get("/test-error", func(c *fiber.Ctx) error {
		return fiber.NewError(fiber.StatusBadRequest, "test error")
	})

	req := httptest.NewRequest("GET", "/test-error", nil)
	resp, err := app.Test(req, -1)

	assert.NoError(t, err)
	assert.Equal(t, 400, resp.StatusCode)

	body, err := io.ReadAll(resp.Body)
	assert.NoError(t, err)
	assert.Contains(t, string(body), "test error")
}

func TestNotFoundRoute(t *testing.T) {
	app := setupTestApp()

	req := httptest.NewRequest("GET", "/nonexistent", nil)
	resp, err := app.Test(req, -1)

	assert.NoError(t, err)
	assert.Equal(t, 404, resp.StatusCode)
}

func TestHealthResponseStructure(t *testing.T) {
	app := setupTestApp()

	req := httptest.NewRequest("GET", "/health", nil)
	resp, err := app.Test(req, -1)

	assert.NoError(t, err)
	assert.Equal(t, 200, resp.StatusCode)
	assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))

	body, err := io.ReadAll(resp.Body)
	assert.NoError(t, err)

	// Verify JSON structure
	assert.Contains(t, string(body), `"status":"ok"`)
	assert.Contains(t, string(body), `"service":"rauth"`)
}
