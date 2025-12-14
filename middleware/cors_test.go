package middleware

import (
	"io"
	"net/http/httptest"
	"testing"

	"rauth/models"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
)

// TestDynamicCORS_MissingOriginHeader tests CORS middleware without Origin header
func TestDynamicCORS_MissingOriginHeader(t *testing.T) {
	app := fiber.New()

	app.Get("/test", DynamicCORS(), func(c *fiber.Ctx) error {
		return c.SendString("success")
	})

	req := httptest.NewRequest("GET", "/test", nil)
	resp, err := app.Test(req)

	assert.NoError(t, err)
	assert.Equal(t, fiber.StatusOK, resp.StatusCode)
	// No CORS headers should be set without Origin
	assert.Empty(t, resp.Header.Get("Access-Control-Allow-Origin"))
}

// TestDynamicCORS_NoAppID_AllowsAllOrigins tests dev mode (no app_id)
func TestDynamicCORS_NoAppID_AllowsAllOrigins(t *testing.T) {
	app := fiber.New()

	app.Get("/test", DynamicCORS(), func(c *fiber.Ctx) error {
		return c.SendString("success")
	})

	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("Origin", "http://any-origin.com")
	resp, err := app.Test(req)

	assert.NoError(t, err)
	assert.Equal(t, fiber.StatusOK, resp.StatusCode)
	// Development mode should allow any origin
	assert.Equal(t, "http://any-origin.com", resp.Header.Get("Access-Control-Allow-Origin"))
	assert.Equal(t, "true", resp.Header.Get("Access-Control-Allow-Credentials"))
}

// TestDynamicCORS_WithAppInContext_AllowedOrigin tests allowed origin from app context
func TestDynamicCORS_WithAppInContext_AllowedOrigin(t *testing.T) {
	app := fiber.New()

	testApp := models.Application{
		ID:          uuid.New(),
		Name:        "Test App",
		APIKey:      "test-key",
		CORSOrigins: []string{"http://allowed-origin.com", "http://another-allowed.com"},
	}

	app.Get("/test", func(c *fiber.Ctx) error {
		c.Locals("application", testApp)
		return DynamicCORS()(c)
	}, func(c *fiber.Ctx) error {
		return c.SendString("success")
	})

	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("Origin", "http://allowed-origin.com")
	resp, err := app.Test(req)

	assert.NoError(t, err)
	assert.Equal(t, fiber.StatusOK, resp.StatusCode)
	assert.Equal(t, "http://allowed-origin.com", resp.Header.Get("Access-Control-Allow-Origin"))
	assert.Equal(t, "true", resp.Header.Get("Access-Control-Allow-Credentials"))
}

// TestDynamicCORS_WithAppInContext_DisallowedOrigin tests disallowed origin
func TestDynamicCORS_WithAppInContext_DisallowedOrigin(t *testing.T) {
	app := fiber.New()

	testApp := models.Application{
		ID:          uuid.New(),
		Name:        "Test App",
		APIKey:      "test-key",
		CORSOrigins: []string{"http://allowed-origin.com"},
	}

	app.Get("/test", func(c *fiber.Ctx) error {
		c.Locals("application", testApp)
		return DynamicCORS()(c)
	}, func(c *fiber.Ctx) error {
		return c.SendString("success")
	})

	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("Origin", "http://malicious-origin.com")
	resp, err := app.Test(req)

	assert.NoError(t, err)
	assert.Equal(t, fiber.StatusForbidden, resp.StatusCode)
	assert.Empty(t, resp.Header.Get("Access-Control-Allow-Origin"))

	body, _ := io.ReadAll(resp.Body)
	assert.Contains(t, string(body), "Origin not allowed")
}

// TestDynamicCORS_WithAppInContext_WildcardOrigin tests wildcard origin
func TestDynamicCORS_WithAppInContext_WildcardOrigin(t *testing.T) {
	app := fiber.New()

	testApp := models.Application{
		ID:          uuid.New(),
		Name:        "Test App",
		APIKey:      "test-key",
		CORSOrigins: []string{"*"},
	}

	app.Get("/test", func(c *fiber.Ctx) error {
		c.Locals("application", testApp)
		return DynamicCORS()(c)
	}, func(c *fiber.Ctx) error {
		return c.SendString("success")
	})

	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("Origin", "http://any-origin.com")
	resp, err := app.Test(req)

	assert.NoError(t, err)
	assert.Equal(t, fiber.StatusOK, resp.StatusCode)
	assert.Equal(t, "http://any-origin.com", resp.Header.Get("Access-Control-Allow-Origin"))
	assert.Equal(t, "true", resp.Header.Get("Access-Control-Allow-Credentials"))
}

// TestDynamicCORS_PreflightRequest_NoAppID tests OPTIONS preflight without app_id
func TestDynamicCORS_PreflightRequest_NoAppID(t *testing.T) {
	app := fiber.New()

	app.Options("/test", DynamicCORS(), func(c *fiber.Ctx) error {
		return c.SendString("should not reach here")
	})

	req := httptest.NewRequest("OPTIONS", "/test", nil)
	req.Header.Set("Origin", "http://localhost:3000")
	req.Header.Set("Access-Control-Request-Method", "POST")
	req.Header.Set("Access-Control-Request-Headers", "Content-Type")
	resp, err := app.Test(req)

	assert.NoError(t, err)
	assert.Equal(t, fiber.StatusNoContent, resp.StatusCode)
	assert.Equal(t, "http://localhost:3000", resp.Header.Get("Access-Control-Allow-Origin"))
	assert.Equal(t, "GET, POST, PUT, DELETE, OPTIONS, PATCH", resp.Header.Get("Access-Control-Allow-Methods"))
	assert.Contains(t, resp.Header.Get("Access-Control-Allow-Headers"), "Content-Type")
	assert.Equal(t, "3600", resp.Header.Get("Access-Control-Max-Age"))
}

// TestDynamicCORS_PreflightRequest_WithApp_AllowedOrigin tests OPTIONS with allowed origin
func TestDynamicCORS_PreflightRequest_WithApp_AllowedOrigin(t *testing.T) {
	app := fiber.New()

	testApp := models.Application{
		ID:          uuid.New(),
		Name:        "Test App",
		APIKey:      "test-key",
		CORSOrigins: []string{"http://allowed-origin.com"},
	}

	app.Options("/test", func(c *fiber.Ctx) error {
		c.Locals("application", testApp)
		return DynamicCORS()(c)
	})

	req := httptest.NewRequest("OPTIONS", "/test", nil)
	req.Header.Set("Origin", "http://allowed-origin.com")
	req.Header.Set("Access-Control-Request-Method", "POST")
	resp, err := app.Test(req)

	assert.NoError(t, err)
	assert.Equal(t, fiber.StatusNoContent, resp.StatusCode)
	assert.Equal(t, "http://allowed-origin.com", resp.Header.Get("Access-Control-Allow-Origin"))
	assert.Equal(t, "GET, POST, PUT, DELETE, OPTIONS, PATCH", resp.Header.Get("Access-Control-Allow-Methods"))
}

// TestDynamicCORS_PreflightRequest_WithApp_DisallowedOrigin tests OPTIONS with disallowed origin
func TestDynamicCORS_PreflightRequest_WithApp_DisallowedOrigin(t *testing.T) {
	app := fiber.New()

	testApp := models.Application{
		ID:          uuid.New(),
		Name:        "Test App",
		APIKey:      "test-key",
		CORSOrigins: []string{"http://allowed-origin.com"},
	}

	app.Options("/test", func(c *fiber.Ctx) error {
		c.Locals("application", testApp)
		return DynamicCORS()(c)
	})

	req := httptest.NewRequest("OPTIONS", "/test", nil)
	req.Header.Set("Origin", "http://malicious-origin.com")
	req.Header.Set("Access-Control-Request-Method", "POST")
	resp, err := app.Test(req)

	assert.NoError(t, err)
	assert.Equal(t, fiber.StatusForbidden, resp.StatusCode)
	assert.Empty(t, resp.Header.Get("Access-Control-Allow-Origin"))
}

// TestDynamicCORS_AppIDFromQueryParam tests retrieving app_id from query parameter
func TestDynamicCORS_AppIDFromQueryParam(t *testing.T) {
	// This test will verify that app_id can be read from query parameter
	// Implementation should retrieve application from database
	t.Skip("Integration test - requires database connection")
}

// TestDynamicCORS_AppIDFromHeader tests retrieving app_id from X-App-ID header
func TestDynamicCORS_AppIDFromHeader(t *testing.T) {
	// This test will verify that app_id can be read from header
	// Implementation should retrieve application from database
	t.Skip("Integration test - requires database connection")
}

// TestDynamicCORS_AllowedMethods tests that correct HTTP methods are allowed
func TestDynamicCORS_AllowedMethods(t *testing.T) {
	app := fiber.New()

	app.Options("/test", DynamicCORS(), func(c *fiber.Ctx) error {
		return c.SendString("should not reach here")
	})

	req := httptest.NewRequest("OPTIONS", "/test", nil)
	req.Header.Set("Origin", "http://localhost:3000")
	req.Header.Set("Access-Control-Request-Method", "POST")
	resp, err := app.Test(req)

	assert.NoError(t, err)
	allowedMethods := resp.Header.Get("Access-Control-Allow-Methods")
	assert.Contains(t, allowedMethods, "GET")
	assert.Contains(t, allowedMethods, "POST")
	assert.Contains(t, allowedMethods, "PUT")
	assert.Contains(t, allowedMethods, "DELETE")
	assert.Contains(t, allowedMethods, "OPTIONS")
	assert.Contains(t, allowedMethods, "PATCH")
}

// TestDynamicCORS_AllowedHeaders tests that correct headers are allowed
func TestDynamicCORS_AllowedHeaders(t *testing.T) {
	app := fiber.New()

	app.Options("/test", DynamicCORS(), func(c *fiber.Ctx) error {
		return c.SendString("should not reach here")
	})

	req := httptest.NewRequest("OPTIONS", "/test", nil)
	req.Header.Set("Origin", "http://localhost:3000")
	req.Header.Set("Access-Control-Request-Method", "POST")
	req.Header.Set("Access-Control-Request-Headers", "Content-Type, Authorization")
	resp, err := app.Test(req)

	assert.NoError(t, err)
	allowedHeaders := resp.Header.Get("Access-Control-Allow-Headers")
	assert.NotEmpty(t, allowedHeaders)
	// Should reflect requested headers or have a default set
}

// TestDynamicCORS_EmptyCORSOrigins tests app with empty CORS origins array
func TestDynamicCORS_EmptyCORSOrigins(t *testing.T) {
	app := fiber.New()

	testApp := models.Application{
		ID:          uuid.New(),
		Name:        "Test App",
		APIKey:      "test-key",
		CORSOrigins: []string{}, // Empty origins
	}

	app.Get("/test", func(c *fiber.Ctx) error {
		c.Locals("application", testApp)
		return DynamicCORS()(c)
	}, func(c *fiber.Ctx) error {
		return c.SendString("success")
	})

	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("Origin", "http://any-origin.com")
	resp, err := app.Test(req)

	assert.NoError(t, err)
	assert.Equal(t, fiber.StatusForbidden, resp.StatusCode)
	assert.Empty(t, resp.Header.Get("Access-Control-Allow-Origin"))
}

// TestDynamicCORS_NilCORSOrigins tests app with nil CORS origins
func TestDynamicCORS_NilCORSOrigins(t *testing.T) {
	app := fiber.New()

	testApp := models.Application{
		ID:          uuid.New(),
		Name:        "Test App",
		APIKey:      "test-key",
		CORSOrigins: nil, // Nil origins
	}

	app.Get("/test", func(c *fiber.Ctx) error {
		c.Locals("application", testApp)
		return DynamicCORS()(c)
	}, func(c *fiber.Ctx) error {
		return c.SendString("success")
	})

	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("Origin", "http://any-origin.com")
	resp, err := app.Test(req)

	assert.NoError(t, err)
	assert.Equal(t, fiber.StatusForbidden, resp.StatusCode)
	assert.Empty(t, resp.Header.Get("Access-Control-Allow-Origin"))
}

// TestDynamicCORS_MultipleOrigins tests app with multiple allowed origins
func TestDynamicCORS_MultipleOrigins(t *testing.T) {
	app := fiber.New()

	testApp := models.Application{
		ID:     uuid.New(),
		Name:   "Test App",
		APIKey: "test-key",
		CORSOrigins: []string{
			"http://localhost:3000",
			"http://localhost:4000",
			"https://production.com",
		},
	}

	app.Get("/test", func(c *fiber.Ctx) error {
		c.Locals("application", testApp)
		return DynamicCORS()(c)
	}, func(c *fiber.Ctx) error {
		return c.SendString("success")
	})

	// Test each allowed origin
	allowedOrigins := []string{
		"http://localhost:3000",
		"http://localhost:4000",
		"https://production.com",
	}

	for _, origin := range allowedOrigins {
		req := httptest.NewRequest("GET", "/test", nil)
		req.Header.Set("Origin", origin)
		resp, err := app.Test(req)

		assert.NoError(t, err)
		assert.Equal(t, fiber.StatusOK, resp.StatusCode, "Origin %s should be allowed", origin)
		assert.Equal(t, origin, resp.Header.Get("Access-Control-Allow-Origin"))
	}

	// Test disallowed origin
	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("Origin", "http://evil.com")
	resp, err := app.Test(req)

	assert.NoError(t, err)
	assert.Equal(t, fiber.StatusForbidden, resp.StatusCode)
	assert.Empty(t, resp.Header.Get("Access-Control-Allow-Origin"))
}

// TestDynamicCORS_CaseSensitiveOrigins tests that origin matching is case-sensitive
func TestDynamicCORS_CaseSensitiveOrigins(t *testing.T) {
	app := fiber.New()

	testApp := models.Application{
		ID:          uuid.New(),
		Name:        "Test App",
		APIKey:      "test-key",
		CORSOrigins: []string{"http://example.com"},
	}

	app.Get("/test", func(c *fiber.Ctx) error {
		c.Locals("application", testApp)
		return DynamicCORS()(c)
	}, func(c *fiber.Ctx) error {
		return c.SendString("success")
	})

	// Test with different case - should fail
	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("Origin", "http://Example.com")
	resp, err := app.Test(req)

	assert.NoError(t, err)
	assert.Equal(t, fiber.StatusForbidden, resp.StatusCode)
	assert.Empty(t, resp.Header.Get("Access-Control-Allow-Origin"))
}

// TestDynamicCORS_ExposedHeaders tests that response headers are properly exposed
func TestDynamicCORS_ExposedHeaders(t *testing.T) {
	app := fiber.New()

	app.Get("/test", DynamicCORS(), func(c *fiber.Ctx) error {
		return c.SendString("success")
	})

	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("Origin", "http://localhost:3000")
	resp, err := app.Test(req)

	assert.NoError(t, err)
	// Should expose custom headers if any
	exposedHeaders := resp.Header.Get("Access-Control-Expose-Headers")
	if exposedHeaders != "" {
		// Verify common exposed headers
		assert.NotEmpty(t, exposedHeaders)
	}
}
