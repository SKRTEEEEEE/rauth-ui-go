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

// TestRequireAPIKey_MissingAPIKey tests when no API key is provided
func TestRequireAPIKey_MissingAPIKey(t *testing.T) {
	app := fiber.New()

	app.Get("/test", RequireAPIKey, func(c *fiber.Ctx) error {
		return c.SendString("success")
	})

	req := httptest.NewRequest("GET", "/test", nil)
	resp, err := app.Test(req)

	assert.NoError(t, err)
	assert.Equal(t, fiber.StatusUnauthorized, resp.StatusCode)

	body, _ := io.ReadAll(resp.Body)
	assert.Contains(t, string(body), "API key required")
}

// TestRequireAPIKey_EmptyAPIKey tests when empty API key is provided
func TestRequireAPIKey_EmptyAPIKey(t *testing.T) {
	app := fiber.New()

	app.Get("/test", RequireAPIKey, func(c *fiber.Ctx) error {
		return c.SendString("success")
	})

	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("X-API-Key", "")
	resp, err := app.Test(req)

	assert.NoError(t, err)
	assert.Equal(t, fiber.StatusUnauthorized, resp.StatusCode)

	body, _ := io.ReadAll(resp.Body)
	assert.Contains(t, string(body), "API key required")
}

// TestGetApplication_NoApplicationInContext tests GetApplication when no app in context
func TestGetApplication_NoApplicationInContext(t *testing.T) {
	app := fiber.New()

	app.Get("/test", func(c *fiber.Ctx) error {
		_, err := GetApplication(c)
		if err != nil {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error": err.Error(),
			})
		}
		return c.SendString("success")
	})

	req := httptest.NewRequest("GET", "/test", nil)
	resp, err := app.Test(req)

	assert.NoError(t, err)
	assert.Equal(t, fiber.StatusUnauthorized, resp.StatusCode)

	body, _ := io.ReadAll(resp.Body)
	assert.Contains(t, string(body), "No application in context")
}

// TestGetApplication_Success tests GetApplication with valid application in context
func TestGetApplication_Success(t *testing.T) {
	app := fiber.New()

	expectedApp := models.Application{
		ID:     uuid.New(),
		Name:   "Test App",
		APIKey: "test-key",
	}

	app.Get("/test", func(c *fiber.Ctx) error {
		c.Locals("application", expectedApp)

		retrievedApp, err := GetApplication(c)
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": err.Error(),
			})
		}

		return c.JSON(fiber.Map{
			"id":   retrievedApp.ID.String(),
			"name": retrievedApp.Name,
		})
	})

	req := httptest.NewRequest("GET", "/test", nil)
	resp, err := app.Test(req)

	assert.NoError(t, err)
	assert.Equal(t, fiber.StatusOK, resp.StatusCode)

	body, _ := io.ReadAll(resp.Body)
	assert.Contains(t, string(body), expectedApp.ID.String())
	assert.Contains(t, string(body), expectedApp.Name)
}

// TestGetApplication_InvalidType tests GetApplication with wrong type in context
func TestGetApplication_InvalidType(t *testing.T) {
	app := fiber.New()

	app.Get("/test", func(c *fiber.Ctx) error {
		// Store wrong type in context
		c.Locals("application", "invalid-type")

		_, err := GetApplication(c)
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": err.Error(),
			})
		}
		return c.SendString("success")
	})

	req := httptest.NewRequest("GET", "/test", nil)
	resp, err := app.Test(req)

	assert.NoError(t, err)
	assert.Equal(t, fiber.StatusInternalServerError, resp.StatusCode)

	body, _ := io.ReadAll(resp.Body)
	assert.Contains(t, string(body), "Invalid application in context")
}

// TestGetApplicationID_Success tests GetApplicationID with valid application
func TestGetApplicationID_Success(t *testing.T) {
	app := fiber.New()

	expectedID := uuid.New()
	expectedApp := models.Application{
		ID:     expectedID,
		Name:   "Test App",
		APIKey: "test-key",
	}

	app.Get("/test", func(c *fiber.Ctx) error {
		c.Locals("application", expectedApp)

		appID, err := GetApplicationID(c)
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": err.Error(),
			})
		}

		return c.JSON(fiber.Map{
			"id": appID.String(),
		})
	})

	req := httptest.NewRequest("GET", "/test", nil)
	resp, err := app.Test(req)

	assert.NoError(t, err)
	assert.Equal(t, fiber.StatusOK, resp.StatusCode)

	body, _ := io.ReadAll(resp.Body)
	assert.Contains(t, string(body), expectedID.String())
}

// TestGetApplicationID_NoApplication tests GetApplicationID when no app in context
func TestGetApplicationID_NoApplication(t *testing.T) {
	app := fiber.New()

	app.Get("/test", func(c *fiber.Ctx) error {
		_, err := GetApplicationID(c)
		if err != nil {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error": err.Error(),
			})
		}
		return c.SendString("success")
	})

	req := httptest.NewRequest("GET", "/test", nil)
	resp, err := app.Test(req)

	assert.NoError(t, err)
	assert.Equal(t, fiber.StatusUnauthorized, resp.StatusCode)
}

// TestRequireAPIKey_ContextPropagation tests that application is properly stored in context
func TestRequireAPIKey_ContextPropagation(t *testing.T) {
	// This test would require a real database connection
	// It's marked as an integration test
	t.Skip("Integration test - requires database connection")
}
