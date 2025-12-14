package middleware

import (
	"context"

	"rauth/database"
	"rauth/models"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
)

// DynamicCORS returns a middleware that handles CORS dynamically based on application configuration
func DynamicCORS() fiber.Handler {
	return func(c *fiber.Ctx) error {
		origin := c.Get("Origin")

		// If no Origin header is present, skip CORS handling
		if origin == "" {
			return c.Next()
		}

		// Try to get application from context (already loaded by another middleware)
		app, ok := c.Locals("application").(models.Application)

		// If no application in context, try to load it from app_id
		if !ok {
			// Try to get app_id from query parameter first, then from header
			appIDStr := c.Query("app_id")
			if appIDStr == "" {
				appIDStr = c.Get("X-App-ID")
			}

			// If no app_id provided, allow all origins (development mode)
			if appIDStr == "" {
				setCORSHeaders(c, origin, true)
				if c.Method() == "OPTIONS" {
					return handlePreflight(c)
				}
				return c.Next()
			}

			// Parse app_id as UUID
			appID, err := uuid.Parse(appIDStr)
			if err != nil {
				// Invalid UUID format - fall back to development mode
				setCORSHeaders(c, origin, true)
				if c.Method() == "OPTIONS" {
					return handlePreflight(c)
				}
				return c.Next()
			}

			// Load application from database
			loadedApp, err := loadApplicationByID(appID)
			if err != nil {
				// Application not found - fall back to development mode
				setCORSHeaders(c, origin, true)
				if c.Method() == "OPTIONS" {
					return handlePreflight(c)
				}
				return c.Next()
			}

			app = *loadedApp
			c.Locals("application", app)
		}

		// Check if origin is allowed
		if !isOriginAllowed(origin, app.CORSOrigins) {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{
				"error": "Origin not allowed",
			})
		}

		// Set CORS headers for allowed origin
		setCORSHeaders(c, origin, true)

		// Handle preflight requests
		if c.Method() == "OPTIONS" {
			return handlePreflight(c)
		}

		return c.Next()
	}
}

// isOriginAllowed checks if an origin is in the allowed list
func isOriginAllowed(origin string, allowedOrigins []string) bool {
	if len(allowedOrigins) == 0 {
		return false
	}

	for _, allowed := range allowedOrigins {
		if allowed == "*" {
			return true
		}
		if allowed == origin {
			return true
		}
	}

	return false
}

// setCORSHeaders sets the CORS headers on the response
func setCORSHeaders(c *fiber.Ctx, origin string, allowCredentials bool) {
	c.Set("Access-Control-Allow-Origin", origin)
	if allowCredentials {
		c.Set("Access-Control-Allow-Credentials", "true")
	}
}

// handlePreflight handles OPTIONS preflight requests
func handlePreflight(c *fiber.Ctx) error {
	// Set allowed methods
	c.Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS, PATCH")

	// Set allowed headers - either reflect what was requested or use a default set
	requestedHeaders := c.Get("Access-Control-Request-Headers")
	if requestedHeaders != "" {
		c.Set("Access-Control-Allow-Headers", requestedHeaders)
	} else {
		c.Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Requested-With, X-App-ID")
	}

	// Set max age for preflight cache
	c.Set("Access-Control-Max-Age", "3600")

	return c.SendStatus(fiber.StatusNoContent)
}

// loadApplicationByID loads an application from the database by ID
func loadApplicationByID(appID uuid.UUID) (*models.Application, error) {
	ctx := context.Background()

	query := `
		SELECT id, name, api_key, allowed_redirect_uris, cors_origins, created_at, updated_at
		FROM applications
		WHERE id = $1
	`

	var app models.Application
	err := database.DB.QueryRow(ctx, query, appID).Scan(
		&app.ID,
		&app.Name,
		&app.APIKey,
		&app.AllowedRedirectURIs,
		&app.CORSOrigins,
		&app.CreatedAt,
		&app.UpdatedAt,
	)

	if err != nil {
		return nil, err
	}

	return &app, nil
}
