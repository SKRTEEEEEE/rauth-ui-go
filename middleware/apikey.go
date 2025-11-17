package middleware

import (
	"context"

	"rauth/database"
	"rauth/models"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// RequireAPIKey middleware valida el API key del header
func RequireAPIKey(c *fiber.Ctx) error {
	// Obtener API key del header
	apiKey := c.Get("X-API-Key")
	if apiKey == "" {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"error": "API key required",
		})
	}

	// Buscar aplicación por API key
	ctx := context.Background()
	var app models.Application

	query := `
		SELECT id, name, api_key, allowed_redirect_uris, cors_origins, created_at, updated_at
		FROM applications
		WHERE api_key = $1
	`

	err := database.DB.QueryRow(ctx, query, apiKey).Scan(
		&app.ID,
		&app.Name,
		&app.APIKey,
		&app.AllowedRedirectURIs,
		&app.CORSOrigins,
		&app.CreatedAt,
		&app.UpdatedAt,
	)

	if err != nil {
		if err == pgx.ErrNoRows {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error": "Invalid API key",
			})
		}
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Database error",
		})
	}

	// Guardar aplicación en el contexto
	c.Locals("application", app)

	return c.Next()
}

// GetApplication obtiene la aplicación del contexto
func GetApplication(c *fiber.Ctx) (*models.Application, error) {
	app := c.Locals("application")
	if app == nil {
		return nil, fiber.NewError(fiber.StatusUnauthorized, "No application in context")
	}

	application, ok := app.(models.Application)
	if !ok {
		return nil, fiber.NewError(fiber.StatusInternalServerError, "Invalid application in context")
	}

	return &application, nil
}

// GetApplicationID obtiene solo el ID de la aplicación
func GetApplicationID(c *fiber.Ctx) (uuid.UUID, error) {
	app, err := GetApplication(c)
	if err != nil {
		return uuid.Nil, err
	}
	return app.ID, nil
}
