package handlers

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strings"

	"rauth/database"
	"rauth/models"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// CreateApp creates a new application
// POST /api/v1/admin/apps
func CreateApp(c *fiber.Ctx) error {
	var req models.CreateApplicationRequest
	if err := c.BodyParser(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Invalid request body",
		})
	}

	// Validate name
	if req.Name == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Name is required",
		})
	}

	// Generate random API key
	apiKey := generateAPIKey()

	// Create application in database
	ctx := context.Background()
	var app models.Application

	query := `
		INSERT INTO applications (name, api_key, allowed_redirect_uris, cors_origins)
		VALUES ($1, $2, $3, $4)
		RETURNING id, name, api_key, allowed_redirect_uris, cors_origins, created_at, updated_at
	`

	err := database.DB.QueryRow(ctx, query,
		req.Name,
		apiKey,
		req.AllowedRedirectURIs,
		req.CORSOrigins,
	).Scan(
		&app.ID,
		&app.Name,
		&app.APIKey,
		&app.AllowedRedirectURIs,
		&app.CORSOrigins,
		&app.CreatedAt,
		&app.UpdatedAt,
	)

	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to create application",
		})
	}

	// Create OAuth providers (disabled by default)
	providersQuery := `
		INSERT INTO oauth_providers (app_id, provider, enabled)
		VALUES ($1, $2, false)
	`

	for _, provider := range models.ValidProviders() {
		_, _ = database.DB.Exec(ctx, providersQuery, app.ID, provider)
	}

	return c.Status(fiber.StatusCreated).JSON(app)
}

// ListApps lists all applications
// GET /api/v1/admin/apps
func ListApps(c *fiber.Ctx) error {
	ctx := context.Background()

	query := `
		SELECT id, name, api_key, allowed_redirect_uris, cors_origins, created_at, updated_at
		FROM applications
		ORDER BY created_at DESC
	`

	rows, err := database.DB.Query(ctx, query)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to fetch applications",
		})
	}
	defer rows.Close()

	apps := []models.Application{}
	for rows.Next() {
		var app models.Application
		err := rows.Scan(
			&app.ID,
			&app.Name,
			&app.APIKey,
			&app.AllowedRedirectURIs,
			&app.CORSOrigins,
			&app.CreatedAt,
			&app.UpdatedAt,
		)
		if err != nil {
			continue
		}
		apps = append(apps, app)
	}

	return c.JSON(apps)
}

// GetApp gets an application by ID
// GET /api/v1/admin/apps/:id
func GetApp(c *fiber.Ctx) error {
	appID, err := uuid.Parse(c.Params("id"))
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Invalid application ID",
		})
	}

	ctx := context.Background()
	var app models.Application

	query := `
		SELECT id, name, api_key, allowed_redirect_uris, cors_origins, created_at, updated_at
		FROM applications
		WHERE id = $1
	`

	err = database.DB.QueryRow(ctx, query, appID).Scan(
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
			return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
				"error": "Application not found",
			})
		}
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Database error",
		})
	}

	return c.JSON(app)
}

// UpdateApp updates an application
// PATCH /api/v1/admin/apps/:id
func UpdateApp(c *fiber.Ctx) error {
	appID, err := uuid.Parse(c.Params("id"))
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Invalid application ID",
		})
	}

	var req models.UpdateApplicationRequest
	if err := c.BodyParser(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Invalid request body",
		})
	}

	ctx := context.Background()

	// Build dynamic update query
	query := "UPDATE applications SET updated_at = NOW()"
	args := []interface{}{appID}
	argIndex := 2

	if req.Name != nil {
		query += fmt.Sprintf(", name = $%d", argIndex)
		args = append(args, *req.Name)
		argIndex++
	}

	if req.AllowedRedirectURIs != nil {
		query += fmt.Sprintf(", allowed_redirect_uris = $%d", argIndex)
		args = append(args, *req.AllowedRedirectURIs)
		argIndex++
	}

	if req.CORSOrigins != nil {
		query += fmt.Sprintf(", cors_origins = $%d", argIndex)
		args = append(args, *req.CORSOrigins)
		argIndex++
	}

	query += " WHERE id = $1 RETURNING id, name, api_key, allowed_redirect_uris, cors_origins, created_at, updated_at"

	var app models.Application
	err = database.DB.QueryRow(ctx, query, args...).Scan(
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
			return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
				"error": "Application not found",
			})
		}
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to update application",
		})
	}

	return c.JSON(app)
}

// DeleteApp deletes an application
// DELETE /api/v1/admin/apps/:id
func DeleteApp(c *fiber.Ctx) error {
	appID, err := uuid.Parse(c.Params("id"))
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Invalid application ID",
		})
	}

	ctx := context.Background()

	query := `DELETE FROM applications WHERE id = $1`
	result, err := database.DB.Exec(ctx, query, appID)

	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to delete application",
		})
	}

	if result.RowsAffected() == 0 {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
			"error": "Application not found",
		})
	}

	return c.Status(fiber.StatusNoContent).Send(nil)
}

// ListAppUsers lists users of an application
// GET /api/v1/admin/apps/:id/users
func ListAppUsers(c *fiber.Ctx) error {
	appID, err := uuid.Parse(c.Params("id"))
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Invalid application ID",
		})
	}

	ctx := context.Background()

	query := `
		SELECT id, app_id, email, name, avatar_url, email_verified, created_at, updated_at
		FROM users
		WHERE app_id = $1
		ORDER BY created_at DESC
		LIMIT 100
	`

	rows, err := database.DB.Query(ctx, query, appID)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to fetch users",
		})
	}
	defer rows.Close()

	users := []models.User{}
	for rows.Next() {
		var user models.User
		err := rows.Scan(
			&user.ID,
			&user.AppID,
			&user.Email,
			&user.Name,
			&user.AvatarURL,
			&user.EmailVerified,
			&user.CreatedAt,
			&user.UpdatedAt,
		)
		if err != nil {
			continue
		}
		users = append(users, user)
	}

	return c.JSON(users)
}

// ListOAuthProviders lists OAuth providers for an application
// GET /api/v1/admin/apps/:id/oauth
func ListOAuthProviders(c *fiber.Ctx) error {
	appID, err := uuid.Parse(c.Params("id"))
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Invalid application ID",
		})
	}

	ctx := context.Background()

	query := `
		SELECT id, app_id, provider, enabled, created_at, updated_at
		FROM oauth_providers
		WHERE app_id = $1
		ORDER BY provider
	`

	rows, err := database.DB.Query(ctx, query, appID)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to fetch providers",
		})
	}
	defer rows.Close()

	providers := []models.OAuthProvider{}
	for rows.Next() {
		var provider models.OAuthProvider
		err := rows.Scan(
			&provider.ID,
			&provider.AppID,
			&provider.Provider,
			&provider.Enabled,
			&provider.CreatedAt,
			&provider.UpdatedAt,
		)
		if err != nil {
			continue
		}
		providers = append(providers, provider)
	}

	return c.JSON(providers)
}

// ToggleOAuthProvider enables/disables an OAuth provider
// PATCH /api/v1/admin/apps/:id/oauth/:provider
func ToggleOAuthProvider(c *fiber.Ctx) error {
	appID, err := uuid.Parse(c.Params("id"))
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Invalid application ID",
		})
	}

	provider := c.Params("provider")
	if !models.IsValidProvider(provider) {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Invalid provider. Valid providers: " +
				strings.Join(models.ValidProviders(), ", "),
		})
	}

	var req struct {
		Enabled bool `json:"enabled"`
	}

	if err := c.BodyParser(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Invalid request body",
		})
	}

	ctx := context.Background()

	query := `
		UPDATE oauth_providers
		SET enabled = $1, updated_at = NOW()
		WHERE app_id = $2 AND provider = $3
		RETURNING id, app_id, provider, enabled, created_at, updated_at
	`

	var oauthProvider models.OAuthProvider
	err = database.DB.QueryRow(ctx, query, req.Enabled, appID, provider).Scan(
		&oauthProvider.ID,
		&oauthProvider.AppID,
		&oauthProvider.Provider,
		&oauthProvider.Enabled,
		&oauthProvider.CreatedAt,
		&oauthProvider.UpdatedAt,
	)

	if err != nil {
		if err == pgx.ErrNoRows {
			return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
				"error": "Provider configuration not found",
			})
		}
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to update provider",
		})
	}

	return c.JSON(oauthProvider)
}

// ============================================
// Helper functions
// ============================================

// generateAPIKey generates a random API key (64 chars hex)
func generateAPIKey() string {
	bytes := make([]byte, 32)
	rand.Read(bytes)
	return hex.EncodeToString(bytes)
}
