package handlers

import (
	"context"
	"fmt"

	"rauth/database"
	"rauth/middleware"
	"rauth/models"

	"github.com/gofiber/fiber/v2"
	"github.com/jackc/pgx/v5"
)

// GetMe obtiene el perfil del usuario actual
// GET /api/v1/users/me
func GetMe(c *fiber.Ctx) error {
	claims, err := middleware.GetJWTClaims(c)
	if err != nil {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"error": "Unauthorized",
		})
	}

	ctx := context.Background()
	var user models.User

	query := `
		SELECT id, app_id, email, name, avatar_url, email_verified, created_at, updated_at
		FROM users
		WHERE id = $1
	`

	err = database.DB.QueryRow(ctx, query, claims.UserID).Scan(
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
		if err == pgx.ErrNoRows {
			return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
				"error": "User not found",
			})
		}
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Database error",
		})
	}

	// Obtener identidades del usuario
	identitiesQuery := `
		SELECT id, user_id, provider, provider_email, created_at
		FROM identities
		WHERE user_id = $1
		ORDER BY created_at ASC
	`

	rows, err := database.DB.Query(ctx, identitiesQuery, claims.UserID)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to fetch identities",
		})
	}
	defer rows.Close()

	identities := []models.Identity{}
	for rows.Next() {
		var identity models.Identity
		err := rows.Scan(
			&identity.ID,
			&identity.UserID,
			&identity.Provider,
			&identity.ProviderEmail,
			&identity.CreatedAt,
		)
		if err != nil {
			continue
		}
		identities = append(identities, identity)
	}

	return c.JSON(fiber.Map{
		"user":       user,
		"identities": identities,
	})
}

// UpdateMe actualiza el perfil del usuario actual
// PATCH /api/v1/users/me
func UpdateMe(c *fiber.Ctx) error {
	claims, err := middleware.GetJWTClaims(c)
	if err != nil {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"error": "Unauthorized",
		})
	}

	var req models.UpdateUserRequest
	if err := c.BodyParser(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Invalid request body",
		})
	}

	ctx := context.Background()

	// Construir query dinámica para actualizar solo los campos proporcionados
	query := `UPDATE users SET updated_at = NOW()`
	args := []interface{}{claims.UserID}
	argIndex := 2

	if req.Name != nil {
		query += fmt.Sprintf(`, name = $%d`, argIndex)
		args = append(args, *req.Name)
		argIndex++
	}

	if req.Email != nil {
		query += fmt.Sprintf(`, email = $%d`, argIndex)
		args = append(args, *req.Email)
		argIndex++
	}

	if req.AvatarURL != nil {
		query += fmt.Sprintf(`, avatar_url = $%d`, argIndex)
		args = append(args, *req.AvatarURL)
		argIndex++
	}

	query += ` WHERE id = $1 RETURNING id, app_id, email, name, avatar_url, email_verified, created_at, updated_at`

	var user models.User
	err = database.DB.QueryRow(ctx, query, args...).Scan(
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
		if err == pgx.ErrNoRows {
			return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
				"error": "User not found",
			})
		}
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to update user",
		})
	}

	return c.JSON(user)
}

// DeleteMe elimina la cuenta del usuario actual
// DELETE /api/v1/users/me
func DeleteMe(c *fiber.Ctx) error {
	claims, err := middleware.GetJWTClaims(c)
	if err != nil {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"error": "Unauthorized",
		})
	}

	ctx := context.Background()

	// Eliminar usuario (las sesiones e identidades se eliminan en cascada)
	query := `DELETE FROM users WHERE id = $1`
	result, err := database.DB.Exec(ctx, query, claims.UserID)

	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to delete user",
		})
	}

	if result.RowsAffected() == 0 {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
			"error": "User not found",
		})
	}

	return c.Status(fiber.StatusNoContent).Send(nil)
}
