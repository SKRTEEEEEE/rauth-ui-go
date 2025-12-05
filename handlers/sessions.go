package handlers

import (
	"context"

	"rauth/database"
	"rauth/middleware"
	"rauth/models"
	"rauth/utils"

	"github.com/gofiber/fiber/v2"
)

// ValidateSession valida si un token es válido
// POST /api/v1/sessions/validate
func ValidateSession(c *fiber.Ctx) error {
	// El middleware RequireAuth ya validó el token
	claims, err := middleware.GetJWTClaims(c)
	if err != nil {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"error": "Unauthorized",
		})
	}

	session, err := middleware.GetSession(c)
	if err != nil {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"error": "Session not found",
		})
	}

	return c.JSON(fiber.Map{
		"valid":      true,
		"user_id":    claims.UserID,
		"session_id": session.ID,
		"expires_at": session.ExpiresAt,
	})
}

// RefreshSession refresca el token JWT
// POST /api/v1/sessions/refresh
func RefreshSession(c *fiber.Ctx) error {
	claims, err := middleware.GetJWTClaims(c)
	if err != nil {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"error": "Unauthorized",
		})
	}

	// Generar nuevo JWT con misma sesión
	newToken, err := utils.GenerateJWT(claims.UserID, claims.AppID, claims.SessionID, claims.Email)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to refresh token",
		})
	}

	// Actualizar token_hash en sesión
	ctx := context.Background()
	tokenHash := utils.HashToken(newToken)

	query := `UPDATE sessions SET token_hash = $1, last_used_at = NOW() WHERE id = $2`
	result, err := database.DB.Exec(ctx, query, tokenHash, claims.SessionID)

	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to update session",
		})
	}

	// Check if any rows were affected
	rowsAffected := result.RowsAffected()
	if rowsAffected == 0 {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
			"error": "Session not found",
		})
	}

	return c.JSON(fiber.Map{
		"token": newToken,
	})
}

// LogoutSession cierra la sesión actual
// DELETE /api/v1/sessions/current
func LogoutSession(c *fiber.Ctx) error {
	claims, err := middleware.GetJWTClaims(c)
	if err != nil {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"error": "Unauthorized",
		})
	}

	ctx := context.Background()
	query := `DELETE FROM sessions WHERE id = $1`
	_, err = database.DB.Exec(ctx, query, claims.SessionID)

	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to logout",
		})
	}

	return c.Status(fiber.StatusNoContent).Send(nil)
}

// ListMySessions lista todas las sesiones del usuario
// GET /api/v1/sessions
func ListMySessions(c *fiber.Ctx) error {
	claims, err := middleware.GetJWTClaims(c)
	if err != nil {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"error": "Unauthorized",
		})
	}

	ctx := context.Background()
	query := `
		SELECT id, user_id, app_id, ip_address, user_agent, expires_at, created_at, last_used_at
		FROM sessions
		WHERE user_id = $1 AND expires_at > NOW()
		ORDER BY last_used_at DESC
	`

	rows, err := database.DB.Query(ctx, query, claims.UserID)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to fetch sessions",
		})
	}
	defer rows.Close()

	sessions := []models.Session{}
	for rows.Next() {
		var session models.Session
		err := rows.Scan(
			&session.ID,
			&session.UserID,
			&session.AppID,
			&session.IPAddress,
			&session.UserAgent,
			&session.ExpiresAt,
			&session.CreatedAt,
			&session.LastUsedAt,
		)
		if err != nil {
			continue
		}
		sessions = append(sessions, session)
	}

	return c.JSON(sessions)
}
