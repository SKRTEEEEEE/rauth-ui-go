package middleware

import (
	"context"
	"strings"

	"rauth/database"
	"rauth/models"
	"rauth/utils"

	"github.com/gofiber/fiber/v2"
	"github.com/jackc/pgx/v5"
)

// RequireAuth valida JWT y carga usuario en contexto
func RequireAuth(c *fiber.Ctx) error {
	// Obtener token del header Authorization
	authHeader := c.Get("Authorization")
	if authHeader == "" {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"error": "Authorization header required",
		})
	}

	// Extraer token (formato: "Bearer <token>")
	parts := strings.Split(authHeader, " ")
	if len(parts) != 2 || parts[0] != "Bearer" {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"error": "Invalid authorization format. Use: Bearer <token>",
		})
	}

	tokenString := parts[1]

	// Validar JWT
	claims, err := utils.ValidateJWT(tokenString)
	if err != nil {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"error": "Invalid or expired token",
		})
	}

	// Verificar que la sesión existe en DB
	ctx := context.Background()
	tokenHash := utils.HashToken(tokenString)

	var session models.Session
	query := `
		SELECT id, user_id, app_id, expires_at
		FROM sessions
		WHERE id = $1 AND token_hash = $2 AND expires_at > NOW()
	`

	err = database.DB.QueryRow(ctx, query, claims.SessionID, tokenHash).Scan(
		&session.ID,
		&session.UserID,
		&session.AppID,
		&session.ExpiresAt,
	)

	if err != nil {
		if err == pgx.ErrNoRows {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error": "Session not found or expired",
			})
		}
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Database error",
		})
	}

	// Actualizar last_used_at
	_, _ = database.DB.Exec(ctx, `UPDATE sessions SET last_used_at = NOW() WHERE id = $1`, session.ID)

	// Guardar claims y session en contexto
	c.Locals("jwt_claims", claims)
	c.Locals("session", session)

	return c.Next()
}

// GetJWTClaims obtiene los claims del JWT del contexto
func GetJWTClaims(c *fiber.Ctx) (*models.JWTClaims, error) {
	claims := c.Locals("jwt_claims")
	if claims == nil {
		return nil, fiber.NewError(fiber.StatusUnauthorized, "No JWT claims in context")
	}

	jwtClaims, ok := claims.(*models.JWTClaims)
	if !ok {
		return nil, fiber.NewError(fiber.StatusInternalServerError, "Invalid JWT claims in context")
	}

	return jwtClaims, nil
}

// GetSession obtiene la sesión del contexto
func GetSession(c *fiber.Ctx) (*models.Session, error) {
	session := c.Locals("session")
	if session == nil {
		return nil, fiber.NewError(fiber.StatusUnauthorized, "No session in context")
	}

	sess, ok := session.(models.Session)
	if !ok {
		return nil, fiber.NewError(fiber.StatusInternalServerError, "Invalid session in context")
	}

	return &sess, nil
}
