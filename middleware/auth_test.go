package middleware

import (
	"encoding/json"
	"io"
	"net/http/httptest"
	"testing"
	"time"

	"rauth/models"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockDBForAuthTests simula la base de datos para tests de autenticación
var mockSessionsDB map[string]models.Session

func setupAuthTestApp() *fiber.App {
	app := fiber.New()

	// Ruta protegida con middleware
	app.Get("/protected", RequireAuth, func(c *fiber.Ctx) error {
		claims, err := GetJWTClaims(c)
		if err != nil {
			return err
		}
		return c.JSON(fiber.Map{
			"message": "success",
			"user_id": claims.UserID.String(),
		})
	})

	// Ruta para obtener sesión
	app.Get("/session", RequireAuth, func(c *fiber.Ctx) error {
		session, err := GetSession(c)
		if err != nil {
			return err
		}
		return c.JSON(fiber.Map{
			"session_id": session.ID.String(),
			"user_id":    session.UserID.String(),
		})
	})

	return app
}

func TestRequireAuth_MissingAuthorizationHeader(t *testing.T) {
	app := setupAuthTestApp()

	req := httptest.NewRequest("GET", "/protected", nil)
	resp, err := app.Test(req)

	require.NoError(t, err)
	assert.Equal(t, fiber.StatusUnauthorized, resp.StatusCode)

	body, _ := io.ReadAll(resp.Body)
	var result map[string]interface{}
	json.Unmarshal(body, &result)

	assert.Equal(t, "Authorization header required", result["error"])
}

func TestRequireAuth_InvalidAuthorizationFormat(t *testing.T) {
	app := setupAuthTestApp()

	testCases := []struct {
		name   string
		header string
	}{
		{"missing Bearer prefix", "some-token"},
		{"wrong prefix", "Basic some-token"},
		{"extra spaces", "Bearer  token with spaces"},
		{"empty bearer", "Bearer "},
		{"only Bearer", "Bearer"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/protected", nil)
			req.Header.Set("Authorization", tc.header)
			resp, err := app.Test(req)

			require.NoError(t, err)
			assert.Equal(t, fiber.StatusUnauthorized, resp.StatusCode)

			body, _ := io.ReadAll(resp.Body)
			var result map[string]interface{}
			json.Unmarshal(body, &result)

			assert.Contains(t, result["error"], "Invalid authorization format")
		})
	}
}

func TestRequireAuth_InvalidJWTToken(t *testing.T) {
	app := setupAuthTestApp()

	testCases := []struct {
		name          string
		token         string
		expectedError string
	}{
		{"malformed token", "invalid.token.here", "Invalid or expired token"},
		{"random string", "random-string-not-jwt", "Invalid or expired token"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/protected", nil)
			req.Header.Set("Authorization", "Bearer "+tc.token)
			resp, err := app.Test(req)

			require.NoError(t, err)
			assert.Equal(t, fiber.StatusUnauthorized, resp.StatusCode)

			body, _ := io.ReadAll(resp.Body)
			var result map[string]interface{}
			json.Unmarshal(body, &result)

			assert.Equal(t, tc.expectedError, result["error"])
		})
	}
}

func TestRequireAuth_ValidToken_SessionNotFound(t *testing.T) {
	// Este test requiere integración con DB
	// Se implementará en auth_integration_test.go
	t.Skip("Requires database integration - see auth_integration_test.go")
}

func TestGetJWTClaims_Success(t *testing.T) {
	app := fiber.New()

	userID := uuid.New()
	appID := uuid.New()
	sessionID := uuid.New()

	app.Get("/test", func(c *fiber.Ctx) error {
		// Simular que el middleware ya guardó los claims
		claims := &models.JWTClaims{
			UserID:    userID,
			AppID:     appID,
			SessionID: sessionID,
			Email:     "test@example.com",
			IssuedAt:  time.Now().Unix(),
			ExpiresAt: time.Now().Add(24 * time.Hour).Unix(),
		}
		c.Locals("jwt_claims", claims)

		// Probar la función
		retrievedClaims, err := GetJWTClaims(c)
		require.NoError(t, err)
		assert.Equal(t, userID, retrievedClaims.UserID)
		assert.Equal(t, appID, retrievedClaims.AppID)
		assert.Equal(t, sessionID, retrievedClaims.SessionID)
		assert.Equal(t, "test@example.com", retrievedClaims.Email)

		return c.SendStatus(fiber.StatusOK)
	})

	req := httptest.NewRequest("GET", "/test", nil)
	resp, err := app.Test(req)

	require.NoError(t, err)
	assert.Equal(t, fiber.StatusOK, resp.StatusCode)
}

func TestGetJWTClaims_NoClaimsInContext(t *testing.T) {
	app := fiber.New()

	app.Get("/test", func(c *fiber.Ctx) error {
		_, err := GetJWTClaims(c)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "No JWT claims in context")
		return err
	})

	req := httptest.NewRequest("GET", "/test", nil)
	resp, err := app.Test(req)

	require.NoError(t, err)
	assert.Equal(t, fiber.StatusUnauthorized, resp.StatusCode)
}

func TestGetJWTClaims_InvalidClaimsType(t *testing.T) {
	app := fiber.New()

	app.Get("/test", func(c *fiber.Ctx) error {
		// Guardar un tipo incorrecto en el contexto
		c.Locals("jwt_claims", "invalid-type")

		_, err := GetJWTClaims(c)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "Invalid JWT claims in context")
		return err
	})

	req := httptest.NewRequest("GET", "/test", nil)
	resp, err := app.Test(req)

	require.NoError(t, err)
	assert.Equal(t, fiber.StatusInternalServerError, resp.StatusCode)
}

func TestGetSession_Success(t *testing.T) {
	app := fiber.New()

	sessionID := uuid.New()
	userID := uuid.New()
	appID := uuid.New()

	app.Get("/test", func(c *fiber.Ctx) error {
		// Simular que el middleware ya guardó la sesión
		session := models.Session{
			ID:        sessionID,
			UserID:    userID,
			AppID:     appID,
			ExpiresAt: time.Now().Add(24 * time.Hour),
			CreatedAt: time.Now(),
		}
		c.Locals("session", session)

		// Probar la función
		retrievedSession, err := GetSession(c)
		require.NoError(t, err)
		assert.Equal(t, sessionID, retrievedSession.ID)
		assert.Equal(t, userID, retrievedSession.UserID)
		assert.Equal(t, appID, retrievedSession.AppID)

		return c.SendStatus(fiber.StatusOK)
	})

	req := httptest.NewRequest("GET", "/test", nil)
	resp, err := app.Test(req)

	require.NoError(t, err)
	assert.Equal(t, fiber.StatusOK, resp.StatusCode)
}

func TestGetSession_NoSessionInContext(t *testing.T) {
	app := fiber.New()

	app.Get("/test", func(c *fiber.Ctx) error {
		_, err := GetSession(c)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "No session in context")
		return err
	})

	req := httptest.NewRequest("GET", "/test", nil)
	resp, err := app.Test(req)

	require.NoError(t, err)
	assert.Equal(t, fiber.StatusUnauthorized, resp.StatusCode)
}

func TestGetSession_InvalidSessionType(t *testing.T) {
	app := fiber.New()

	app.Get("/test", func(c *fiber.Ctx) error {
		// Guardar un tipo incorrecto en el contexto
		c.Locals("session", "invalid-type")

		_, err := GetSession(c)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "Invalid session in context")
		return err
	})

	req := httptest.NewRequest("GET", "/test", nil)
	resp, err := app.Test(req)

	require.NoError(t, err)
	assert.Equal(t, fiber.StatusInternalServerError, resp.StatusCode)
}



func TestRequireAuth_Integration_EndToEnd(t *testing.T) {
	// Este test requiere configuración completa de DB
	// Se implementará en auth_integration_test.go
	t.Skip("Requires full database setup - see auth_integration_test.go")
}
