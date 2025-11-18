package middleware

import (
	"context"
	"encoding/json"
	"io"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"rauth/database"
	"rauth/utils"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/joho/godotenv"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var testDB *pgxpool.Pool

func setupAuthIntegrationTest(t *testing.T) {
	// Cargar variables de entorno
	_ = godotenv.Load("../.env")

	// Conectar a la base de datos de prueba
	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		t.Skip("DATABASE_URL not set, skipping integration tests")
	}

	var err error
	testDB, err = pgxpool.New(context.Background(), dbURL)
	require.NoError(t, err)

	// Asignar a la variable global del paquete database
	database.DB = testDB

	// Limpiar datos de prueba previos
	cleanupAuthTestData(t)
}

func teardownAuthIntegrationTest(t *testing.T) {
	cleanupAuthTestData(t)
	if testDB != nil {
		testDB.Close()
	}
}

func cleanupAuthTestData(t *testing.T) {
	ctx := context.Background()
	queries := []string{
		"DELETE FROM sessions WHERE app_id IN (SELECT id FROM applications WHERE name LIKE 'Auth Test App%')",
		"DELETE FROM identities WHERE user_id IN (SELECT id FROM users WHERE app_id IN (SELECT id FROM applications WHERE name LIKE 'Auth Test App%'))",
		"DELETE FROM users WHERE app_id IN (SELECT id FROM applications WHERE name LIKE 'Auth Test App%')",
		"DELETE FROM oauth_providers WHERE app_id IN (SELECT id FROM applications WHERE name LIKE 'Auth Test App%')",
		"DELETE FROM applications WHERE name LIKE 'Auth Test App%'",
	}

	for _, query := range queries {
		_, err := testDB.Exec(ctx, query)
		if err != nil {
			t.Logf("Warning: cleanup query failed: %v", err)
		}
	}
}

func createAuthTestApplication(t *testing.T) uuid.UUID {
	ctx := context.Background()
	appID := uuid.New()
	apiKey := uuid.New().String()

	query := `
		INSERT INTO applications (id, name, api_key, allowed_redirect_uris, cors_origins)
		VALUES ($1, $2, $3, $4, $5)
	`
	_, err := testDB.Exec(ctx, query,
		appID,
		"Auth Test App "+appID.String(),
		apiKey,
		[]string{"http://localhost:3000/callback"},
		[]string{"http://localhost:3000"},
	)
	require.NoError(t, err)

	return appID
}

func createAuthTestUser(t *testing.T, appID uuid.UUID) uuid.UUID {
	ctx := context.Background()
	userID := uuid.New()

	query := `
		INSERT INTO users (id, app_id, email, name)
		VALUES ($1, $2, $3, $4)
	`
	_, err := testDB.Exec(ctx, query,
		userID,
		appID,
		"authtest@example.com",
		"Auth Test User",
	)
	require.NoError(t, err)

	return userID
}

func createAuthTestSession(t *testing.T, userID, appID uuid.UUID, token string) uuid.UUID {
	ctx := context.Background()
	sessionID := uuid.New()
	tokenHash := utils.HashToken(token)
	expiresAt := time.Now().Add(24 * time.Hour)

	query := `
		INSERT INTO sessions (id, user_id, app_id, token_hash, expires_at)
		VALUES ($1, $2, $3, $4, $5)
	`
	_, err := testDB.Exec(ctx, query, sessionID, userID, appID, tokenHash, expiresAt)
	require.NoError(t, err)

	return sessionID
}

func TestRequireAuth_Integration_ValidTokenAndSession(t *testing.T) {
	setupAuthIntegrationTest(t)
	defer teardownAuthIntegrationTest(t)

	// Crear datos de prueba
	appID := createAuthTestApplication(t)
	userID := createAuthTestUser(t, appID)

	// Generar JWT
	sessionID := uuid.New()
	token, err := utils.GenerateJWT(userID, appID, sessionID, "authtest@example.com")
	require.NoError(t, err)

	// Crear sesión en DB
	createdSessionID := createAuthTestSession(t, userID, appID, token)
	assert.NotEqual(t, uuid.Nil, createdSessionID)

	// Nota: El JWT tiene un sessionID diferente al creado en DB
	// Necesitamos regenerar el JWT con el sessionID correcto
	token, err = utils.GenerateJWT(userID, appID, createdSessionID, "authtest@example.com")
	require.NoError(t, err)

	// Actualizar el token_hash en DB
	ctx := context.Background()
	tokenHash := utils.HashToken(token)
	_, err = testDB.Exec(ctx, "UPDATE sessions SET token_hash = $1 WHERE id = $2", tokenHash, createdSessionID)
	require.NoError(t, err)

	// Configurar app de prueba
	app := fiber.New()
	app.Get("/protected", RequireAuth, func(c *fiber.Ctx) error {
		claims, err := GetJWTClaims(c)
		if err != nil {
			return err
		}
		return c.JSON(fiber.Map{
			"message": "success",
			"user_id": claims.UserID.String(),
			"email":   claims.Email,
		})
	})

	// Hacer request con token válido
	req := httptest.NewRequest("GET", "/protected", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := app.Test(req, -1) // -1 = no timeout

	require.NoError(t, err)
	assert.Equal(t, fiber.StatusOK, resp.StatusCode)

	body, _ := io.ReadAll(resp.Body)
	var result map[string]interface{}
	json.Unmarshal(body, &result)

	assert.Equal(t, "success", result["message"])
	assert.Equal(t, userID.String(), result["user_id"])
	assert.Equal(t, "authtest@example.com", result["email"])
}

func TestRequireAuth_Integration_ValidToken_SessionNotFound(t *testing.T) {
	setupAuthIntegrationTest(t)
	defer teardownAuthIntegrationTest(t)

	// Crear datos de prueba
	appID := createAuthTestApplication(t)
	userID := createAuthTestUser(t, appID)

	// Generar JWT pero NO crear sesión en DB
	sessionID := uuid.New()
	token, err := utils.GenerateJWT(userID, appID, sessionID, "authtest@example.com")
	require.NoError(t, err)

	// Configurar app de prueba
	app := fiber.New()
	app.Get("/protected", RequireAuth, func(c *fiber.Ctx) error {
		return c.SendStatus(fiber.StatusOK)
	})

	// Hacer request
	req := httptest.NewRequest("GET", "/protected", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := app.Test(req, -1)

	require.NoError(t, err)
	assert.Equal(t, fiber.StatusUnauthorized, resp.StatusCode)

	body, _ := io.ReadAll(resp.Body)
	var result map[string]interface{}
	json.Unmarshal(body, &result)

	assert.Equal(t, "Session not found or expired", result["error"])
}

func TestRequireAuth_Integration_ValidToken_ExpiredSession(t *testing.T) {
	setupAuthIntegrationTest(t)
	defer teardownAuthIntegrationTest(t)

	// Crear datos de prueba
	appID := createAuthTestApplication(t)
	userID := createAuthTestUser(t, appID)

	// Generar JWT con expiración más larga (el JWT en sí debe ser válido)
	sessionID := uuid.New()
	token, err := utils.GenerateJWT(userID, appID, sessionID, "authtest@example.com")
	require.NoError(t, err)

	// Crear sesión EXPIRADA en DB (aunque el JWT sea válido)
	ctx := context.Background()
	tokenHash := utils.HashToken(token)
	expiredAt := time.Now().Add(-1 * time.Hour) // Expirada hace 1 hora

	query := `
		INSERT INTO sessions (id, user_id, app_id, token_hash, expires_at)
		VALUES ($1, $2, $3, $4, $5)
	`
	_, err = testDB.Exec(ctx, query, sessionID, userID, appID, tokenHash, expiredAt)
	require.NoError(t, err)

	// Configurar app de prueba
	app := fiber.New()
	app.Get("/protected", RequireAuth, func(c *fiber.Ctx) error {
		return c.SendStatus(fiber.StatusOK)
	})

	// Hacer request - debe fallar porque expires_at > NOW() en la query
	req := httptest.NewRequest("GET", "/protected", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := app.Test(req, -1)

	require.NoError(t, err)

	// Si el token es rechazado porque la sesión expiró
	if resp.StatusCode == fiber.StatusUnauthorized {
		body, _ := io.ReadAll(resp.Body)
		var result map[string]interface{}
		json.Unmarshal(body, &result)
		assert.Equal(t, "Session not found or expired", result["error"])
	} else {
		// Si el JWT en sí ha expirado (también válido)
		assert.Equal(t, fiber.StatusUnauthorized, resp.StatusCode)
	}
}

func TestRequireAuth_Integration_ValidToken_WrongTokenHash(t *testing.T) {
	setupAuthIntegrationTest(t)
	defer teardownAuthIntegrationTest(t)

	// Crear datos de prueba
	appID := createAuthTestApplication(t)
	userID := createAuthTestUser(t, appID)

	// Generar JWT
	sessionID := uuid.New()
	token, err := utils.GenerateJWT(userID, appID, sessionID, "authtest@example.com")
	require.NoError(t, err)

	// Crear sesión con token_hash DIFERENTE
	ctx := context.Background()
	wrongTokenHash := utils.HashToken("different-token")
	expiresAt := time.Now().Add(24 * time.Hour)

	query := `
		INSERT INTO sessions (id, user_id, app_id, token_hash, expires_at)
		VALUES ($1, $2, $3, $4, $5)
	`
	_, err = testDB.Exec(ctx, query, sessionID, userID, appID, wrongTokenHash, expiresAt)
	require.NoError(t, err)

	// Configurar app de prueba
	app := fiber.New()
	app.Get("/protected", RequireAuth, func(c *fiber.Ctx) error {
		return c.SendStatus(fiber.StatusOK)
	})

	// Hacer request
	req := httptest.NewRequest("GET", "/protected", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := app.Test(req, -1)

	require.NoError(t, err)
	assert.Equal(t, fiber.StatusUnauthorized, resp.StatusCode)

	body, _ := io.ReadAll(resp.Body)
	var result map[string]interface{}
	json.Unmarshal(body, &result)

	assert.Equal(t, "Session not found or expired", result["error"])
}

func TestRequireAuth_Integration_SessionLastUsedAtUpdate(t *testing.T) {
	setupAuthIntegrationTest(t)
	defer teardownAuthIntegrationTest(t)

	// Crear datos de prueba
	appID := createAuthTestApplication(t)
	userID := createAuthTestUser(t, appID)

	// Generar JWT y crear sesión manualmente con token_hash correcto
	ctx := context.Background()
	sessionID := uuid.New()
	token, err := utils.GenerateJWT(userID, appID, sessionID, "authtest@example.com")
	require.NoError(t, err)

	tokenHash := utils.HashToken(token)
	expiresAt := time.Now().Add(24 * time.Hour)

	// Crear sesión con token_hash correcto desde el inicio
	query := `
		INSERT INTO sessions (id, user_id, app_id, token_hash, expires_at)
		VALUES ($1, $2, $3, $4, $5)
	`
	_, err = testDB.Exec(ctx, query, sessionID, userID, appID, tokenHash, expiresAt)
	require.NoError(t, err)

	// Obtener last_used_at inicial (debería ser NULL)
	var initialLastUsed *time.Time
	err = testDB.QueryRow(ctx, "SELECT last_used_at FROM sessions WHERE id = $1", sessionID).Scan(&initialLastUsed)
	require.NoError(t, err)

	// Esperar un segundo para asegurar que el timestamp sea diferente
	time.Sleep(1 * time.Second)

	// Configurar app y hacer request
	app := fiber.New()
	app.Get("/protected", RequireAuth, func(c *fiber.Ctx) error {
		return c.SendStatus(fiber.StatusOK)
	})

	req := httptest.NewRequest("GET", "/protected", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := app.Test(req, -1)

	require.NoError(t, err)
	assert.Equal(t, fiber.StatusOK, resp.StatusCode)

	// Verificar que last_used_at se actualizó
	var updatedLastUsed time.Time
	err = testDB.QueryRow(ctx, "SELECT last_used_at FROM sessions WHERE id = $1", sessionID).Scan(&updatedLastUsed)
	require.NoError(t, err)

	// Verificar que el timestamp se actualizó
	if initialLastUsed != nil {
		assert.True(t, updatedLastUsed.After(*initialLastUsed), "last_used_at should be updated")
	} else {
		assert.False(t, updatedLastUsed.IsZero(), "last_used_at should be set")
	}
}

func TestGetJWTClaims_Integration_WithRealMiddleware(t *testing.T) {
	setupAuthIntegrationTest(t)
	defer teardownAuthIntegrationTest(t)

	// Crear datos de prueba
	appID := createAuthTestApplication(t)
	userID := createAuthTestUser(t, appID)

	// Generar JWT y crear sesión manualmente con token_hash correcto
	ctx := context.Background()
	sessionID := uuid.New()
	token, err := utils.GenerateJWT(userID, appID, sessionID, "authtest@example.com")
	require.NoError(t, err)

	tokenHash := utils.HashToken(token)
	expiresAt := time.Now().Add(24 * time.Hour)

	// Crear sesión con token_hash correcto desde el inicio
	query := `
		INSERT INTO sessions (id, user_id, app_id, token_hash, expires_at)
		VALUES ($1, $2, $3, $4, $5)
	`
	_, err = testDB.Exec(ctx, query, sessionID, userID, appID, tokenHash, expiresAt)
	require.NoError(t, err)

	// Configurar app que usa GetJWTClaims
	app := fiber.New()
	app.Get("/user-info", RequireAuth, func(c *fiber.Ctx) error {
		claims, err := GetJWTClaims(c)
		if err != nil {
			return err
		}

		return c.JSON(fiber.Map{
			"user_id":    claims.UserID.String(),
			"app_id":     claims.AppID.String(),
			"session_id": claims.SessionID.String(),
			"email":      claims.Email,
		})
	})

	// Hacer request
	req := httptest.NewRequest("GET", "/user-info", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := app.Test(req, -1)

	require.NoError(t, err)
	assert.Equal(t, fiber.StatusOK, resp.StatusCode)

	body, _ := io.ReadAll(resp.Body)
	var result map[string]interface{}
	json.Unmarshal(body, &result)

	assert.Equal(t, userID.String(), result["user_id"])
	assert.Equal(t, appID.String(), result["app_id"])
	assert.Equal(t, sessionID.String(), result["session_id"])
	assert.Equal(t, "authtest@example.com", result["email"])
}

func TestGetSession_Integration_WithRealMiddleware(t *testing.T) {
	setupAuthIntegrationTest(t)
	defer teardownAuthIntegrationTest(t)

	// Crear datos de prueba
	appID := createAuthTestApplication(t)
	userID := createAuthTestUser(t, appID)

	// Generar JWT y crear sesión manualmente con token_hash correcto
	ctx := context.Background()
	sessionID := uuid.New()
	token, err := utils.GenerateJWT(userID, appID, sessionID, "authtest@example.com")
	require.NoError(t, err)

	tokenHash := utils.HashToken(token)
	expiresAt := time.Now().Add(24 * time.Hour)

	// Crear sesión con token_hash correcto desde el inicio
	query := `
		INSERT INTO sessions (id, user_id, app_id, token_hash, expires_at)
		VALUES ($1, $2, $3, $4, $5)
	`
	_, err = testDB.Exec(ctx, query, sessionID, userID, appID, tokenHash, expiresAt)
	require.NoError(t, err)

	// Configurar app que usa GetSession
	app := fiber.New()
	app.Get("/session-info", RequireAuth, func(c *fiber.Ctx) error {
		session, err := GetSession(c)
		if err != nil {
			return err
		}

		return c.JSON(fiber.Map{
			"session_id": session.ID.String(),
			"user_id":    session.UserID.String(),
			"app_id":     session.AppID.String(),
		})
	})

	// Hacer request
	req := httptest.NewRequest("GET", "/session-info", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := app.Test(req, -1)

	require.NoError(t, err)
	assert.Equal(t, fiber.StatusOK, resp.StatusCode)

	body, _ := io.ReadAll(resp.Body)
	var result map[string]interface{}
	json.Unmarshal(body, &result)

	assert.Equal(t, sessionID.String(), result["session_id"])
	assert.Equal(t, userID.String(), result["user_id"])
	assert.Equal(t, appID.String(), result["app_id"])
}
