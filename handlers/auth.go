package handlers

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"time"

	"rauth/database"
	"rauth/models"
	"rauth/oauth"
	"rauth/utils"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// OAuthAuthorize inicia el flujo OAuth
// GET /api/v1/oauth/authorize?provider=google&app_id=xxx&redirect_uri=xxx
func OAuthAuthorize(c *fiber.Ctx) error {
	provider := c.Query("provider")
	appIDStr := c.Query("app_id")
	redirectURI := c.Query("redirect_uri")

	// Validar parámetros
	if provider == "" || appIDStr == "" || redirectURI == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Missing required parameters: provider, app_id, redirect_uri",
		})
	}

	// Validar provider
	if !models.IsValidProvider(provider) {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Invalid provider",
		})
	}

	// Parsear app_id
	appID, err := uuid.Parse(appIDStr)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Invalid app_id",
		})
	}

	ctx := context.Background()

	// Verificar que la app existe y el provider está habilitado
	var enabled bool
	query := `
		SELECT enabled FROM oauth_providers
		WHERE app_id = $1 AND provider = $2
	`
	err = database.DB.QueryRow(ctx, query, appID, provider).Scan(&enabled)
	if err != nil {
		if err == pgx.ErrNoRows {
			return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
				"error": "Application or provider not found",
			})
		}
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Database error",
		})
	}

	if !enabled {
		return c.Status(fiber.StatusForbidden).JSON(fiber.Map{
			"error": fmt.Sprintf("%s OAuth is not enabled for this application", provider),
		})
	}

	// Generar state token aleatorio
	stateToken := generateStateToken()

	// Guardar state en Redis (5 min TTL)
	stateData := models.OAuthState{
		AppID:       appID,
		RedirectURI: redirectURI,
		CreatedAt:   time.Now(),
	}

	if err := database.SaveOAuthState(ctx, stateToken, stateData); err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to save OAuth state",
		})
	}

	// Construir callback URI
	platformURL := os.Getenv("PLATFORM_URL")
	if platformURL == "" {
		platformURL = "http://localhost:8080"
	}
	callbackURI := fmt.Sprintf("%s/api/v1/oauth/callback/%s", platformURL, provider)

	// Construir URL de autorización según el provider
	var authURL string
	switch provider {
	case models.ProviderGoogle:
		authURL = oauth.BuildGoogleAuthURL(stateToken, callbackURI)
	case models.ProviderGitHub:
		authURL = oauth.BuildGitHubAuthURL(stateToken, callbackURI)
	default:
		return c.Status(fiber.StatusNotImplemented).JSON(fiber.Map{
			"error": "Provider not implemented yet",
		})
	}

	// Redirigir al usuario al provider
	return c.Redirect(authURL, fiber.StatusTemporaryRedirect)
}

// OAuthCallback procesa el callback del proveedor OAuth
// GET /api/v1/oauth/callback/:provider?code=xxx&state=xxx
func OAuthCallback(c *fiber.Ctx) error {
	provider := c.Params("provider")
	code := c.Query("code")
	state := c.Query("state")

	// Validar parámetros
	if code == "" || state == "" {
		return c.Status(fiber.StatusBadRequest).SendString("Missing code or state")
	}

	ctx := context.Background()

	// Recuperar y validar state de Redis
	var stateData models.OAuthState
	if err := database.GetOAuthState(ctx, state, &stateData); err != nil {
		return c.Status(fiber.StatusBadRequest).SendString("Invalid or expired state")
	}

	// Construir callback URI
	platformURL := os.Getenv("PLATFORM_URL")
	if platformURL == "" {
		platformURL = "http://localhost:8080"
	}
	callbackURI := fmt.Sprintf("%s/api/v1/oauth/callback/%s", platformURL, provider)

	// Intercambiar code por access token según provider
	var accessToken, refreshToken string
	var userInfo *models.OAuthUserInfo
	var err error

	switch provider {
	case models.ProviderGoogle:
		accessToken, refreshToken, err = oauth.ExchangeGoogleCode(code, callbackURI)
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).SendString("Failed to exchange code: " + err.Error())
		}

		userInfo, err = oauth.GetGoogleUserInfo(accessToken)
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).SendString("Failed to get user info: " + err.Error())
		}
	case models.ProviderGitHub:
		accessToken, refreshToken, err = oauth.ExchangeGitHubCode(code, callbackURI)
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).SendString("Failed to exchange code: " + err.Error())
		}

		userInfo, err = oauth.GetGitHubUserInfo(accessToken)
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).SendString("Failed to get user info: " + err.Error())
		}
	default:
		return c.Status(fiber.StatusNotImplemented).SendString("Provider not implemented")
	}

	// Encontrar o crear usuario e identidad
	userID, err := findOrCreateUser(ctx, stateData.AppID, provider, userInfo, accessToken, refreshToken)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).SendString("Failed to create user: " + err.Error())
	}

	// Crear sesión
	sessionID := uuid.New()
	expiresAt := time.Now().Add(24 * time.Hour)

	// Generar JWT
	jwtToken, err := utils.GenerateJWT(userID, stateData.AppID, sessionID, userInfo.Email)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).SendString("Failed to generate token")
	}

	tokenHash := utils.HashToken(jwtToken)

	// Guardar sesión en DB
	sessionQuery := `
		INSERT INTO sessions (id, user_id, app_id, token_hash, ip_address, user_agent, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
	`
	_, err = database.DB.Exec(ctx, sessionQuery,
		sessionID,
		userID,
		stateData.AppID,
		tokenHash,
		c.IP(),
		c.Get("User-Agent"),
		expiresAt,
	)

	if err != nil {
		return c.Status(fiber.StatusInternalServerError).SendString("Failed to create session")
	}

	// Redirigir al cliente con el token
	redirectURL := fmt.Sprintf("%s?token=%s", stateData.RedirectURI, jwtToken)
	return c.Redirect(redirectURL, fiber.StatusTemporaryRedirect)
}

// ============================================
// Helper functions
// ============================================

func generateStateToken() string {
	bytes := make([]byte, 32)
	rand.Read(bytes)
	return hex.EncodeToString(bytes)
}

func findOrCreateUser(ctx context.Context, appID uuid.UUID, provider string, userInfo *models.OAuthUserInfo, accessToken, refreshToken string) (uuid.UUID, error) {
	// Buscar identidad existente
	var userID uuid.UUID
	query := `
		SELECT user_id FROM identities
		WHERE provider = $1 AND provider_user_id = $2
	`
	err := database.DB.QueryRow(ctx, query, provider, userInfo.ProviderUserID).Scan(&userID)

	if err == nil {
		// Usuario ya existe, actualizar tokens
		updateQuery := `
			UPDATE identities
			SET access_token = $1, refresh_token = $2, updated_at = NOW()
			WHERE provider = $3 AND provider_user_id = $4
		`
		_, _ = database.DB.Exec(ctx, updateQuery, accessToken, refreshToken, provider, userInfo.ProviderUserID)
		return userID, nil
	}

	if err != pgx.ErrNoRows {
		return uuid.Nil, err
	}

	// Usuario no existe, crear nuevo
	userID = uuid.New()

	// Crear usuario
	userQuery := `
		INSERT INTO users (id, app_id, email, name, avatar_url, email_verified)
		VALUES ($1, $2, $3, $4, $5, $6)
	`
	_, err = database.DB.Exec(ctx, userQuery,
		userID,
		appID,
		userInfo.Email,
		userInfo.Name,
		userInfo.AvatarURL,
		userInfo.EmailVerified,
	)

	if err != nil {
		return uuid.Nil, err
	}

	// Crear identidad
	identityQuery := `
		INSERT INTO identities (user_id, provider, provider_user_id, provider_email, access_token, refresh_token)
		VALUES ($1, $2, $3, $4, $5, $6)
	`
	_, err = database.DB.Exec(ctx, identityQuery,
		userID,
		provider,
		userInfo.ProviderUserID,
		userInfo.Email,
		accessToken,
		refreshToken,
	)

	return userID, err
}
