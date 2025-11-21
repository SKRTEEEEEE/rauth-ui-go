package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"testing"
	"time"

	"rauth/database"
	"rauth/models"
	"rauth/oauth"

	"github.com/alicebob/miniredis/v2"
	"github.com/google/uuid"
	"github.com/pashagolub/pgxmock/v3"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/require"
)

type stubOAuthProvider struct {
	authURL      string
	accessToken  string
	refreshToken string
	userInfo     *models.OAuthUserInfo

	lastState    string
	lastRedirect string
	lastCode     string
	lastCallback string
	lastToken    string
}

func newStubOAuthProvider() *stubOAuthProvider {
	return &stubOAuthProvider{
		authURL:     "https://stub.example/authorize",
		accessToken: "stub-access-token",
		refreshToken:"stub-refresh-token",
		userInfo: &models.OAuthUserInfo{
			ProviderUserID: "stub-user",
			Email:          "stub@example.com",
			Name:           "Stub User",
			AvatarURL:      "https://stub.example/avatar.png",
			EmailVerified:  true,
		},
	}
}

func (s *stubOAuthProvider) BuildAuthURL(state, redirectURI string) string {
	s.lastState = state
	s.lastRedirect = redirectURI
	return s.authURL
}

func (s *stubOAuthProvider) ExchangeCode(code, redirectURI string) (string, string, error) {
	s.lastCode = code
	s.lastCallback = redirectURI
	return s.accessToken, s.refreshToken, nil
}

func (s *stubOAuthProvider) GetUserInfo(accessToken string) (*models.OAuthUserInfo, error) {
	s.lastToken = accessToken
	return s.userInfo, nil
}

func setupMockPool(t *testing.T) pgxmock.PgxPoolIface {
	mockPool, err := pgxmock.NewPool()
	require.NoError(t, err)
	database.DB = mockPool
	t.Cleanup(func() {
		mockPool.Close()
		database.DB = nil
	})
	return mockPool
}

func setupTestRedis(t *testing.T) *miniredis.Miniredis {
	server := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: server.Addr()})
	database.RedisClient = client
	t.Cleanup(func() {
		client.Close()
		database.RedisClient = nil
		server.Close()
	})
	return server
}

func overrideProvider(t *testing.T, name string, provider oauth.OAuthProvider) {
	original, ok := oauth.GetProvider(name)
	oauth.RegisterProvider(name, provider)
	t.Cleanup(func() {
		if ok {
			oauth.RegisterProvider(name, original)
		}
	})
}

func TestOAuthAuthorize_UsesRegisteredProvider(t *testing.T) {
	t.Setenv("PLATFORM_URL", "https://platform.test")
	mockPool := setupMockPool(t)
	redisServer := setupTestRedis(t)
	stub := newStubOAuthProvider()
	overrideProvider(t, models.ProviderGoogle, stub)

	appID := uuid.New()

	mockPool.ExpectQuery("SELECT enabled FROM oauth_providers").
		WithArgs(appID, models.ProviderGoogle).
		WillReturnRows(pgxmock.NewRows([]string{"enabled"}).AddRow(true))

	app := setupTestApp()
	req := httptest.NewRequest("GET",
		fmt.Sprintf("/api/v1/oauth/authorize?provider=%s&app_id=%s&redirect_uri=https://client.test/callback",
			models.ProviderGoogle, appID), nil)

	resp, err := app.Test(req, -1)
	require.NoError(t, err)
	require.Equal(t, 307, resp.StatusCode)
	require.Equal(t, stub.authURL, resp.Header.Get("Location"))
	require.NotEmpty(t, stub.lastState)
	require.Equal(t, "https://platform.test/api/v1/oauth/callback/"+models.ProviderGoogle, stub.lastRedirect)
	require.NotEmpty(t, redisServer.Keys())
	require.NoError(t, mockPool.ExpectationsWereMet())
}

func TestOAuthCallback_UsesRegisteredProvider(t *testing.T) {
	t.Setenv("PLATFORM_URL", "https://platform.test")
	t.Setenv("JWT_SECRET", "test-secret-that-is-at-least-32-characters-long!!")
	mockPool := setupMockPool(t)
	setupTestRedis(t)
	stub := newStubOAuthProvider()
	stub.accessToken = "callback-access"
	stub.refreshToken = "callback-refresh"
	stub.userInfo = &models.OAuthUserInfo{
		ProviderUserID: "provider-123",
		Email:          "user@example.com",
		Name:           "OAuth User",
		AvatarURL:      "https://example.com/avatar.png",
		EmailVerified:  true,
	}
	overrideProvider(t, models.ProviderGoogle, stub)

	appID := uuid.New()
	userID := uuid.New()
	state := "test-state-token"
	stateData := models.OAuthState{
		AppID:       appID,
		RedirectURI: "https://client.test/welcome",
		CreatedAt:   time.Now(),
	}
	data, err := json.Marshal(stateData)
	require.NoError(t, err)
	require.NoError(t, database.RedisClient.Set(context.Background(), database.OAuthStatePrefix+state, data, 5*time.Minute).Err())

	mockPool.ExpectQuery("SELECT user_id FROM identities").
		WithArgs(models.ProviderGoogle, stub.userInfo.ProviderUserID).
		WillReturnRows(pgxmock.NewRows([]string{"user_id"}).AddRow(userID))

	mockPool.ExpectExec("UPDATE identities").
		WithArgs(stub.accessToken, stub.refreshToken, models.ProviderGoogle, stub.userInfo.ProviderUserID).
		WillReturnResult(pgxmock.NewResult("UPDATE", 1))

	mockPool.ExpectExec("INSERT INTO sessions").
		WithArgs(pgxmock.AnyArg(), userID, appID, pgxmock.AnyArg(), pgxmock.AnyArg(), "stub-agent", pgxmock.AnyArg()).
		WillReturnResult(pgxmock.NewResult("INSERT", 1))

	app := setupTestApp()
	req := httptest.NewRequest("GET",
		fmt.Sprintf("/api/v1/oauth/callback/%s?code=stub-code&state=%s", models.ProviderGoogle, state), nil)
	req.Header.Set("User-Agent", "stub-agent")
	req.RemoteAddr = "203.0.113.1:1234"

	resp, err := app.Test(req, -1)
	require.NoError(t, err)
	require.Equal(t, 307, resp.StatusCode)
	location := resp.Header.Get("Location")
	require.Contains(t, location, stateData.RedirectURI)
	require.Contains(t, location, "token=")
	require.Equal(t, "stub-code", stub.lastCode)
	require.Equal(t, "https://platform.test/api/v1/oauth/callback/"+models.ProviderGoogle, stub.lastCallback)
	require.Equal(t, stub.accessToken, stub.lastToken)
	require.NoError(t, mockPool.ExpectationsWereMet())
}
