package utils

import (
	"os"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMain(m *testing.M) {
	// Set up test environment variables
	// gitleaks:allow - This is a deliberate test-only fake secret for unit testing
	// NOT A REAL SECRET - Using obvious fake value that meets minimum length requirement
	testSecret := "FAKE_TEST_KEY_NOT_A_REAL_SECRET_MINIMUM_32_CHARS_REQUIRED"
	os.Setenv("JWT_SECRET", testSecret)
	os.Setenv("JWT_EXPIRATION_HOURS", "24")

	// Reinitialize jwtSecret with test value
	jwtSecret = []byte(os.Getenv("JWT_SECRET"))

	// Run tests
	code := m.Run()

	// Clean up
	os.Unsetenv("JWT_SECRET")
	os.Unsetenv("JWT_EXPIRATION_HOURS")

	os.Exit(code)
}

func TestGenerateJWT(t *testing.T) {
	userID := uuid.New()
	appID := uuid.New()
	sessionID := uuid.New()
	email := "test@example.com"

	token, err := GenerateJWT(userID, appID, sessionID, email)

	require.NoError(t, err)
	assert.NotEmpty(t, token)

	// Verify token can be parsed
	parsedToken, err := jwt.Parse(token, func(token *jwt.Token) (interface{}, error) {
		return jwtSecret, nil
	})

	require.NoError(t, err)
	assert.True(t, parsedToken.Valid)

	// Verify claims
	claims, ok := parsedToken.Claims.(jwt.MapClaims)
	require.True(t, ok)

	assert.Equal(t, userID.String(), claims["user_id"].(string))
	assert.Equal(t, appID.String(), claims["app_id"].(string))
	assert.Equal(t, sessionID.String(), claims["session_id"].(string))
	assert.Equal(t, email, claims["email"].(string))

	// Verify expiration is set correctly (24 hours from now)
	exp := int64(claims["exp"].(float64))
	iat := int64(claims["iat"].(float64))

	// Should be approximately 24 hours difference
	diff := exp - iat
	assert.InDelta(t, 24*60*60, diff, 5) // Allow 5 seconds tolerance
}

func TestGenerateJWTWithCustomExpiration(t *testing.T) {
	// Set custom expiration
	os.Setenv("JWT_EXPIRATION_HOURS", "48")
	defer os.Setenv("JWT_EXPIRATION_HOURS", "24")

	userID := uuid.New()
	appID := uuid.New()
	sessionID := uuid.New()
	email := "test@example.com"

	token, err := GenerateJWT(userID, appID, sessionID, email)
	require.NoError(t, err)

	parsedToken, err := jwt.Parse(token, func(token *jwt.Token) (interface{}, error) {
		return jwtSecret, nil
	})
	require.NoError(t, err)

	claims, _ := parsedToken.Claims.(jwt.MapClaims)
	exp := int64(claims["exp"].(float64))
	iat := int64(claims["iat"].(float64))

	// Should be approximately 48 hours difference
	diff := exp - iat
	assert.InDelta(t, 48*60*60, diff, 5)
}

func TestValidateJWT(t *testing.T) {
	userID := uuid.New()
	appID := uuid.New()
	sessionID := uuid.New()
	email := "test@example.com"

	// Generate token
	token, err := GenerateJWT(userID, appID, sessionID, email)
	require.NoError(t, err)

	// Validate token
	claims, err := ValidateJWT(token)
	require.NoError(t, err)
	require.NotNil(t, claims)

	assert.Equal(t, userID, claims.UserID)
	assert.Equal(t, appID, claims.AppID)
	assert.Equal(t, sessionID, claims.SessionID)
	assert.Equal(t, email, claims.Email)
	assert.NotZero(t, claims.IssuedAt)
	assert.NotZero(t, claims.ExpiresAt)

	// Verify expiration is in the future
	assert.True(t, claims.ExpiresAt > time.Now().Unix())
}

func TestValidateJWTWithInvalidToken(t *testing.T) {
	tests := []struct {
		name  string
		token string
	}{
		{
			name:  "empty token",
			token: "",
		},
		{
			name:  "malformed token",
			token: "not.a.valid.token",
		},
		{
			name:  "random string",
			token: "random-string-123",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			claims, err := ValidateJWT(tt.token)
			assert.Error(t, err)
			assert.Nil(t, claims)
		})
	}
}

func TestValidateJWTWithWrongSecret(t *testing.T) {
	userID := uuid.New()
	appID := uuid.New()
	sessionID := uuid.New()
	email := "test@example.com"

	// Generate token with correct secret
	token, err := GenerateJWT(userID, appID, sessionID, email)
	require.NoError(t, err)

	// Change secret temporarily (test value only)
	// gitleaks:allow - Deliberate fake secret for testing validation failures
	originalSecret := jwtSecret
	wrongTestSecret := []byte("WRONG_FAKE_KEY_FOR_TEST_VALIDATION_ONLY")
	jwtSecret = wrongTestSecret
	defer func() { jwtSecret = originalSecret }()

	// Try to validate with wrong secret
	claims, err := ValidateJWT(token)
	assert.Error(t, err)
	assert.Nil(t, claims)
}

func TestValidateJWTWithExpiredToken(t *testing.T) {
	userID := uuid.New()
	appID := uuid.New()
	sessionID := uuid.New()
	email := "test@example.com"

	// Create an expired token manually
	now := time.Now()
	expiresAt := now.Add(-1 * time.Hour) // 1 hour ago

	claims := jwt.MapClaims{
		"user_id":    userID.String(),
		"app_id":     appID.String(),
		"session_id": sessionID.String(),
		"email":      email,
		"iat":        now.Unix(),
		"exp":        expiresAt.Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(jwtSecret)
	require.NoError(t, err)

	// Try to validate expired token
	validatedClaims, err := ValidateJWT(tokenString)
	assert.Error(t, err)
	assert.Nil(t, validatedClaims)
}

func TestHashToken(t *testing.T) {
	tests := []struct {
		name     string
		token    string
		expected string
	}{
		{
			name:     "simple token",
			token:    "test-token",
			expected: "e998e0dc7e5c2f28d29e8d211e710a53bb7ec72e37d5775615760f4a5c5879d6",
		},
		{
			name:     "jwt token",
			token:    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0",
			expected: "7a563c5f58f1a5a09832c4f7b36c42b62e7b8de2e6c5d5a3e4f8c3b2a1d0e9f8",
		},
		{
			name:     "empty string",
			token:    "",
			expected: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hash := HashToken(tt.token)
			assert.NotEmpty(t, hash)
			assert.Len(t, hash, 64) // SHA-256 produces 64 hex characters

			// Verify same input produces same hash
			hash2 := HashToken(tt.token)
			assert.Equal(t, hash, hash2)
		})
	}
}

func TestHashTokenConsistency(t *testing.T) {
	token := "test-token-for-consistency-check"

	// Generate hash multiple times
	hashes := make([]string, 100)
	for i := 0; i < 100; i++ {
		hashes[i] = HashToken(token)
	}

	// All hashes should be identical
	firstHash := hashes[0]
	for _, hash := range hashes {
		assert.Equal(t, firstHash, hash)
	}
}

func TestHashTokenUniqueness(t *testing.T) {
	tokens := []string{
		"token1",
		"token2",
		"token3",
		"token1 ", // with space
		"Token1",  // different case
	}

	hashes := make(map[string]bool)

	for _, token := range tokens {
		hash := HashToken(token)

		// Each different token should produce a unique hash
		assert.False(t, hashes[hash], "Hash collision detected for token: %s", token)
		hashes[hash] = true
	}

	assert.Len(t, hashes, len(tokens))
}

func TestJWTRoundTrip(t *testing.T) {
	// Test complete flow: generate -> validate
	userID := uuid.New()
	appID := uuid.New()
	sessionID := uuid.New()
	email := "roundtrip@example.com"

	// Generate token
	token, err := GenerateJWT(userID, appID, sessionID, email)
	require.NoError(t, err)

	// Hash token
	tokenHash := HashToken(token)
	assert.NotEmpty(t, tokenHash)

	// Validate token
	claims, err := ValidateJWT(token)
	require.NoError(t, err)

	// Verify all data matches
	assert.Equal(t, userID, claims.UserID)
	assert.Equal(t, appID, claims.AppID)
	assert.Equal(t, sessionID, claims.SessionID)
	assert.Equal(t, email, claims.Email)
}

func BenchmarkGenerateJWT(b *testing.B) {
	userID := uuid.New()
	appID := uuid.New()
	sessionID := uuid.New()
	email := "bench@example.com"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = GenerateJWT(userID, appID, sessionID, email)
	}
}

func BenchmarkValidateJWT(b *testing.B) {
	userID := uuid.New()
	appID := uuid.New()
	sessionID := uuid.New()
	email := "bench@example.com"

	token, _ := GenerateJWT(userID, appID, sessionID, email)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = ValidateJWT(token)
	}
}

func BenchmarkHashToken(b *testing.B) {
	token := "benchmark-token-for-hashing-test"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = HashToken(token)
	}
}
