package utils

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"strconv"
	"time"

	"rauth/models"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

var jwtSecret []byte

func init() {
	secret := os.Getenv("JWT_SECRET")
	if secret == "" {
		// SECURITY WARNING: Default secret for testing only!
		// NEVER use this in production. Always set JWT_SECRET environment variable.
		secret = "default-insecure-key-for-testing-only-min-32-characters-long"
	}
	jwtSecret = []byte(secret)
}

// GenerateJWT genera un JWT para un usuario
func GenerateJWT(userID, appID, sessionID uuid.UUID, email string) (string, error) {
	expirationHours, err := strconv.Atoi(os.Getenv("JWT_EXPIRATION_HOURS"))
	if err != nil || expirationHours == 0 {
		expirationHours = 24
	}

	now := time.Now()
	expiresAt := now.Add(time.Duration(expirationHours) * time.Hour)

	claims := jwt.MapClaims{
		"user_id":    userID.String(),
		"app_id":     appID.String(),
		"session_id": sessionID.String(),
		"email":      email,
		"iat":        now.Unix(),
		"exp":        expiresAt.Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(jwtSecret)
}

// ValidateJWT valida y parsea un JWT
func ValidateJWT(tokenString string) (*models.JWTClaims, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// Verify signing method
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return jwtSecret, nil
	})

	if err != nil {
		return nil, fmt.Errorf("failed to parse token: %w", err)
	}

	if !token.Valid {
		return nil, fmt.Errorf("invalid token")
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, fmt.Errorf("invalid claims format")
	}

	// Extract and validate user_id
	userIDStr, ok := claims["user_id"].(string)
	if !ok {
		return nil, fmt.Errorf("invalid user_id in token")
	}
	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		return nil, fmt.Errorf("invalid user_id format: %w", err)
	}

	// Extract and validate app_id
	appIDStr, ok := claims["app_id"].(string)
	if !ok {
		return nil, fmt.Errorf("invalid app_id in token")
	}
	appID, err := uuid.Parse(appIDStr)
	if err != nil {
		return nil, fmt.Errorf("invalid app_id format: %w", err)
	}

	// Extract and validate session_id
	sessionIDStr, ok := claims["session_id"].(string)
	if !ok {
		return nil, fmt.Errorf("invalid session_id in token")
	}
	sessionID, err := uuid.Parse(sessionIDStr)
	if err != nil {
		return nil, fmt.Errorf("invalid session_id format: %w", err)
	}

	// Extract email (optional)
	email, _ := claims["email"].(string)

	// Extract timestamps
	iat, ok := claims["iat"].(float64)
	if !ok {
		return nil, fmt.Errorf("invalid iat in token")
	}

	exp, ok := claims["exp"].(float64)
	if !ok {
		return nil, fmt.Errorf("invalid exp in token")
	}

	return &models.JWTClaims{
		UserID:    userID,
		AppID:     appID,
		SessionID: sessionID,
		Email:     email,
		IssuedAt:  int64(iat),
		ExpiresAt: int64(exp),
	}, nil
}

// HashToken genera SHA-256 hash del token para almacenar en DB
func HashToken(token string) string {
	hash := sha256.Sum256([]byte(token))
	return hex.EncodeToString(hash[:])
}
