package models

import (
	"time"

	"github.com/google/uuid"
)

// Session representa una sesión activa de usuario
type Session struct {
	ID         uuid.UUID `json:"id" db:"id"`
	UserID     uuid.UUID `json:"user_id" db:"user_id"`
	AppID      uuid.UUID `json:"app_id" db:"app_id"`
	TokenHash  string    `json:"-" db:"token_hash"` // No exponer en JSON
	IPAddress  *string   `json:"ip_address" db:"ip_address"`
	UserAgent  *string   `json:"user_agent" db:"user_agent"`
	ExpiresAt  time.Time `json:"expires_at" db:"expires_at"`
	CreatedAt  time.Time `json:"created_at" db:"created_at"`
	LastUsedAt time.Time `json:"last_used_at" db:"last_used_at"`
}

// JWTClaims son los claims del JWT token
type JWTClaims struct {
	UserID    uuid.UUID `json:"user_id"`
	AppID     uuid.UUID `json:"app_id"`
	SessionID uuid.UUID `json:"session_id"`
	Email     string    `json:"email,omitempty"`
	IssuedAt  int64     `json:"iat"`
	ExpiresAt int64     `json:"exp"`
}

// SessionWithUser incluye información del usuario
type SessionWithUser struct {
	Session Session `json:"session"`
	User    User    `json:"user"`
}
