package models

import (
	"time"

	"github.com/google/uuid"
)

// User representa un usuario final de una aplicación
type User struct {
	ID            uuid.UUID `json:"id" db:"id"`
	AppID         uuid.UUID `json:"app_id" db:"app_id"`
	Email         *string   `json:"email" db:"email"`
	Name          *string   `json:"name" db:"name"`
	AvatarURL     *string   `json:"avatar_url" db:"avatar_url"`
	EmailVerified bool      `json:"email_verified" db:"email_verified"`
	CreatedAt     time.Time `json:"created_at" db:"created_at"`
	UpdatedAt     time.Time `json:"updated_at" db:"updated_at"`
}

// UpdateUserRequest es el request para actualizar un usuario
type UpdateUserRequest struct {
	Name      *string `json:"name,omitempty"`
	Email     *string `json:"email,omitempty"`
	AvatarURL *string `json:"avatar_url,omitempty"`
}

// UserWithIdentities incluye las identidades OAuth del usuario
type UserWithIdentities struct {
	User       User       `json:"user"`
	Identities []Identity `json:"identities"`
}
