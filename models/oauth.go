package models

import (
	"time"

	"github.com/google/uuid"
)

// Identity representa una identidad OAuth vinculada a un usuario
type Identity struct {
	ID             uuid.UUID  `json:"id" db:"id"`
	UserID         uuid.UUID  `json:"user_id" db:"user_id"`
	Provider       string     `json:"provider" db:"provider"` // 'google', 'github', 'facebook'
	ProviderUserID string     `json:"provider_user_id" db:"provider_user_id"`
	ProviderEmail  *string    `json:"provider_email" db:"provider_email"`
	AccessToken    *string    `json:"-" db:"access_token"`  // No exponer en JSON
	RefreshToken   *string    `json:"-" db:"refresh_token"` // No exponer en JSON
	TokenExpiresAt *time.Time `json:"token_expires_at" db:"token_expires_at"`
	CreatedAt      time.Time  `json:"created_at" db:"created_at"`
	UpdatedAt      time.Time  `json:"updated_at" db:"updated_at"`
}

// OAuthUserInfo es la información del usuario obtenida del proveedor OAuth
type OAuthUserInfo struct {
	ProviderUserID string `json:"id"`
	Email          string `json:"email"`
	Name           string `json:"name"`
	AvatarURL      string `json:"avatar_url"`
	EmailVerified  bool   `json:"email_verified"`
}

// OAuthState almacena el estado de una petición OAuth
type OAuthState struct {
	AppID       uuid.UUID `json:"app_id"`
	RedirectURI string    `json:"redirect_uri"`
	CreatedAt   time.Time `json:"created_at"`
}

// Constantes de proveedores OAuth
const (
	ProviderGoogle    = "google"
	ProviderGitHub    = "github"
	ProviderFacebook  = "facebook"
	ProviderMicrosoft = "microsoft"
)

// IsValidProvider verifica si el proveedor es válido
func IsValidProvider(provider string) bool {
	switch provider {
	case ProviderGoogle, ProviderGitHub, ProviderFacebook, ProviderMicrosoft:
		return true
	default:
		return false
	}
}

// ValidProviders retorna la lista de proveedores válidos
func ValidProviders() []string {
	return []string{
		ProviderGoogle,
		ProviderGitHub,
		ProviderFacebook,
		ProviderMicrosoft,
	}
}
