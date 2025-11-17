package models

import (
	"time"

	"github.com/google/uuid"
)

// Application representa una aplicación cliente que usa el servicio
type Application struct {
	ID                  uuid.UUID `json:"id" db:"id"`
	Name                string    `json:"name" db:"name"`
	APIKey              string    `json:"api_key" db:"api_key"`
	AllowedRedirectURIs []string  `json:"allowed_redirect_uris" db:"allowed_redirect_uris"`
	CORSOrigins         []string  `json:"cors_origins" db:"cors_origins"`
	CreatedAt           time.Time `json:"created_at" db:"created_at"`
	UpdatedAt           time.Time `json:"updated_at" db:"updated_at"`
}

// OAuthProvider representa la configuración de un proveedor OAuth para una app
type OAuthProvider struct {
	ID        uuid.UUID `json:"id" db:"id"`
	AppID     uuid.UUID `json:"app_id" db:"app_id"`
	Provider  string    `json:"provider" db:"provider"` // 'google', 'github', 'facebook'
	Enabled   bool      `json:"enabled" db:"enabled"`
	CreatedAt time.Time `json:"created_at" db:"created_at"`
	UpdatedAt time.Time `json:"updated_at" db:"updated_at"`
}

// CreateApplicationRequest es el request para crear una nueva aplicación
type CreateApplicationRequest struct {
	Name                string   `json:"name" validate:"required"`
	AllowedRedirectURIs []string `json:"allowed_redirect_uris"`
	CORSOrigins         []string `json:"cors_origins"`
}

// UpdateApplicationRequest es el request para actualizar una aplicación
type UpdateApplicationRequest struct {
	Name                *string   `json:"name,omitempty"`
	AllowedRedirectURIs *[]string `json:"allowed_redirect_uris,omitempty"`
	CORSOrigins         *[]string `json:"cors_origins,omitempty"`
}

// GenerateAPIKey genera una API key aleatoria
func GenerateAPIKey() string {
	return uuid.New().String()
}

// HasRedirectURI verifica si una URI está permitida
func (a *Application) HasRedirectURI(uri string) bool {
	for _, allowed := range a.AllowedRedirectURIs {
		if allowed == uri {
			return true
		}
	}
	return false
}

// HasCORSOrigin verifica si un origin está permitido
func (a *Application) HasCORSOrigin(origin string) bool {
	for _, allowed := range a.CORSOrigins {
		if allowed == origin || allowed == "*" {
			return true
		}
	}
	return false
}
