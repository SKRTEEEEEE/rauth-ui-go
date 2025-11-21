package oauth

import (
	"sync"

	"rauth/models"
)

// OAuthProvider define la interfaz mínima para los proveedores OAuth soportados.
type OAuthProvider interface {
	BuildAuthURL(state, redirectURI string) string
	ExchangeCode(code, redirectURI string) (string, string, error)
	GetUserInfo(accessToken string) (*models.OAuthUserInfo, error)
}

var (
	providersMu sync.RWMutex
	providers   = make(map[string]OAuthProvider)
)

// RegisterProvider registra o reemplaza un proveedor OAuth disponible en el runtime.
func RegisterProvider(name string, provider OAuthProvider) {
	providersMu.Lock()
	defer providersMu.Unlock()
	providers[name] = provider
}

// GetProvider retorna un proveedor registrado junto con un booleano indicando si existe.
func GetProvider(name string) (OAuthProvider, bool) {
	providersMu.RLock()
	defer providersMu.RUnlock()
	p, ok := providers[name]
	return p, ok
}

// RegisteredProviders devuelve la lista de proveedores disponibles.
func RegisteredProviders() []string {
	providersMu.RLock()
	defer providersMu.RUnlock()
	result := make([]string, 0, len(providers))
	for name := range providers {
		result = append(result, name)
	}
	return result
}
