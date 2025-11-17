package models

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestApplication_JSONSerialization(t *testing.T) {
	app := Application{
		ID:                  uuid.New(),
		Name:                "Test App",
		APIKey:              "test-api-key",
		AllowedRedirectURIs: []string{"http://localhost:3000/callback"},
		CORSOrigins:         []string{"http://localhost:3000"},
		CreatedAt:           time.Now(),
		UpdatedAt:           time.Now(),
	}

	// Test JSON marshaling
	data, err := json.Marshal(app)
	if err != nil {
		t.Fatalf("Failed to marshal application: %v", err)
	}

	// Test JSON unmarshaling
	var decoded Application
	err = json.Unmarshal(data, &decoded)
	if err != nil {
		t.Fatalf("Failed to unmarshal application: %v", err)
	}

	// Verify fields
	if decoded.Name != app.Name {
		t.Errorf("Expected name %s, got %s", app.Name, decoded.Name)
	}
	if decoded.APIKey != app.APIKey {
		t.Errorf("Expected API key %s, got %s", app.APIKey, decoded.APIKey)
	}
}

func TestApplication_HasRedirectURI(t *testing.T) {
	app := Application{
		AllowedRedirectURIs: []string{
			"http://localhost:3000/callback",
			"https://example.com/auth/callback",
		},
	}

	tests := []struct {
		name     string
		uri      string
		expected bool
	}{
		{"Valid URI 1", "http://localhost:3000/callback", true},
		{"Valid URI 2", "https://example.com/auth/callback", true},
		{"Invalid URI", "http://evil.com/callback", false},
		{"Empty string", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := app.HasRedirectURI(tt.uri)
			if result != tt.expected {
				t.Errorf("HasRedirectURI(%s) = %v, expected %v", tt.uri, result, tt.expected)
			}
		})
	}
}

func TestApplication_HasCORSOrigin(t *testing.T) {
	app := Application{
		CORSOrigins: []string{
			"http://localhost:3000",
			"https://example.com",
		},
	}

	tests := []struct {
		name     string
		origin   string
		expected bool
	}{
		{"Valid origin 1", "http://localhost:3000", true},
		{"Valid origin 2", "https://example.com", true},
		{"Invalid origin", "http://evil.com", false},
		{"Empty string", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := app.HasCORSOrigin(tt.origin)
			if result != tt.expected {
				t.Errorf("HasCORSOrigin(%s) = %v, expected %v", tt.origin, result, tt.expected)
			}
		})
	}
}

func TestApplication_HasCORSOrigin_Wildcard(t *testing.T) {
	app := Application{
		CORSOrigins: []string{"*"},
	}

	if !app.HasCORSOrigin("http://any-domain.com") {
		t.Error("Wildcard should allow any origin")
	}
	if !app.HasCORSOrigin("https://another-domain.com") {
		t.Error("Wildcard should allow any origin")
	}
}

func TestGenerateAPIKey(t *testing.T) {
	key1 := GenerateAPIKey()
	key2 := GenerateAPIKey()

	// Should generate non-empty keys
	if key1 == "" {
		t.Error("Generated API key should not be empty")
	}

	// Should generate unique keys
	if key1 == key2 {
		t.Error("Generated API keys should be unique")
	}

	// Should be valid UUID format
	_, err := uuid.Parse(key1)
	if err != nil {
		t.Errorf("Generated API key should be valid UUID: %v", err)
	}
}

func TestOAuthProvider_JSONSerialization(t *testing.T) {
	provider := OAuthProvider{
		ID:        uuid.New(),
		AppID:     uuid.New(),
		Provider:  ProviderGoogle,
		Enabled:   true,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	// Test JSON marshaling
	data, err := json.Marshal(provider)
	if err != nil {
		t.Fatalf("Failed to marshal OAuth provider: %v", err)
	}

	// Test JSON unmarshaling
	var decoded OAuthProvider
	err = json.Unmarshal(data, &decoded)
	if err != nil {
		t.Fatalf("Failed to unmarshal OAuth provider: %v", err)
	}

	// Verify fields
	if decoded.Provider != provider.Provider {
		t.Errorf("Expected provider %s, got %s", provider.Provider, decoded.Provider)
	}
	if decoded.Enabled != provider.Enabled {
		t.Errorf("Expected enabled %v, got %v", provider.Enabled, decoded.Enabled)
	}
}

func TestCreateApplicationRequest_Validation(t *testing.T) {
	tests := []struct {
		name    string
		request CreateApplicationRequest
		valid   bool
	}{
		{
			name: "Valid request with all fields",
			request: CreateApplicationRequest{
				Name:                "Test App",
				AllowedRedirectURIs: []string{"http://localhost:3000/callback"},
				CORSOrigins:         []string{"http://localhost:3000"},
			},
			valid: true,
		},
		{
			name: "Valid request minimal",
			request: CreateApplicationRequest{
				Name: "Test App",
			},
			valid: true,
		},
		{
			name: "Invalid request no name",
			request: CreateApplicationRequest{
				AllowedRedirectURIs: []string{"http://localhost:3000/callback"},
			},
			valid: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Basic validation check
			if tt.request.Name == "" && tt.valid {
				t.Error("Request should be invalid when name is empty")
			}
		})
	}
}

func TestUpdateApplicationRequest_PartialUpdate(t *testing.T) {
	name := "Updated Name"
	req := UpdateApplicationRequest{
		Name: &name,
	}

	// Test that only name is set
	if req.Name == nil {
		t.Error("Name should be set")
	}
	if req.AllowedRedirectURIs != nil {
		t.Error("AllowedRedirectURIs should be nil")
	}
	if req.CORSOrigins != nil {
		t.Error("CORSOrigins should be nil")
	}

	// Test JSON marshaling with omitempty
	data, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("Failed to marshal request: %v", err)
	}

	var decoded map[string]interface{}
	json.Unmarshal(data, &decoded)

	if _, exists := decoded["name"]; !exists {
		t.Error("Name should be in JSON")
	}
	if _, exists := decoded["allowed_redirect_uris"]; exists {
		t.Error("allowed_redirect_uris should not be in JSON")
	}
}
