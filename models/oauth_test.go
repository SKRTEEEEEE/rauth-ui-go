package models

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestIdentity_JSONSerialization(t *testing.T) {
	providerEmail := "test@gmail.com"
	accessToken := "secret-access-token"
	refreshToken := "secret-refresh-token"
	expiresAt := time.Now().Add(time.Hour)

	identity := Identity{
		ID:             uuid.New(),
		UserID:         uuid.New(),
		Provider:       ProviderGoogle,
		ProviderUserID: "google-123",
		ProviderEmail:  &providerEmail,
		AccessToken:    &accessToken,
		RefreshToken:   &refreshToken,
		TokenExpiresAt: &expiresAt,
		CreatedAt:      time.Now(),
		UpdatedAt:      time.Now(),
	}

	// Test JSON marshaling
	data, err := json.Marshal(identity)
	if err != nil {
		t.Fatalf("Failed to marshal identity: %v", err)
	}

	// Test that sensitive fields are not exposed
	var decoded map[string]interface{}
	json.Unmarshal(data, &decoded)

	if _, exists := decoded["access_token"]; exists {
		t.Error("AccessToken should not be exposed in JSON")
	}
	if _, exists := decoded["refresh_token"]; exists {
		t.Error("RefreshToken should not be exposed in JSON")
	}

	// Test JSON unmarshaling
	var decodedIdentity Identity
	err = json.Unmarshal(data, &decodedIdentity)
	if err != nil {
		t.Fatalf("Failed to unmarshal identity: %v", err)
	}

	// Verify non-sensitive fields
	if decodedIdentity.Provider != identity.Provider {
		t.Errorf("Expected provider %s, got %s", identity.Provider, decodedIdentity.Provider)
	}
	if decodedIdentity.ProviderUserID != identity.ProviderUserID {
		t.Errorf("Expected provider user ID %s, got %s", identity.ProviderUserID, decodedIdentity.ProviderUserID)
	}
}

func TestIsValidProvider(t *testing.T) {
	tests := []struct {
		provider string
		valid    bool
	}{
		{ProviderGoogle, true},
		{ProviderGitHub, true},
		{ProviderFacebook, true},
		{ProviderMicrosoft, true},
		{"invalid", false},
		{"", false},
		{"GOOGLE", false}, // Case sensitive
	}

	for _, tt := range tests {
		t.Run(tt.provider, func(t *testing.T) {
			result := IsValidProvider(tt.provider)
			if result != tt.valid {
				t.Errorf("IsValidProvider(%s) = %v, expected %v", tt.provider, result, tt.valid)
			}
		})
	}
}

func TestValidProviders(t *testing.T) {
	providers := ValidProviders()

	// Should return 4 providers
	if len(providers) != 4 {
		t.Errorf("Expected 4 providers, got %d", len(providers))
	}

	// Should contain expected providers
	expectedProviders := map[string]bool{
		ProviderGoogle:    false,
		ProviderGitHub:    false,
		ProviderFacebook:  false,
		ProviderMicrosoft: false,
	}

	for _, provider := range providers {
		if _, exists := expectedProviders[provider]; !exists {
			t.Errorf("Unexpected provider: %s", provider)
		}
		expectedProviders[provider] = true
	}

	// Verify all expected providers are present
	for provider, found := range expectedProviders {
		if !found {
			t.Errorf("Missing provider: %s", provider)
		}
	}
}

func TestOAuthUserInfo_JSONSerialization(t *testing.T) {
	userInfo := OAuthUserInfo{
		ProviderUserID: "google-123",
		Email:          "test@gmail.com",
		Name:           "Test User",
		AvatarURL:      "https://example.com/avatar.jpg",
		EmailVerified:  true,
	}

	// Test JSON marshaling
	data, err := json.Marshal(userInfo)
	if err != nil {
		t.Fatalf("Failed to marshal OAuth user info: %v", err)
	}

	// Test JSON unmarshaling
	var decoded OAuthUserInfo
	err = json.Unmarshal(data, &decoded)
	if err != nil {
		t.Fatalf("Failed to unmarshal OAuth user info: %v", err)
	}

	// Verify fields
	if decoded.ProviderUserID != userInfo.ProviderUserID {
		t.Errorf("Expected provider user ID %s, got %s", userInfo.ProviderUserID, decoded.ProviderUserID)
	}
	if decoded.Email != userInfo.Email {
		t.Errorf("Expected email %s, got %s", userInfo.Email, decoded.Email)
	}
	if decoded.EmailVerified != userInfo.EmailVerified {
		t.Errorf("Expected email verified %v, got %v", userInfo.EmailVerified, decoded.EmailVerified)
	}
}

func TestOAuthState_JSONSerialization(t *testing.T) {
	state := OAuthState{
		AppID:       uuid.New(),
		RedirectURI: "http://localhost:3000/callback",
		CreatedAt:   time.Now(),
	}

	// Test JSON marshaling
	data, err := json.Marshal(state)
	if err != nil {
		t.Fatalf("Failed to marshal OAuth state: %v", err)
	}

	// Test JSON unmarshaling
	var decoded OAuthState
	err = json.Unmarshal(data, &decoded)
	if err != nil {
		t.Fatalf("Failed to unmarshal OAuth state: %v", err)
	}

	// Verify fields
	if decoded.AppID != state.AppID {
		t.Error("AppID mismatch")
	}
	if decoded.RedirectURI != state.RedirectURI {
		t.Errorf("Expected redirect URI %s, got %s", state.RedirectURI, decoded.RedirectURI)
	}
}

func TestProviderConstants(t *testing.T) {
	// Verify provider constants are defined
	if ProviderGoogle == "" {
		t.Error("ProviderGoogle should be defined")
	}
	if ProviderGitHub == "" {
		t.Error("ProviderGitHub should be defined")
	}
	if ProviderFacebook == "" {
		t.Error("ProviderFacebook should be defined")
	}
	if ProviderMicrosoft == "" {
		t.Error("ProviderMicrosoft should be defined")
	}

	// Verify they have expected values
	if ProviderGoogle != "google" {
		t.Errorf("Expected 'google', got %s", ProviderGoogle)
	}
	if ProviderGitHub != "github" {
		t.Errorf("Expected 'github', got %s", ProviderGitHub)
	}
	if ProviderFacebook != "facebook" {
		t.Errorf("Expected 'facebook', got %s", ProviderFacebook)
	}
	if ProviderMicrosoft != "microsoft" {
		t.Errorf("Expected 'microsoft', got %s", ProviderMicrosoft)
	}
}
