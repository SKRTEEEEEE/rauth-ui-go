package models

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestUser_JSONSerialization(t *testing.T) {
	email := "test@example.com"
	name := "Test User"
	avatarURL := "https://example.com/avatar.jpg"

	user := User{
		ID:            uuid.New(),
		AppID:         uuid.New(),
		Email:         &email,
		Name:          &name,
		AvatarURL:     &avatarURL,
		EmailVerified: true,
		CreatedAt:     time.Now(),
		UpdatedAt:     time.Now(),
	}

	// Test JSON marshaling
	data, err := json.Marshal(user)
	if err != nil {
		t.Fatalf("Failed to marshal user: %v", err)
	}

	// Test JSON unmarshaling
	var decoded User
	err = json.Unmarshal(data, &decoded)
	if err != nil {
		t.Fatalf("Failed to unmarshal user: %v", err)
	}

	// Verify fields
	if decoded.Email == nil || *decoded.Email != email {
		t.Errorf("Expected email %s, got %v", email, decoded.Email)
	}
	if decoded.Name == nil || *decoded.Name != name {
		t.Errorf("Expected name %s, got %v", name, decoded.Name)
	}
	if !decoded.EmailVerified {
		t.Error("Expected email verified to be true")
	}
}

func TestUser_NullableFields(t *testing.T) {
	// User with null fields
	user := User{
		ID:            uuid.New(),
		AppID:         uuid.New(),
		Email:         nil,
		Name:          nil,
		AvatarURL:     nil,
		EmailVerified: false,
		CreatedAt:     time.Now(),
		UpdatedAt:     time.Now(),
	}

	// Test JSON marshaling
	data, err := json.Marshal(user)
	if err != nil {
		t.Fatalf("Failed to marshal user: %v", err)
	}

	// Test JSON unmarshaling
	var decoded User
	err = json.Unmarshal(data, &decoded)
	if err != nil {
		t.Fatalf("Failed to unmarshal user: %v", err)
	}

	// Verify null fields
	if decoded.Email != nil {
		t.Error("Email should be nil")
	}
	if decoded.Name != nil {
		t.Error("Name should be nil")
	}
	if decoded.AvatarURL != nil {
		t.Error("AvatarURL should be nil")
	}
}

func TestUpdateUserRequest_JSONSerialization(t *testing.T) {
	name := "Updated Name"
	email := "updated@example.com"

	req := UpdateUserRequest{
		Name:  &name,
		Email: &email,
	}

	// Test JSON marshaling
	data, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("Failed to marshal request: %v", err)
	}

	// Test JSON unmarshaling
	var decoded UpdateUserRequest
	err = json.Unmarshal(data, &decoded)
	if err != nil {
		t.Fatalf("Failed to unmarshal request: %v", err)
	}

	// Verify fields
	if decoded.Name == nil || *decoded.Name != name {
		t.Errorf("Expected name %s, got %v", name, decoded.Name)
	}
	if decoded.Email == nil || *decoded.Email != email {
		t.Errorf("Expected email %s, got %v", email, decoded.Email)
	}
}

func TestUpdateUserRequest_PartialUpdate(t *testing.T) {
	name := "Only Name"
	req := UpdateUserRequest{
		Name: &name,
	}

	// Test that only name is set
	if req.Name == nil {
		t.Error("Name should be set")
	}
	if req.Email != nil {
		t.Error("Email should be nil")
	}
	if req.AvatarURL != nil {
		t.Error("AvatarURL should be nil")
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
	if _, exists := decoded["email"]; exists {
		t.Error("Email should not be in JSON")
	}
}

func TestUserWithIdentities_JSONSerialization(t *testing.T) {
	email := "test@example.com"
	providerEmail := "test@gmail.com"

	user := User{
		ID:            uuid.New(),
		AppID:         uuid.New(),
		Email:         &email,
		EmailVerified: true,
		CreatedAt:     time.Now(),
		UpdatedAt:     time.Now(),
	}

	identities := []Identity{
		{
			ID:             uuid.New(),
			UserID:         user.ID,
			Provider:       ProviderGoogle,
			ProviderUserID: "google-123",
			ProviderEmail:  &providerEmail,
			CreatedAt:      time.Now(),
			UpdatedAt:      time.Now(),
		},
	}

	userWithIdentities := UserWithIdentities{
		User:       user,
		Identities: identities,
	}

	// Test JSON marshaling
	data, err := json.Marshal(userWithIdentities)
	if err != nil {
		t.Fatalf("Failed to marshal user with identities: %v", err)
	}

	// Test JSON unmarshaling
	var decoded UserWithIdentities
	err = json.Unmarshal(data, &decoded)
	if err != nil {
		t.Fatalf("Failed to unmarshal user with identities: %v", err)
	}

	// Verify fields
	if decoded.User.ID != user.ID {
		t.Error("User ID mismatch")
	}
	if len(decoded.Identities) != 1 {
		t.Errorf("Expected 1 identity, got %d", len(decoded.Identities))
	}
	if decoded.Identities[0].Provider != ProviderGoogle {
		t.Errorf("Expected provider %s, got %s", ProviderGoogle, decoded.Identities[0].Provider)
	}
}
