package models

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestSession_JSONSerialization(t *testing.T) {
	ipAddress := "192.168.1.1"
	userAgent := "Mozilla/5.0"

	session := Session{
		ID:         uuid.New(),
		UserID:     uuid.New(),
		AppID:      uuid.New(),
		TokenHash:  "hashed-token",
		IPAddress:  &ipAddress,
		UserAgent:  &userAgent,
		ExpiresAt:  time.Now().Add(24 * time.Hour),
		CreatedAt:  time.Now(),
		LastUsedAt: time.Now(),
	}

	// Test JSON marshaling
	data, err := json.Marshal(session)
	if err != nil {
		t.Fatalf("Failed to marshal session: %v", err)
	}

	// Test that sensitive fields are not exposed
	var decoded map[string]interface{}
	json.Unmarshal(data, &decoded)

	if _, exists := decoded["token_hash"]; exists {
		t.Error("TokenHash should not be exposed in JSON")
	}

	// Test JSON unmarshaling
	var decodedSession Session
	err = json.Unmarshal(data, &decodedSession)
	if err != nil {
		t.Fatalf("Failed to unmarshal session: %v", err)
	}

	// Verify non-sensitive fields
	if decodedSession.ID != session.ID {
		t.Error("Session ID mismatch")
	}
	if decodedSession.IPAddress == nil || *decodedSession.IPAddress != ipAddress {
		t.Errorf("Expected IP address %s, got %v", ipAddress, decodedSession.IPAddress)
	}
}

func TestSession_NullableFields(t *testing.T) {
	session := Session{
		ID:         uuid.New(),
		UserID:     uuid.New(),
		AppID:      uuid.New(),
		TokenHash:  "hashed-token",
		IPAddress:  nil,
		UserAgent:  nil,
		ExpiresAt:  time.Now().Add(24 * time.Hour),
		CreatedAt:  time.Now(),
		LastUsedAt: time.Now(),
	}

	// Test JSON marshaling
	data, err := json.Marshal(session)
	if err != nil {
		t.Fatalf("Failed to marshal session: %v", err)
	}

	// Test JSON unmarshaling
	var decoded Session
	err = json.Unmarshal(data, &decoded)
	if err != nil {
		t.Fatalf("Failed to unmarshal session: %v", err)
	}

	// Verify null fields
	if decoded.IPAddress != nil {
		t.Error("IPAddress should be nil")
	}
	if decoded.UserAgent != nil {
		t.Error("UserAgent should be nil")
	}
}

func TestJWTClaims_JSONSerialization(t *testing.T) {
	now := time.Now()
	claims := JWTClaims{
		UserID:    uuid.New(),
		AppID:     uuid.New(),
		SessionID: uuid.New(),
		Email:     "test@example.com",
		IssuedAt:  now.Unix(),
		ExpiresAt: now.Add(24 * time.Hour).Unix(),
	}

	// Test JSON marshaling
	data, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("Failed to marshal JWT claims: %v", err)
	}

	// Test JSON unmarshaling
	var decoded JWTClaims
	err = json.Unmarshal(data, &decoded)
	if err != nil {
		t.Fatalf("Failed to unmarshal JWT claims: %v", err)
	}

	// Verify fields
	if decoded.UserID != claims.UserID {
		t.Error("UserID mismatch")
	}
	if decoded.Email != claims.Email {
		t.Errorf("Expected email %s, got %s", claims.Email, decoded.Email)
	}
	if decoded.IssuedAt != claims.IssuedAt {
		t.Errorf("Expected issued at %d, got %d", claims.IssuedAt, decoded.IssuedAt)
	}
	if decoded.ExpiresAt != claims.ExpiresAt {
		t.Errorf("Expected expires at %d, got %d", claims.ExpiresAt, decoded.ExpiresAt)
	}
}

func TestJWTClaims_OptionalEmail(t *testing.T) {
	claims := JWTClaims{
		UserID:    uuid.New(),
		AppID:     uuid.New(),
		SessionID: uuid.New(),
		Email:     "", // Empty email
		IssuedAt:  time.Now().Unix(),
		ExpiresAt: time.Now().Add(24 * time.Hour).Unix(),
	}

	// Test JSON marshaling with omitempty
	data, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("Failed to marshal JWT claims: %v", err)
	}

	var decoded map[string]interface{}
	json.Unmarshal(data, &decoded)

	// Email should not be in JSON when empty
	if _, exists := decoded["email"]; exists {
		t.Error("Email should not be in JSON when empty")
	}
}

func TestSessionWithUser_JSONSerialization(t *testing.T) {
	email := "test@example.com"
	name := "Test User"
	ipAddress := "192.168.1.1"

	user := User{
		ID:            uuid.New(),
		AppID:         uuid.New(),
		Email:         &email,
		Name:          &name,
		EmailVerified: true,
		CreatedAt:     time.Now(),
		UpdatedAt:     time.Now(),
	}

	session := Session{
		ID:         uuid.New(),
		UserID:     user.ID,
		AppID:      user.AppID,
		TokenHash:  "hashed-token",
		IPAddress:  &ipAddress,
		ExpiresAt:  time.Now().Add(24 * time.Hour),
		CreatedAt:  time.Now(),
		LastUsedAt: time.Now(),
	}

	sessionWithUser := SessionWithUser{
		Session: session,
		User:    user,
	}

	// Test JSON marshaling
	data, err := json.Marshal(sessionWithUser)
	if err != nil {
		t.Fatalf("Failed to marshal session with user: %v", err)
	}

	// Test JSON unmarshaling
	var decoded SessionWithUser
	err = json.Unmarshal(data, &decoded)
	if err != nil {
		t.Fatalf("Failed to unmarshal session with user: %v", err)
	}

	// Verify fields
	if decoded.Session.ID != session.ID {
		t.Error("Session ID mismatch")
	}
	if decoded.User.ID != user.ID {
		t.Error("User ID mismatch")
	}
	if decoded.User.Email == nil || *decoded.User.Email != email {
		t.Errorf("Expected email %s, got %v", email, decoded.User.Email)
	}
}

func TestSession_ExpirationValidation(t *testing.T) {
	// Session that expires in the future (valid)
	validSession := Session{
		ID:         uuid.New(),
		UserID:     uuid.New(),
		AppID:      uuid.New(),
		TokenHash:  "hashed-token",
		ExpiresAt:  time.Now().Add(24 * time.Hour),
		CreatedAt:  time.Now(),
		LastUsedAt: time.Now(),
	}

	if validSession.ExpiresAt.Before(time.Now()) {
		t.Error("Valid session should not be expired")
	}

	// Session that expired in the past (invalid)
	expiredSession := Session{
		ID:         uuid.New(),
		UserID:     uuid.New(),
		AppID:      uuid.New(),
		TokenHash:  "hashed-token",
		ExpiresAt:  time.Now().Add(-1 * time.Hour),
		CreatedAt:  time.Now().Add(-25 * time.Hour),
		LastUsedAt: time.Now().Add(-1 * time.Hour),
	}

	if !expiredSession.ExpiresAt.Before(time.Now()) {
		t.Error("Expired session should be expired")
	}
}
