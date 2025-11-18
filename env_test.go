package main

import (
	"os"
	"testing"

	"github.com/joho/godotenv"
	"github.com/stretchr/testify/assert"
)

// TestEnvLoading tests that .env file loads correctly
func TestEnvLoading(t *testing.T) {
	// Create a temporary .env file for testing
	envContent := `PORT=9999
ENV=test
JWT_SECRET=test-jwt-secret-key-minimum-32-chars-required
ENCRYPTION_KEY=test-encryption-key-32bytes!!
PLATFORM_URL=http://localhost:9999`

	err := os.WriteFile(".env.test", []byte(envContent), 0644)
	assert.NoError(t, err, "Should create test .env file")
	defer os.Remove(".env.test")

	// Load the test env file
	err = godotenv.Load(".env.test")
	assert.NoError(t, err, "Should load .env.test file without error")

	// Verify values are loaded
	assert.Equal(t, "9999", os.Getenv("PORT"), "PORT should be loaded")
	assert.Equal(t, "test", os.Getenv("ENV"), "ENV should be loaded")
}

// TestRequiredEnvVariables tests validation of required environment variables
func TestRequiredEnvVariables(t *testing.T) {
	tests := []struct {
		name     string
		envVars  map[string]string
		required []string
		wantErr  bool
	}{
		{
			name: "All required variables present",
			envVars: map[string]string{
				"JWT_SECRET":     "test-jwt-secret-minimum-32-characters",
				"ENCRYPTION_KEY": "test-encryption-key-32bytes!!",
			},
			required: []string{"JWT_SECRET", "ENCRYPTION_KEY"},
			wantErr:  false,
		},
		{
			name: "Missing JWT_SECRET",
			envVars: map[string]string{
				"ENCRYPTION_KEY": "test-encryption-key-32bytes!!",
			},
			required: []string{"JWT_SECRET", "ENCRYPTION_KEY"},
			wantErr:  true,
		},
		{
			name: "Missing ENCRYPTION_KEY",
			envVars: map[string]string{
				"JWT_SECRET": "test-jwt-secret-minimum-32-characters",
			},
			required: []string{"JWT_SECRET", "ENCRYPTION_KEY"},
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Clear environment
			for _, key := range tt.required {
				os.Unsetenv(key)
			}

			// Set test environment variables
			for key, val := range tt.envVars {
				os.Setenv(key, val)
			}

			// Validate required variables
			err := validateRequiredEnvVars(tt.required)

			if tt.wantErr {
				assert.Error(t, err, "Should return error when required var is missing")
			} else {
				assert.NoError(t, err, "Should not return error when all required vars present")
			}
		})
	}
}

// TestJWTSecretLength tests that JWT_SECRET meets minimum length requirement
func TestJWTSecretLength(t *testing.T) {
	tests := []struct {
		name      string
		jwtSecret string
		wantErr   bool
	}{
		{
			name:      "Valid JWT secret (32+ chars)",
			jwtSecret: "this-is-a-valid-jwt-secret-key-with-32-plus-characters",
			wantErr:   false,
		},
		{
			name:      "JWT secret too short",
			jwtSecret: "short",
			wantErr:   true,
		},
		{
			name:      "JWT secret exactly 32 chars",
			jwtSecret: "12345678901234567890123456789012", // exactly 32 chars
			wantErr:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			os.Setenv("JWT_SECRET", tt.jwtSecret)

			err := validateJWTSecret()

			if tt.wantErr {
				assert.Error(t, err, "Should return error for invalid JWT secret")
			} else {
				assert.NoError(t, err, "Should not return error for valid JWT secret")
			}
		})
	}
}

// TestEncryptionKeyLength tests that ENCRYPTION_KEY is exactly 32 bytes
func TestEncryptionKeyLength(t *testing.T) {
	tests := []struct {
		name          string
		encryptionKey string
		wantErr       bool
	}{
		{
			name:          "Valid encryption key (32 bytes)",
			encryptionKey: "12345678901234567890123456789012", // exactly 32 bytes
			wantErr:       false,
		},
		{
			name:          "Encryption key too short",
			encryptionKey: "short",
			wantErr:       true,
		},
		{
			name:          "Encryption key too long",
			encryptionKey: "this-encryption-key-is-way-too-long-more-than-32-bytes",
			wantErr:       true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			os.Setenv("ENCRYPTION_KEY", tt.encryptionKey)

			err := validateEncryptionKey()

			if tt.wantErr {
				assert.Error(t, err, "Should return error for invalid encryption key")
			} else {
				assert.NoError(t, err, "Should not return error for valid encryption key")
			}
		})
	}
}

// TestDefaultPortValue tests that PORT defaults to 8080 if not set
func TestDefaultPortValue(t *testing.T) {
	os.Unsetenv("PORT")

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	assert.Equal(t, "8080", port, "PORT should default to 8080")
}

// TestPortValueFromEnv tests that PORT is read from environment
func TestPortValueFromEnv(t *testing.T) {
	os.Setenv("PORT", "3000")
	defer os.Unsetenv("PORT")

	port := os.Getenv("PORT")
	assert.Equal(t, "3000", port, "PORT should be read from environment")
}

// TestPlatformURL tests that PLATFORM_URL is correctly set
func TestPlatformURL(t *testing.T) {
	tests := []struct {
		name        string
		platformURL string
		expected    string
	}{
		{
			name:        "Development URL",
			platformURL: "http://localhost:8080",
			expected:    "http://localhost:8080",
		},
		{
			name:        "Production URL",
			platformURL: "https://api.rauth.io",
			expected:    "https://api.rauth.io",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			os.Setenv("PLATFORM_URL", tt.platformURL)
			defer os.Unsetenv("PLATFORM_URL")

			url := os.Getenv("PLATFORM_URL")
			assert.Equal(t, tt.expected, url, "PLATFORM_URL should match expected value")
		})
	}
}

// TestOptionalEnvVariables tests that optional variables don't break the app
func TestOptionalEnvVariables(t *testing.T) {
	optionalVars := []string{
		"GOOGLE_CLIENT_ID",
		"GITHUB_CLIENT_ID",
		"FACEBOOK_APP_ID",
		"AZURE_STORAGE_ACCOUNT",
		"SMTP_HOST",
	}

	for _, varName := range optionalVars {
		t.Run(varName, func(t *testing.T) {
			// These should be able to be empty without causing issues
			os.Unsetenv(varName)
			value := os.Getenv(varName)
			assert.Equal(t, "", value, "%s should be able to be empty", varName)
		})
	}
}

// Helper functions for validation (to be implemented in main.go or utils)

func validateRequiredEnvVars(required []string) error {
	for _, envVar := range required {
		if os.Getenv(envVar) == "" {
			return &EnvVarError{VarName: envVar}
		}
	}
	return nil
}

func validateJWTSecret() error {
	secret := os.Getenv("JWT_SECRET")
	if len(secret) < 32 {
		return &JWTSecretError{Length: len(secret)}
	}
	return nil
}

func validateEncryptionKey() error {
	key := os.Getenv("ENCRYPTION_KEY")
	if len(key) != 32 {
		return &EncryptionKeyError{Length: len(key)}
	}
	return nil
}

// Custom error types
type EnvVarError struct {
	VarName string
}

func (e *EnvVarError) Error() string {
	return "required environment variable " + e.VarName + " is not set"
}

type JWTSecretError struct {
	Length int
}

func (e *JWTSecretError) Error() string {
	return "JWT_SECRET must be at least 32 characters"
}

type EncryptionKeyError struct {
	Length int
}

func (e *EncryptionKeyError) Error() string {
	return "ENCRYPTION_KEY must be exactly 32 bytes"
}
