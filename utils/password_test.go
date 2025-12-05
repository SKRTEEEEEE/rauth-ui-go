package utils

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHashPassword(t *testing.T) {
	tests := []struct {
		name     string
		password string
	}{
		{
			name:     "simple password",
			password: "password123",
		},
		{
			name:     "complex password",
			password: "SecureP@ssw0rd!2024",
		},
		{
			name:     "long password",
			password: "ThisIsAVeryLongPasswordWithMoreThan50CharactersToTestTheHashingFunction",
		},
		{
			name:     "password with special characters",
			password: "P@$$w0rd!#$%^&*()",
		},
		{
			name:     "minimum length password",
			password: "Pass123!",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hash, err := HashPassword(tt.password)

			require.NoError(t, err)
			assert.NotEmpty(t, hash)

			// bcrypt hashes always start with $2a$, $2b$, or $2y$
			assert.True(t, len(hash) > 50, "Hash should be at least 50 characters")
			assert.Contains(t, hash, "$2a$")

			// Verify that the same password produces different hashes (due to salt)
			hash2, err := HashPassword(tt.password)
			require.NoError(t, err)
			assert.NotEqual(t, hash, hash2, "Different salts should produce different hashes")
		})
	}
}

func TestHashPasswordWithEmptyString(t *testing.T) {
	hash, err := HashPassword("")

	// bcrypt should handle empty strings
	require.NoError(t, err)
	assert.NotEmpty(t, hash)
}

func TestComparePassword(t *testing.T) {
	password := "SecurePassword123!"

	hash, err := HashPassword(password)
	require.NoError(t, err)

	tests := []struct {
		name          string
		inputPassword string
		expectMatch   bool
	}{
		{
			name:          "correct password",
			inputPassword: "SecurePassword123!",
			expectMatch:   true,
		},
		{
			name:          "wrong password",
			inputPassword: "WrongPassword123!",
			expectMatch:   false,
		},
		{
			name:          "empty password",
			inputPassword: "",
			expectMatch:   false,
		},
		{
			name:          "password with extra space",
			inputPassword: "SecurePassword123! ",
			expectMatch:   false,
		},
		{
			name:          "case sensitive check",
			inputPassword: "securepassword123!",
			expectMatch:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ComparePassword(hash, tt.inputPassword)
			assert.Equal(t, tt.expectMatch, result)
		})
	}
}

func TestComparePasswordWithInvalidHash(t *testing.T) {
	tests := []struct {
		name string
		hash string
	}{
		{
			name: "empty hash",
			hash: "",
		},
		{
			name: "invalid hash format",
			hash: "not-a-valid-bcrypt-hash",
		},
		{
			name: "truncated hash",
			hash: "$2a$10$",
		},
		{
			name: "random string",
			hash: "random-string-12345",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ComparePassword(tt.hash, "anypassword")
			assert.False(t, result, "Invalid hash should not match")
		})
	}
}

func TestPasswordHashConsistency(t *testing.T) {
	password := "ConsistentPassword123!"

	// Generate hash
	hash, err := HashPassword(password)
	require.NoError(t, err)

	// Verify multiple times
	for i := 0; i < 10; i++ {
		result := ComparePassword(hash, password)
		assert.True(t, result, "Password should consistently match its hash")
	}
}

func TestPasswordRoundTrip(t *testing.T) {
	// Test complete flow: hash -> verify
	passwords := []string{
		"SimplePass1!",
		"Complex@P@ssw0rd#2024",
		"12345678",
		"UPPERCASE_PASSWORD_123",
		"lowercase_password_456",
		"Mixed_Case_Password_789!",
	}

	for _, password := range passwords {
		t.Run(password, func(t *testing.T) {
			// Hash password
			hash, err := HashPassword(password)
			require.NoError(t, err)

			// Verify correct password
			assert.True(t, ComparePassword(hash, password))

			// Verify incorrect password fails
			assert.False(t, ComparePassword(hash, password+"wrong"))
		})
	}
}

func TestHashPasswordCost(t *testing.T) {
	password := "TestPassword123!"

	hash, err := HashPassword(password)
	require.NoError(t, err)

	// bcrypt default cost is 10
	// Hash format: $2a$10$...
	// We should check that it uses appropriate cost
	assert.Contains(t, hash, "$2a$10$")
}

func TestPasswordHashUniqueness(t *testing.T) {
	password := "UniquePassword123!"

	// Generate multiple hashes
	hashes := make(map[string]bool)

	for i := 0; i < 100; i++ {
		hash, err := HashPassword(password)
		require.NoError(t, err)

		// Each hash should be unique due to random salt
		assert.False(t, hashes[hash], "Hash collision detected")
		hashes[hash] = true

		// But all should verify the same password
		assert.True(t, ComparePassword(hash, password))
	}

	assert.Len(t, hashes, 100, "All hashes should be unique")
}

func TestComparePasswordCasesSensitivity(t *testing.T) {
	password := "CaseSensitive123!"

	hash, err := HashPassword(password)
	require.NoError(t, err)

	// Test case variations
	testCases := []struct {
		input    string
		expected bool
	}{
		{"CaseSensitive123!", true},  // exact match
		{"casesensitive123!", false}, // lowercase
		{"CASESENSITIVE123!", false}, // uppercase
		{"CaseSensitive123", false},  // missing !
		{"caseSensitive123!", false}, // first char lowercase
	}

	for _, tc := range testCases {
		t.Run(tc.input, func(t *testing.T) {
			result := ComparePassword(hash, tc.input)
			assert.Equal(t, tc.expected, result)
		})
	}
}

func BenchmarkHashPassword(b *testing.B) {
	password := "BenchmarkPassword123!"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = HashPassword(password)
	}
}

func BenchmarkComparePassword(b *testing.B) {
	password := "BenchmarkPassword123!"
	hash, _ := HashPassword(password)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = ComparePassword(hash, password)
	}
}

func BenchmarkPasswordRoundTrip(b *testing.B) {
	password := "BenchmarkPassword123!"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		hash, _ := HashPassword(password)
		_ = ComparePassword(hash, password)
	}
}
