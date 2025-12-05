package utils

import (
	"golang.org/x/crypto/bcrypt"
)

const (
	// bcryptCost is the cost parameter for bcrypt hashing
	// Default is 10, which provides a good balance between security and performance
	bcryptCost = 10
)

// HashPassword hashes a password using bcrypt
func HashPassword(password string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcryptCost)
	if err != nil {
		return "", err
	}
	return string(hash), nil
}

// ComparePassword compares a password with its hash
// Returns true if the password matches the hash, false otherwise
func ComparePassword(hash, password string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}
