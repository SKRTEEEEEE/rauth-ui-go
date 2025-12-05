package utils

import (
	"errors"
)

// NewError creates a new error with the given message
// This is a helper function for consistent error creation
func NewError(message string) error {
	return errors.New(message)
}
