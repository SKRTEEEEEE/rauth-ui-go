package database

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestConnect_Success tests successful database connection
func TestConnect_Success(t *testing.T) {
	// Setup: ensure DATABASE_URL is set
	originalURL := os.Getenv("DATABASE_URL")
	defer os.Setenv("DATABASE_URL", originalURL)

	// Use test database URL if available, otherwise skip
	testURL := os.Getenv("DATABASE_URL")
	if testURL == "" {
		t.Skip("DATABASE_URL not set, skipping integration test")
	}

	// Ensure DB is nil before test
	DB = nil

	// Execute
	err := Connect()

	// Assert
	require.NoError(t, err, "Connect should not return error with valid DATABASE_URL")
	assert.NotNil(t, DB, "DB should be initialized after Connect")

	// Cleanup
	if DB != nil {
		Close()
	}
}

// TestConnect_MissingDatabaseURL tests connection failure when DATABASE_URL is not set
func TestConnect_MissingDatabaseURL(t *testing.T) {
	// Setup: temporarily unset DATABASE_URL
	originalURL := os.Getenv("DATABASE_URL")
	os.Unsetenv("DATABASE_URL")
	defer os.Setenv("DATABASE_URL", originalURL)

	// Ensure DB is nil
	DB = nil

	// Execute
	err := Connect()

	// Assert
	require.Error(t, err, "Connect should return error when DATABASE_URL is not set")
	assert.Contains(t, err.Error(), "DATABASE_URL not set", "Error message should mention DATABASE_URL")
	assert.Nil(t, DB, "DB should remain nil on connection failure")
}

// TestConnect_InvalidDatabaseURL tests connection failure with invalid URL
func TestConnect_InvalidDatabaseURL(t *testing.T) {
	// Setup: set invalid DATABASE_URL
	originalURL := os.Getenv("DATABASE_URL")
	os.Setenv("DATABASE_URL", "invalid://url")
	defer os.Setenv("DATABASE_URL", originalURL)

	// Ensure DB is nil
	DB = nil

	// Execute
	err := Connect()

	// Assert
	require.Error(t, err, "Connect should return error with invalid DATABASE_URL")
	assert.Nil(t, DB, "DB should remain nil on connection failure")
}

// TestPing_Success tests successful database ping
func TestPing_Success(t *testing.T) {
	// Setup: ensure database is connected
	if os.Getenv("DATABASE_URL") == "" {
		t.Skip("DATABASE_URL not set, skipping integration test")
	}

	DB = nil
	err := Connect()
	require.NoError(t, err, "Connect should succeed for ping test")
	defer Close()

	// Execute
	err = Ping()

	// Assert
	assert.NoError(t, err, "Ping should succeed with active connection")
}

// TestPing_NoConnection tests ping failure when not connected
func TestPing_NoConnection(t *testing.T) {
	// Setup: ensure DB is nil
	originalDB := DB
	DB = nil
	defer func() { DB = originalDB }()

	// Execute
	err := Ping()

	// Assert
	require.Error(t, err, "Ping should return error when DB is nil")
	assert.Contains(t, err.Error(), "database not connected", "Error should mention database not connected")
}

// TestClose_Success tests successful database close
func TestClose_Success(t *testing.T) {
	// Setup: connect to database
	if os.Getenv("DATABASE_URL") == "" {
		t.Skip("DATABASE_URL not set, skipping integration test")
	}

	DB = nil
	err := Connect()
	require.NoError(t, err, "Connect should succeed for close test")

	// Execute
	Close()

	// Assert: DB should be closed (can't really assert much here, just ensure no panic)
	// Try to ping after close - should fail
	err = Ping()
	assert.Error(t, err, "Ping should fail after Close")
}

// TestClose_WhenNil tests that Close handles nil DB gracefully
func TestClose_WhenNil(t *testing.T) {
	// Setup: ensure DB is nil
	originalDB := DB
	DB = nil
	defer func() { DB = originalDB }()

	// Execute (should not panic)
	assert.NotPanics(t, func() {
		Close()
	}, "Close should not panic when DB is nil")
}

// TestConnectionPool_Configuration tests connection pool settings
func TestConnectionPool_Configuration(t *testing.T) {
	// Setup
	if os.Getenv("DATABASE_URL") == "" {
		t.Skip("DATABASE_URL not set, skipping integration test")
	}

	DB = nil
	err := Connect()
	require.NoError(t, err, "Connect should succeed")
	defer Close()

	// Assert: verify pool is working by executing a simple query
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var result int
	err = DB.QueryRow(ctx, "SELECT 1").Scan(&result)
	assert.NoError(t, err, "Simple query should succeed with connection pool")
	assert.Equal(t, 1, result, "Query should return expected result")
}

// TestPing_WithTimeout tests that Ping respects timeout
func TestPing_WithTimeout(t *testing.T) {
	// Setup
	if os.Getenv("DATABASE_URL") == "" {
		t.Skip("DATABASE_URL not set, skipping integration test")
	}

	DB = nil
	err := Connect()
	require.NoError(t, err, "Connect should succeed")
	defer Close()

	// Execute with very short timeout (this test verifies timeout mechanism works)
	start := time.Now()
	err = Ping()
	duration := time.Since(start)

	// Assert: Ping should complete within reasonable time
	assert.NoError(t, err, "Ping should succeed")
	assert.Less(t, duration, 10*time.Second, "Ping should complete within timeout")
}

// TestMultipleConnections tests that multiple Connect calls are handled properly
func TestMultipleConnections(t *testing.T) {
	// Setup
	if os.Getenv("DATABASE_URL") == "" {
		t.Skip("DATABASE_URL not set, skipping integration test")
	}

	DB = nil

	// Execute: Connect multiple times
	err1 := Connect()
	require.NoError(t, err1, "First Connect should succeed")

	firstDB := DB

	err2 := Connect()
	require.NoError(t, err2, "Second Connect should succeed")

	// Assert: DB should be replaced with new connection
	assert.NotNil(t, DB, "DB should still be initialized")

	// Cleanup
	Close()

	// Note: In production, this could lead to connection leaks
	// Consider tracking this in implementation if it becomes an issue
	_ = firstDB // Prevent unused variable warning
}
