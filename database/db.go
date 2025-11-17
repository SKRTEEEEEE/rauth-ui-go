package database

import (
	"context"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// DB is the global database connection pool
var DB *pgxpool.Pool

// Connect establishes connection with PostgreSQL and initializes the connection pool
func Connect() error {
	ctx := context.Background()

	// Get connection URL from environment
	databaseURL := os.Getenv("DATABASE_URL")
	if databaseURL == "" {
		return fmt.Errorf("DATABASE_URL not set in environment")
	}

	// Parse connection configuration
	config, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		return fmt.Errorf("error parsing database URL: %w", err)
	}

	// Configure connection pool
	config.MaxConns = 25                      // Maximum number of connections in the pool
	config.MinConns = 5                       // Minimum number of idle connections
	config.MaxConnLifetime = time.Hour        // Recycle connections after 1 hour
	config.MaxConnIdleTime = 30 * time.Minute // Close idle connections after 30 minutes

	// Create connection pool
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		return fmt.Errorf("error creating connection pool: %w", err)
	}

	// Verify connection by pinging the database
	if err := pool.Ping(ctx); err != nil {
		pool.Close() // Clean up the pool if ping fails
		return fmt.Errorf("error pinging database: %w", err)
	}

	DB = pool
	log.Println("✅ Connected to PostgreSQL")
	return nil
}

// Close closes the database connection pool
func Close() {
	if DB != nil {
		DB.Close()
		log.Println("🔌 Database connection closed")
	}
}

// Ping verifies that the database connection is still alive
func Ping() error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if DB == nil {
		return fmt.Errorf("database not connected")
	}

	return DB.Ping(ctx)
}
