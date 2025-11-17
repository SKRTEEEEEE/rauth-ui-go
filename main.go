package main

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"rauth/database"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"github.com/gofiber/fiber/v2/middleware/logger"
	"github.com/joho/godotenv"
)

func main() {
	// Load .env file (ignore error if doesn't exist)
	_ = godotenv.Load()

	// Validate required environment variables
	if err := validateEnvironment(); err != nil {
		log.Fatalf("❌ Environment validation failed: %v", err)
	}
	log.Println("✅ Environment variables loaded")

	// Connect to PostgreSQL
	if err := database.Connect(); err != nil {
		log.Fatalf("❌ Database connection failed: %v", err)
	}
	defer database.Close()

	// Connect to Redis
	if err := database.ConnectRedis(); err != nil {
		log.Fatalf("❌ Redis connection failed: %v", err)
	}
	defer database.CloseRedis()

	// Create Fiber app
	app := fiber.New(fiber.Config{
		AppName: "AuthFlow v1.0",
		ErrorHandler: func(c *fiber.Ctx, err error) error {
			code := fiber.StatusInternalServerError
			if e, ok := err.(*fiber.Error); ok {
				code = e.Code
			}
			return c.Status(code).JSON(fiber.Map{
				"error": err.Error(),
			})
		},
	})

	// Middleware
	app.Use(logger.New())
	app.Use(cors.New())

	// Health check endpoint (now includes database and Redis status)
	app.Get("/health", func(c *fiber.Ctx) error {
		dbStatus := "ok"
		if err := database.Ping(); err != nil {
			dbStatus = "error"
		}

		redisStatus := "ok"
		if err := database.PingRedis(); err != nil {
			redisStatus = "error"
		}

		return c.JSON(fiber.Map{
			"status":   "ok",
			"service":  "authflow",
			"database": dbStatus,
			"redis":    redisStatus,
		})
	})

	// Graceful shutdown
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-quit
		log.Println("🛑 Shutting down server...")
		_ = app.Shutdown()
	}()

	// Get port from env or use default
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	// Start server
	log.Printf("🚀 Server starting on port %s", port)
	if err := app.Listen(":" + port); err != nil {
		log.Printf("❌ Server failed: %v", err)
	}
}

// validateEnvironment validates required environment variables
func validateEnvironment() error {
	// Validate critical environment variables
	requiredVars := []string{"JWT_SECRET", "ENCRYPTION_KEY", "DATABASE_URL", "REDIS_URL"}

	for _, envVar := range requiredVars {
		if os.Getenv(envVar) == "" {
			return fmt.Errorf("required environment variable %s is not set", envVar)
		}
	}

	// Validate JWT_SECRET length (must be at least 32 characters)
	jwtSecret := os.Getenv("JWT_SECRET")
	if len(jwtSecret) < 32 {
		return fmt.Errorf("JWT_SECRET must be at least 32 characters long (current: %d)", len(jwtSecret))
	}

	// Validate ENCRYPTION_KEY length (must be exactly 32 bytes for AES-256)
	encryptionKey := os.Getenv("ENCRYPTION_KEY")
	if len(encryptionKey) != 32 {
		return fmt.Errorf("ENCRYPTION_KEY must be exactly 32 bytes long (current: %d)", len(encryptionKey))
	}

	return nil
}
