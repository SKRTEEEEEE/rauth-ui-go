# RAuth - Authentication as a Service

A monolithic backend service built in Go that provides authentication-as-a-service (similar to Clerk). It allows clients to integrate OAuth login (Google, GitHub, Facebook, etc.) into their applications through a simple SDK, without managing OAuth credentials themselves.


## Tech Stack

- **Language**: Go 1.25+
- **Framework**: Fiber (high-performance, Express-like API)
- **Database**: PostgreSQL 15+ with pgx driver
- **Cache/Sessions**: Redis 7+
- **Queue**: Redis lists/channels
- **Storage**: Azure Blob Storage
- **Email**: SMTP
- **JWT**: golang-jwt/jwt/v5
- **Config**: .env with godotenv

## Prerequisites

- Go 1.21 or higher
- PostgreSQL 15+
- Redis 7+
- Docker & Docker Compose (optional, for containerized development)

## Quick Start

### 1. Clone the Repository
```bash
git clone <repository-url>
cd rauth-ui
```

### 2. Configure Environment Variables

Copy the example environment file and configure it:

```bash
cp .env.example .env
```

Edit `.env` and set the required variables:

```env
# Required: JWT secret (minimum 32 characters)
JWT_SECRET=your-secret-key-at-least-32-characters-long

# Required: Encryption key (exactly 32 bytes for AES-256)
ENCRYPTION_KEY=12345678901234567890123456789012

# Required: PostgreSQL connection URL
DATABASE_URL=postgresql://username:password@localhost:5432/dbname?sslmode=disable

# Optional: Server port (defaults to 8080)
PORT=8080

# Required: Redis connection URL
REDIS_URL=redis://localhost:6379/0
```

**Important**: 
- `JWT_SECRET` must be at least 32 characters
- `ENCRYPTION_KEY` must be exactly 32 bytes
- `DATABASE_URL` must point to a valid PostgreSQL instance
- `REDIS_URL` must point to a valid Redis instance
- Never commit `.env` file to version control

### 3. Install Dependencies
```bash
go mod download
```

### 4. Run Tests
```bash
go test -v
```

### 5. Build the Application
```bash
go build -o rflow.exe .
```

### 6. Run the Application
```bash
./rflow.exe
```

You should see:
```
✅ Environment variables loaded
✅ Connected to PostgreSQL
✅ Connected to Redis
🚀 Server starting on port 8080
```

Test the health endpoint:
```bash
curl http://localhost:8080/health
# Expected: {"database":"ok","redis":"ok","service":"authflow","status":"ok"}
```



## Project Structure

```
/
├── main.go                    # Application entry point
├── go.mod                     # Go module definition
├── go.sum                     # Dependency checksums
├── Dockerfile                 # Multi-stage Docker build
├── docker-compose.yml         # Docker services configuration
├── .env.example               # Environment variables template
├── api-workflow.http          # Interactive API testing workflow
├── API_TESTING_GUIDE.md       # Guide for using .http files
├── setup_test.go              # Setup validation tests
├── /handlers                  # HTTP handlers
│   ├── auth.go                # OAuth authentication endpoints
│   ├── users.go               # User management endpoints
│   ├── admin.go               # Admin dashboard endpoints
│   └── webhooks.go            # Webhook handling
├── /models                    # Database models
│   ├── application.go         # Application/client model
│   ├── user.go                # User model
│   ├── session.go             # Session model
│   └── oauth.go               # OAuth provider model
├── /database                  # Database layer
│   ├── db.go                  # PostgreSQL connection
│   ├── redis.go               # Redis connection and helpers
│   ├── migrations.sql         # SQL migrations
│   └── queries.go             # Database queries
├── /middleware                # Middleware functions
│   ├── auth.go                # JWT authentication
│   ├── apikey.go              # API key validation
│   └── cors.go                # CORS handling
├── /oauth                     # OAuth provider implementations
│   ├── google.go              # Google OAuth
│   ├── github.go              # GitHub OAuth
│   └── facebook.go            # Facebook OAuth
├── /utils                     # Helper functions
│   ├── jwt.go                 # JWT utilities
│   ├── crypto.go              # Encryption/hashing
│   ├── email.go               # Email sending
│   └── azure.go               # Azure Blob Storage
└── /docs                      # Documentation
    ├── API.md                 # API documentation
    ├── task/                  # Task tracking
    └── buss-plain.v1.md       # Business plan
```

## Testing

The project includes comprehensive tests to validate the setup:

```bash
# Run all tests
go test -v

# Run specific test
go test -v -run TestGoModExists

# Run tests with coverage
go test -v -cover
```

### Test Coverage

- ✅ Go module initialization
- ✅ Required dependencies installation
- ✅ Go.mod and go.sum validation
- ✅ Module verification
- ✅ Build compilation
- ✅ Go version check

### [API HTTP Testing](./docs/API_TESTING_GUIDE.md)

## Dependencies

All required dependencies are managed through `go.mod`:

- **github.com/gofiber/fiber/v2** - Web framework
- **github.com/jackc/pgx/v5** - PostgreSQL driver
- **github.com/redis/go-redis/v9** - Redis client
- **github.com/joho/godotenv** - Environment variables
- **github.com/golang-jwt/jwt/v5** - JWT tokens
- **github.com/google/uuid** - UUID generation
- **github.com/Azure/azure-sdk-for-go/sdk/storage/azblob** - Azure Blob Storage

## Available Commands

```bash
# Format code
go fmt ./...

# Run linter
go vet ./...

# Clean and verify modules
go mod tidy
go mod verify

# List all modules
go list -m all

# Build for production
go build -ldflags="-s -w" -o rauth .
```



## Contributing

This project follows a test-driven development approach with automated pipelines. All changes must:

1. Include tests
2. Pass existing test suite
3. Follow Go standard conventions
4. Be documented appropriately

## License

[License information to be added]

## Support

For issues, questions, or contributions, please refer to the project documentation in the `docs/` directory.

---

**Built with ❤️ using Go and modern cloud technologies**
