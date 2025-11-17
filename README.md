# AuthFlow - Authentication as a Service

A monolithic backend service built in Go that provides authentication-as-a-service (similar to Clerk). It allows clients to integrate OAuth login (Google, GitHub, Facebook, etc.) into their applications through a simple SDK, without managing OAuth credentials themselves.

## Project Status

🚧 **In Development** - Task 2 Complete: Go Module Setup

### Completed Milestones
- ✅ Task 2: Go project initialized with all required dependencies

### Current Phase
Setting up the foundation for the authentication service.

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

### 2. Install Dependencies
```bash
go mod download
```

### 3. Run Tests
```bash
go test -v
```

### 4. Build the Application
```bash
go build -o authflow .
```

### 5. Run the Application
```bash
./authflow
```

## Development with Docker

### Start PostgreSQL and Redis
```bash
docker-compose up -d postgres redis
```

### Stop Services
```bash
docker-compose down
```

### View Logs
```bash
docker-compose logs -f
```

## Project Structure

```
/
├── main.go              # Application entry point
├── go.mod              # Go module definition
├── go.sum              # Dependency checksums
├── Dockerfile          # Multi-stage Docker build
├── docker-compose.yml  # Docker services configuration
├── .env.example        # Example configuration (to be created)
├── setup_test.go       # Setup validation tests
└── docs/               # Documentation
    ├── task/          # Task tracking
    └── AGENTS.md      # Development guidelines
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
go build -ldflags="-s -w" -o authflow .
```

## Docker Commands

```bash
# Build Docker image
docker build -t authflow:latest .

# Run with docker-compose
docker-compose up -d

# Stop all services
docker-compose down

# View logs
docker-compose logs -f

# Rebuild services
docker-compose up -d --build
```

## Next Steps

The following tasks are planned:

1. ✅ **Task 2**: Setup Go project (COMPLETED)
2. 🔄 **Task 3**: Create project structure
3. ⏳ **Task 4**: Implement basic Fiber server
4. ⏳ **Task 5**: Setup environment configuration
5. ⏳ **Task 6**: PostgreSQL connection
6. ⏳ **Task 7**: Database schema and migrations
7. ⏳ **Task 8**: Implement Go models
8. ⏳ **Task 9**: Redis setup

See [AGENTS.md](./AGENTS.md) for detailed development guidelines and complete roadmap.

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
