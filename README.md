# RAuth - Authentication as a Service

A monolithic backend service built in Go that provides authentication-as-a-service (similar to Clerk). It allows clients to integrate OAuth login (Google, GitHub, Facebook, etc.) into their applications through a simple SDK, without managing OAuth credentials themselves.

## Project Status

🚧 **In Development** - Milestone 4 Completed: Admin API - Application Management

### Completed Milestones

**Milestone 2**: Foundation - Server Setup ✅
- ✅ Task 2.1: Go project initialized with all required dependencies
- ✅ Task 2.2: Complete project structure created
- ✅ Task 2.3: Fiber server implemented with health check endpoint
- ✅ Task 2.4: Environment configuration with validation

**Milestone 3**: Database Layer - Persistence ✅
- ✅ Task 3.1: PostgreSQL connection implemented with pgx driver
- ✅ Task 3.2: Database schema created with all tables (applications, oauth_providers, users, identities, sessions)
- ✅ Task 3.3: Go models implemented for all database tables
- ✅ Task 3.4: Redis cache layer with connection pool and OAuth state management

**Milestone 4**: Admin API - Application Management ✅
- ✅ Task 4.1: API Key authentication middleware
- ✅ Task 4.2: CRUD endpoints for applications
- ✅ Task 4.3: OAuth provider toggle endpoints

### Current Phase
✅ **Milestone 4**: Admin API - Application Management COMPLETED

The application now features:
- Secure API key authentication for admin endpoints
- Complete CRUD operations for managing applications
- OAuth provider configuration (enable/disable Google, GitHub, Facebook, Microsoft)
- Comprehensive test coverage with 10+ integration tests
- Production-ready error handling and validation
- Interactive API testing workflow with `.http` files

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

## API Testing

The project includes interactive API testing files that simulate the complete OAuth workflow:

### Quick Test with REST Client

1. Install [REST Client](https://marketplace.visualstudio.com/items?itemName=humao.rest-client) extension for VSCode
2. Open `api-workflow.http` in VSCode
3. Click "Send Request" on each HTTP block to test endpoints

```bash
# View the complete workflow
code api-workflow.http

# Read the testing guide
code API_TESTING_GUIDE.md
```

### Available Test Flows

The `api-workflow.http` file includes:

1. **Admin Setup** - Create and configure applications
2. **OAuth Configuration** - Enable/disable providers (Google, GitHub, Facebook, Microsoft)
3. **OAuth Flow** - End-to-end authentication workflow (partial, requires Milestone 5)
4. **Session Management** - Token validation and refresh (requires Milestone 5)
5. **User Management** - Profile operations (requires Milestone 7)
6. **Error Testing** - Validation and error handling

### Example: Enable Google OAuth

```http
### Create Application
POST http://localhost:8080/api/v1/admin/apps
X-API-Key: test-api-key-12345
Content-Type: application/json

{
  "name": "My App",
  "allowed_redirect_uris": ["http://localhost:3000/callback"],
  "cors_origins": ["http://localhost:3000"]
}

### Enable Google OAuth for the app
PATCH http://localhost:8080/api/v1/admin/apps/{app_id}/oauth/google
X-API-Key: test-api-key-12345
Content-Type: application/json

{
  "enabled": true
}
```

See `API_TESTING_GUIDE.md` for detailed instructions.

## Development with Docker

### Start All Services (App + Database + Redis)
```bash
docker-compose up -d --build
```

The application will be available at `http://localhost:8080`

### Start Only PostgreSQL and Redis
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
# or for specific service:
docker-compose logs -f app
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

## Docker Commands

```bash
# Build Docker image
docker build -t rauth:latest .

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

### Milestone 2: Foundation - Server Setup ✅ COMPLETED
1. ✅ **Task 2.1**: Setup Go project 
2. ✅ **Task 2.2**: Create project structure
3. ✅ **Task 2.3**: Implement basic Fiber server
4. ✅ **Task 2.4**: Setup environment configuration

### Milestone 3: Database Layer - Persistence ✅ COMPLETED
1. ✅ **Task 3.1**: PostgreSQL connection with pgx driver
2. ✅ **Task 3.2**: Database schema and migrations
3. ✅ **Task 3.3**: Go models implementation
4. ✅ **Task 3.4**: Redis setup and integration

### Milestone 4: Admin API - Application Management ✅ COMPLETED
1. ✅ **Task 4.1**: API Key authentication middleware
2. ✅ **Task 4.2**: CRUD operations for applications
3. ✅ **Task 4.3**: OAuth provider toggle endpoints

### Upcoming Milestones
5. ⏳ **Milestone 5**: Google OAuth - First Complete Flow
6. ⏳ **Milestone 6**: Multi-Provider OAuth - GitHub & Facebook
7. ⏳ **Milestone 7**: User Management - Profile & Sessions
8. ⏳ **Milestone 8**: Production Ready - Deploy & Secure

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
