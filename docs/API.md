# API Documentation

## Overview
Authentication SaaS Platform API - OAuth as a Service

## Base URL
```http
http://localhost:8080/api/v1
```

## Authentication
- **API Key**: Used for admin endpoints - `X-API-Key: {your-api-key}`
- **JWT Token**: Used for user endpoints - `Authorization: Bearer {jwt-token}`

## Endpoints

### OAuth Endpoints (Public)

#### Start OAuth Flow
```http
GET http://localhost:8080/api/v1/oauth/authorize
```

**Query Parameters:**
- `provider` (string, required): OAuth provider (google, github, facebook)
- `app_id` (string, required): Application ID
- `redirect_uri` (string, required): Callback URL

**Response:**
- 302 Redirect to OAuth provider

---

#### OAuth Callback
```http
GET /oauth/callback/:provider
```

**Query Parameters:**
- `code` (string, required): Authorization code from provider
- `state` (string, required): State token for validation

**Response:**
- 302 Redirect to client with JWT token

---

### User Endpoints (JWT Protected)

#### Get Current User
```http
GET /users/me
```

**Response:**
```json
{
  "id": "uuid",
  "email": "user@example.com",
  "name": "John Doe",
  "avatar_url": "https://...",
  "created_at": "2024-01-01T00:00:00Z"
}
```

---

#### Update User Profile
```http
PATCH /users/me
```

**Request Body:**
```json
{
  "name": "John Doe",
  "avatar_url": "https://..."
}
```

---

#### Delete Account
```http
DELETE /users/me
```

**Response:**
- 204 No Content

---

### Session Endpoints

#### Validate Token
```http
POST /sessions/validate
```

**Request Body:**
```json
{
  "token": "jwt-token"
}
```

**Response:**
```json
{
  "valid": true,
  "user_id": "uuid",
  "expires_at": "2024-01-01T00:00:00Z"
}
```

---

#### Refresh Token
```http
POST /sessions/refresh
```

**Request Body:**
```json
{
  "token": "current-jwt-token"
}
```

**Response:**
```json
{
  "token": "new-jwt-token",
  "expires_at": "2024-01-01T00:00:00Z"
}
```

---

#### Logout
```http
DELETE /sessions/:id
```

**Response:**
- 204 No Content

---

### Admin Endpoints (API Key Protected)

#### List Applications
```http
GET /admin/apps
```

**Response:**
```json
{
  "applications": [
    {
      "id": "uuid",
      "name": "My App",
      "api_key": "key",
      "created_at": "2024-01-01T00:00:00Z"
    }
  ]
}
```

---

#### Create Application
```http
POST /admin/apps
```

**Request Body:**
```json
{
  "name": "My New App",
  "allowed_redirect_uris": ["http://localhost:3000/callback"],
  "cors_origins": ["http://localhost:3000"]
}
```

**Response:**
```json
{
  "id": "uuid",
  "name": "My New App",
  "api_key": "generated-key",
  "created_at": "2024-01-01T00:00:00Z"
}
```

---

#### Get Application
```http
GET /admin/apps/:id
```

---

#### Update Application
```http
PATCH /admin/apps/:id
```

---

#### Delete Application
```http
DELETE /admin/apps/:id
```

---

#### List App Users
```http
GET /admin/apps/:id/users
```

**Response:**
```json
{
  "users": [
    {
      "id": "uuid",
      "email": "user@example.com",
      "name": "John Doe",
      "created_at": "2024-01-01T00:00:00Z"
    }
  ]
}
```

---

#### Toggle OAuth Provider
```http
PATCH /admin/apps/:id/oauth/:provider
```

**Request Body:**
```json
{
  "enabled": true
}
```

**Response:**
```json
{
  "provider": "google",
  "enabled": true
}
```

---

### Health Check

```http
GET /health
```

**Response:**
```json
{
  "status": "ok"
}
```

---

## Error Responses

All endpoints return errors in this format:

```json
{
  "error": {
    "code": "ERROR_CODE",
    "message": "Human readable message"
  }
}
```

### Common Error Codes
- `INVALID_REQUEST`: Bad request parameters
- `UNAUTHORIZED`: Missing or invalid authentication
- `FORBIDDEN`: Insufficient permissions
- `NOT_FOUND`: Resource not found
- `INTERNAL_ERROR`: Server error

---

## Rate Limiting
- 100 requests per 15 minutes per IP
- Rate limit headers included in responses:
  - `X-RateLimit-Limit`
  - `X-RateLimit-Remaining`
  - `X-RateLimit-Reset`

---

## CORS
CORS is configured per application in the admin panel. Set `cors_origins` when creating or updating an application.

---

## Webhooks
*Coming in Phase 2*

---

## SDK Examples

### JavaScript
```javascript
// Initialize client
const auth = new AuthFlowClient({
  appId: 'your-app-id',
  apiKey: 'your-api-key'
});

// Start OAuth
await auth.signIn('google', {
  redirectUri: 'http://localhost:3000/callback'
});

// Get current user
const user = await auth.getCurrentUser(jwtToken);
```

### Go
```go
// Initialize client
client := rauth.NewClient("your-app-id", "your-api-key")

// Start OAuth
url, err := client.GetOAuthURL("google", "http://localhost:3000/callback")

// Get current user
user, err := client.GetCurrentUser(jwtToken)
```

---

## Notes
- All timestamps are in ISO 8601 format (UTC)
- All IDs are UUIDs (v4)
- HTTPS required in production
- OAuth redirect URIs must be pre-configured in admin panel
