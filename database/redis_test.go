package database

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/joho/godotenv"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestMain sets up test environment
func TestMain(m *testing.M) {
	// Load .env for tests
	_ = godotenv.Load("../.env")

	// Run tests
	code := m.Run()

	os.Exit(code)
}

func TestConnectRedis(t *testing.T) {
	// Clean up any existing connection
	CloseRedis()

	// Test connection
	err := ConnectRedis()
	require.NoError(t, err, "Should connect to Redis successfully")
	require.NotNil(t, RedisClient, "RedisClient should be initialized")

	// Clean up
	defer CloseRedis()

	// Verify connection works
	err = PingRedis()
	assert.NoError(t, err, "Should ping Redis successfully")
}

func TestConnectRedis_MissingURL(t *testing.T) {
	// Clean up
	CloseRedis()

	// Save original URL
	originalURL := os.Getenv("REDIS_URL")
	defer os.Setenv("REDIS_URL", originalURL)

	// Remove URL
	os.Setenv("REDIS_URL", "")

	// Test connection should fail
	err := ConnectRedis()
	assert.Error(t, err, "Should fail when REDIS_URL is not set")
	assert.Contains(t, err.Error(), "REDIS_URL not set", "Error should mention missing REDIS_URL")
}

func TestConnectRedis_InvalidURL(t *testing.T) {
	// Clean up
	CloseRedis()

	// Save original URL
	originalURL := os.Getenv("REDIS_URL")
	defer os.Setenv("REDIS_URL", originalURL)

	// Set invalid URL
	os.Setenv("REDIS_URL", "invalid-url")

	// Test connection should fail
	err := ConnectRedis()
	assert.Error(t, err, "Should fail with invalid Redis URL")
}

func TestPingRedis(t *testing.T) {
	// Setup
	CloseRedis()
	err := ConnectRedis()
	require.NoError(t, err)
	defer CloseRedis()

	// Test ping
	err = PingRedis()
	assert.NoError(t, err, "Ping should succeed")
}

func TestPingRedis_NotConnected(t *testing.T) {
	// Clean up any connection
	CloseRedis()

	// Test ping without connection
	err := PingRedis()
	assert.Error(t, err, "Ping should fail when not connected")
	// Error can be either "Redis not connected" or "client is closed"
	isValidError := err.Error() == "Redis not connected" || err.Error() == "redis: client is closed"
	assert.True(t, isValidError, "Error should indicate Redis not connected or client closed")
}

func TestSetJSON_GetJSON(t *testing.T) {
	// Setup
	CloseRedis()
	err := ConnectRedis()
	require.NoError(t, err)
	defer CloseRedis()

	ctx := context.Background()

	// Test data
	type TestData struct {
		ID    uuid.UUID `json:"id"`
		Name  string    `json:"name"`
		Count int       `json:"count"`
	}

	testData := TestData{
		ID:    uuid.New(),
		Name:  "test-item",
		Count: 42,
	}

	key := "test:json:" + uuid.New().String()
	ttl := 10 * time.Second

	// Set JSON
	err = SetJSON(ctx, key, testData, ttl)
	assert.NoError(t, err, "SetJSON should succeed")

	// Get JSON
	var retrieved TestData
	err = GetJSON(ctx, key, &retrieved)
	assert.NoError(t, err, "GetJSON should succeed")

	// Verify data
	assert.Equal(t, testData.ID, retrieved.ID, "ID should match")
	assert.Equal(t, testData.Name, retrieved.Name, "Name should match")
	assert.Equal(t, testData.Count, retrieved.Count, "Count should match")

	// Clean up
	Delete(ctx, key)
}

func TestGetJSON_NotFound(t *testing.T) {
	// Setup
	CloseRedis()
	err := ConnectRedis()
	require.NoError(t, err)
	defer CloseRedis()

	ctx := context.Background()

	// Try to get non-existent key
	var data map[string]interface{}
	err = GetJSON(ctx, "test:nonexistent:"+uuid.New().String(), &data)

	// Should get redis.Nil error
	assert.Error(t, err, "GetJSON should fail for non-existent key")
	assert.Equal(t, redis.Nil, err, "Should return redis.Nil error")
}

func TestSetString_GetString(t *testing.T) {
	// Setup
	CloseRedis()
	err := ConnectRedis()
	require.NoError(t, err)
	defer CloseRedis()

	ctx := context.Background()

	key := "test:string:" + uuid.New().String()
	value := "test-value-" + uuid.New().String()
	ttl := 10 * time.Second

	// Set string
	err = SetString(ctx, key, value, ttl)
	assert.NoError(t, err, "SetString should succeed")

	// Get string
	retrieved, err := GetString(ctx, key)
	assert.NoError(t, err, "GetString should succeed")
	assert.Equal(t, value, retrieved, "Value should match")

	// Clean up
	Delete(ctx, key)
}

func TestGetString_NotFound(t *testing.T) {
	// Setup
	CloseRedis()
	err := ConnectRedis()
	require.NoError(t, err)
	defer CloseRedis()

	ctx := context.Background()

	// Try to get non-existent key
	_, err = GetString(ctx, "test:nonexistent:"+uuid.New().String())

	// Should get redis.Nil error
	assert.Error(t, err, "GetString should fail for non-existent key")
	assert.Equal(t, redis.Nil, err, "Should return redis.Nil error")
}

func TestDelete(t *testing.T) {
	// Setup
	CloseRedis()
	err := ConnectRedis()
	require.NoError(t, err)
	defer CloseRedis()

	ctx := context.Background()

	// Create test keys
	key1 := "test:delete:1:" + uuid.New().String()
	key2 := "test:delete:2:" + uuid.New().String()

	err = SetString(ctx, key1, "value1", 10*time.Second)
	require.NoError(t, err)
	err = SetString(ctx, key2, "value2", 10*time.Second)
	require.NoError(t, err)

	// Delete keys
	err = Delete(ctx, key1, key2)
	assert.NoError(t, err, "Delete should succeed")

	// Verify deletion
	_, err = GetString(ctx, key1)
	assert.Equal(t, redis.Nil, err, "Key1 should be deleted")

	_, err = GetString(ctx, key2)
	assert.Equal(t, redis.Nil, err, "Key2 should be deleted")
}

func TestExists(t *testing.T) {
	// Setup
	CloseRedis()
	err := ConnectRedis()
	require.NoError(t, err)
	defer CloseRedis()

	ctx := context.Background()

	key := "test:exists:" + uuid.New().String()

	// Check non-existent key
	exists, err := Exists(ctx, key)
	assert.NoError(t, err, "Exists should not error")
	assert.False(t, exists, "Key should not exist")

	// Create key
	err = SetString(ctx, key, "value", 10*time.Second)
	require.NoError(t, err)

	// Check existing key
	exists, err = Exists(ctx, key)
	assert.NoError(t, err, "Exists should not error")
	assert.True(t, exists, "Key should exist")

	// Clean up
	Delete(ctx, key)
}

func TestSetTTL(t *testing.T) {
	// Setup
	CloseRedis()
	err := ConnectRedis()
	require.NoError(t, err)
	defer CloseRedis()

	ctx := context.Background()

	key := "test:ttl:" + uuid.New().String()

	// Create key with long TTL
	err = SetString(ctx, key, "value", 1*time.Hour)
	require.NoError(t, err)

	// Update TTL to short duration
	err = SetTTL(ctx, key, 2*time.Second)
	assert.NoError(t, err, "SetTTL should succeed")

	// Verify key exists
	exists, err := Exists(ctx, key)
	assert.NoError(t, err)
	assert.True(t, exists, "Key should exist")

	// Wait for TTL to expire
	time.Sleep(3 * time.Second)

	// Verify key no longer exists
	exists, err = Exists(ctx, key)
	assert.NoError(t, err)
	assert.False(t, exists, "Key should be expired")
}

func TestSaveOAuthState(t *testing.T) {
	// Setup
	CloseRedis()
	err := ConnectRedis()
	require.NoError(t, err)
	defer CloseRedis()

	ctx := context.Background()

	// Test data
	type OAuthStateData struct {
		AppID       uuid.UUID `json:"app_id"`
		RedirectURI string    `json:"redirect_uri"`
		CreatedAt   time.Time `json:"created_at"`
	}

	stateKey := uuid.New().String()
	stateData := OAuthStateData{
		AppID:       uuid.New(),
		RedirectURI: "http://localhost:3000/callback",
		CreatedAt:   time.Now(),
	}

	// Save OAuth state
	err = SaveOAuthState(ctx, stateKey, stateData)
	assert.NoError(t, err, "SaveOAuthState should succeed")

	// Verify key exists with correct prefix
	fullKey := OAuthStatePrefix + stateKey
	exists, err := Exists(ctx, fullKey)
	assert.NoError(t, err)
	assert.True(t, exists, "OAuth state key should exist")

	// Verify TTL is set (should be around 5 minutes)
	ttl := RedisClient.TTL(ctx, fullKey).Val()
	assert.Greater(t, ttl, 4*time.Minute, "TTL should be close to 5 minutes")
	assert.LessOrEqual(t, ttl, OAuthStateTTL, "TTL should not exceed configured TTL")

	// Clean up
	Delete(ctx, fullKey)
}

func TestGetOAuthState(t *testing.T) {
	// Setup
	CloseRedis()
	err := ConnectRedis()
	require.NoError(t, err)
	defer CloseRedis()

	ctx := context.Background()

	// Test data
	type OAuthStateData struct {
		AppID       uuid.UUID `json:"app_id"`
		RedirectURI string    `json:"redirect_uri"`
		CreatedAt   time.Time `json:"created_at"`
	}

	stateKey := uuid.New().String()
	stateData := OAuthStateData{
		AppID:       uuid.New(),
		RedirectURI: "http://localhost:3000/callback",
		CreatedAt:   time.Now(),
	}

	// Save OAuth state
	err = SaveOAuthState(ctx, stateKey, stateData)
	require.NoError(t, err)

	// Get OAuth state
	var retrieved OAuthStateData
	err = GetOAuthState(ctx, stateKey, &retrieved)
	assert.NoError(t, err, "GetOAuthState should succeed")

	// Verify data
	assert.Equal(t, stateData.AppID, retrieved.AppID, "AppID should match")
	assert.Equal(t, stateData.RedirectURI, retrieved.RedirectURI, "RedirectURI should match")
	assert.WithinDuration(t, stateData.CreatedAt, retrieved.CreatedAt, time.Second, "CreatedAt should match")

	// Verify key was deleted (single-use)
	fullKey := OAuthStatePrefix + stateKey
	exists, err := Exists(ctx, fullKey)
	assert.NoError(t, err)
	assert.False(t, exists, "OAuth state should be deleted after retrieval")
}

func TestGetOAuthState_NotFound(t *testing.T) {
	// Setup
	CloseRedis()
	err := ConnectRedis()
	require.NoError(t, err)
	defer CloseRedis()

	ctx := context.Background()

	// Try to get non-existent OAuth state
	var data map[string]interface{}
	err = GetOAuthState(ctx, uuid.New().String(), &data)

	// Should get redis.Nil error
	assert.Error(t, err, "GetOAuthState should fail for non-existent state")
	assert.Equal(t, redis.Nil, err, "Should return redis.Nil error")
}

func TestGetOAuthState_ExpiredState(t *testing.T) {
	// Setup
	CloseRedis()
	err := ConnectRedis()
	require.NoError(t, err)
	defer CloseRedis()

	ctx := context.Background()

	// Test data
	type OAuthStateData struct {
		AppID       uuid.UUID `json:"app_id"`
		RedirectURI string    `json:"redirect_uri"`
	}

	stateKey := uuid.New().String()
	stateData := OAuthStateData{
		AppID:       uuid.New(),
		RedirectURI: "http://localhost:3000/callback",
	}

	// Save OAuth state with very short TTL
	fullKey := OAuthStatePrefix + stateKey
	err = SetJSON(ctx, fullKey, stateData, 1*time.Second)
	require.NoError(t, err)

	// Wait for expiration
	time.Sleep(2 * time.Second)

	// Try to get expired state
	var retrieved OAuthStateData
	err = GetOAuthState(ctx, stateKey, &retrieved)

	// Should get redis.Nil error
	assert.Error(t, err, "GetOAuthState should fail for expired state")
	assert.Equal(t, redis.Nil, err, "Should return redis.Nil error")
}

func TestOAuthState_SingleUse(t *testing.T) {
	// Setup
	CloseRedis()
	err := ConnectRedis()
	require.NoError(t, err)
	defer CloseRedis()

	ctx := context.Background()

	// Test data
	type OAuthStateData struct {
		AppID       uuid.UUID `json:"app_id"`
		RedirectURI string    `json:"redirect_uri"`
		CreatedAt   time.Time `json:"created_at"`
	}

	stateKey := uuid.New().String()
	stateData := OAuthStateData{
		AppID:       uuid.New(),
		RedirectURI: "http://localhost:3000/callback",
		CreatedAt:   time.Now(),
	}

	// Save OAuth state
	err = SaveOAuthState(ctx, stateKey, stateData)
	require.NoError(t, err)

	// First retrieval should work
	var retrieved1 OAuthStateData
	err = GetOAuthState(ctx, stateKey, &retrieved1)
	require.NoError(t, err, "First GetOAuthState should succeed")
	assert.Equal(t, stateData.AppID, retrieved1.AppID)

	// Second retrieval should fail (single use)
	var retrieved2 OAuthStateData
	err = GetOAuthState(ctx, stateKey, &retrieved2)
	assert.Error(t, err, "Second GetOAuthState should fail")
	assert.Equal(t, redis.Nil, err, "Error should be redis.Nil")
}

func TestOAuthState_MultipleStates(t *testing.T) {
	// Setup
	CloseRedis()
	err := ConnectRedis()
	require.NoError(t, err)
	defer CloseRedis()

	ctx := context.Background()

	// Test data
	type OAuthStateData struct {
		AppID       uuid.UUID `json:"app_id"`
		RedirectURI string    `json:"redirect_uri"`
		CreatedAt   time.Time `json:"created_at"`
	}

	// Create multiple states
	states := make(map[string]OAuthStateData)
	for i := 0; i < 5; i++ {
		stateKey := uuid.New().String()
		stateData := OAuthStateData{
			AppID:       uuid.New(),
			RedirectURI: "http://localhost:3000/callback",
			CreatedAt:   time.Now(),
		}
		states[stateKey] = stateData

		err := SaveOAuthState(ctx, stateKey, stateData)
		require.NoError(t, err, "SaveOAuthState should not return error")
	}

	// Verify all states can be retrieved
	for stateKey, expected := range states {
		var retrieved OAuthStateData
		err := GetOAuthState(ctx, stateKey, &retrieved)
		require.NoError(t, err, "GetOAuthState should not return error")
		assert.Equal(t, expected.AppID, retrieved.AppID, "AppID should match")
		assert.Equal(t, expected.RedirectURI, retrieved.RedirectURI, "RedirectURI should match")
	}

	// Verify all states are deleted after retrieval
	for stateKey := range states {
		fullKey := OAuthStatePrefix + stateKey
		exists, err := Exists(ctx, fullKey)
		require.NoError(t, err)
		assert.False(t, exists, "State should be deleted after retrieval")
	}
}

func TestOAuthState_ConcurrentAccess(t *testing.T) {
	// Setup
	CloseRedis()
	err := ConnectRedis()
	require.NoError(t, err)
	defer CloseRedis()

	ctx := context.Background()

	// Test data
	type OAuthStateData struct {
		AppID       uuid.UUID `json:"app_id"`
		RedirectURI string    `json:"redirect_uri"`
		CreatedAt   time.Time `json:"created_at"`
	}

	stateKey := uuid.New().String()
	stateData := OAuthStateData{
		AppID:       uuid.New(),
		RedirectURI: "http://localhost:3000/callback",
		CreatedAt:   time.Now(),
	}

	// Save state
	err = SaveOAuthState(ctx, stateKey, stateData)
	require.NoError(t, err)

	// Try to retrieve concurrently
	results := make(chan error, 3)

	for i := 0; i < 3; i++ {
		go func() {
			var retrieved OAuthStateData
			err := GetOAuthState(ctx, stateKey, &retrieved)
			results <- err
		}()
	}

	// Collect results
	var successCount, failCount int
	for i := 0; i < 3; i++ {
		err := <-results
		if err == nil {
			successCount++
		} else {
			failCount++
		}
	}

	// Only one should succeed (single use)
	assert.Equal(t, 1, successCount, "Only one concurrent access should succeed")
	assert.Equal(t, 2, failCount, "Other concurrent accesses should fail")
}

func TestCloseRedis(t *testing.T) {
	// Setup
	err := ConnectRedis()
	require.NoError(t, err)

	// Close connection
	CloseRedis()

	// Verify connection is closed by attempting to ping
	err = PingRedis()
	assert.Error(t, err, "Ping should fail after closing connection")
}

// Benchmark tests
func BenchmarkSetJSON(b *testing.B) {
	CloseRedis()
	err := ConnectRedis()
	if err != nil {
		b.Fatal(err)
	}
	defer CloseRedis()

	ctx := context.Background()

	type TestData struct {
		ID   uuid.UUID
		Name string
	}

	testData := TestData{
		ID:   uuid.New(),
		Name: "benchmark-test",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		key := "bench:json:" + uuid.New().String()
		SetJSON(ctx, key, testData, 10*time.Second)
	}
}

func BenchmarkGetJSON(b *testing.B) {
	CloseRedis()
	err := ConnectRedis()
	if err != nil {
		b.Fatal(err)
	}
	defer CloseRedis()

	ctx := context.Background()

	type TestData struct {
		ID   uuid.UUID
		Name string
	}

	testData := TestData{
		ID:   uuid.New(),
		Name: "benchmark-test",
	}

	// Pre-populate keys
	keys := make([]string, b.N)
	for i := 0; i < b.N; i++ {
		keys[i] = "bench:json:" + uuid.New().String()
		SetJSON(ctx, keys[i], testData, 10*time.Second)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var retrieved TestData
		GetJSON(ctx, keys[i], &retrieved)
	}
}
