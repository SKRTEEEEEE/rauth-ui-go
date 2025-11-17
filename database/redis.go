package database

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/redis/go-redis/v9"
)

var RedisClient *redis.Client

// ConnectRedis establece conexión con Redis
func ConnectRedis() error {
	ctx := context.Background()

	// Obtener URL de Redis desde .env
	redisURL := os.Getenv("REDIS_URL")
	if redisURL == "" {
		return fmt.Errorf("REDIS_URL not set in environment")
	}

	// Parsear opciones desde URL
	opts, err := redis.ParseURL(redisURL)
	if err != nil {
		return fmt.Errorf("error parsing Redis URL: %w", err)
	}

	// Configurar timeouts
	opts.DialTimeout = 5 * time.Second
	opts.ReadTimeout = 3 * time.Second
	opts.WriteTimeout = 3 * time.Second
	opts.PoolSize = 10
	opts.MinIdleConns = 5

	// Crear cliente
	client := redis.NewClient(opts)

	// Verificar conexión
	if err := client.Ping(ctx).Err(); err != nil {
		return fmt.Errorf("error pinging Redis: %w", err)
	}

	RedisClient = client
	log.Println("✅ Connected to Redis")
	return nil
}

// CloseRedis cierra la conexión a Redis
func CloseRedis() {
	if RedisClient != nil {
		RedisClient.Close()
		log.Println("🔌 Redis connection closed")
	}
}

// PingRedis verifica que la conexión esté activa
func PingRedis() error {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	if RedisClient == nil {
		return fmt.Errorf("Redis not connected")
	}

	return RedisClient.Ping(ctx).Err()
}

// ============================================
// Helper functions para operaciones comunes
// ============================================

// SetJSON guarda un valor como JSON con TTL
func SetJSON(ctx context.Context, key string, value interface{}, ttl time.Duration) error {
	jsonData, err := json.Marshal(value)
	if err != nil {
		return fmt.Errorf("error marshaling to JSON: %w", err)
	}

	return RedisClient.Set(ctx, key, jsonData, ttl).Err()
}

// GetJSON obtiene un valor JSON y lo deserializa
func GetJSON(ctx context.Context, key string, dest interface{}) error {
	data, err := RedisClient.Get(ctx, key).Result()
	if err != nil {
		return err // redis.Nil si no existe
	}

	return json.Unmarshal([]byte(data), dest)
}

// SetString guarda un string simple con TTL
func SetString(ctx context.Context, key string, value string, ttl time.Duration) error {
	return RedisClient.Set(ctx, key, value, ttl).Err()
}

// GetString obtiene un string simple
func GetString(ctx context.Context, key string) (string, error) {
	return RedisClient.Get(ctx, key).Result()
}

// Delete elimina una o más keys
func Delete(ctx context.Context, keys ...string) error {
	return RedisClient.Del(ctx, keys...).Err()
}

// Exists verifica si una key existe
func Exists(ctx context.Context, key string) (bool, error) {
	result, err := RedisClient.Exists(ctx, key).Result()
	if err != nil {
		return false, err
	}
	return result > 0, nil
}

// SetTTL establece o actualiza el TTL de una key
func SetTTL(ctx context.Context, key string, ttl time.Duration) error {
	return RedisClient.Expire(ctx, key, ttl).Err()
}

// ============================================
// Funciones específicas para OAuth states
// ============================================

const (
	OAuthStatePrefix = "oauth:state:"
	OAuthStateTTL    = 5 * time.Minute
)

// SaveOAuthState guarda el estado de OAuth (5 min TTL)
func SaveOAuthState(ctx context.Context, state string, data interface{}) error {
	key := OAuthStatePrefix + state
	return SetJSON(ctx, key, data, OAuthStateTTL)
}

// GetOAuthState obtiene y elimina el estado de OAuth
func GetOAuthState(ctx context.Context, state string, dest interface{}) error {
	key := OAuthStatePrefix + state

	// Obtener el estado
	err := GetJSON(ctx, key, dest)
	if err != nil {
		return err
	}

	// Eliminar el estado (uso único)
	_ = Delete(ctx, key)

	return nil
}
