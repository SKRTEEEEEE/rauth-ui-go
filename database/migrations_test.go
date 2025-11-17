package database

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestDatabaseMigrations verifica que las migraciones se ejecuten correctamente
func TestDatabaseMigrations(t *testing.T) {
	// Conectar a la base de datos de prueba
	ctx := context.Background()

	// Usar DATABASE_URL del .env o variable de entorno
	databaseURL := os.Getenv("DATABASE_URL")
	if databaseURL == "" {
		t.Skip("DATABASE_URL no configurado, saltando test de integración")
	}

	pool, err := pgxpool.New(ctx, databaseURL)
	require.NoError(t, err, "Error al conectar a la base de datos")
	defer pool.Close()

	// Ejecutar migraciones usando el pool del test
	err = RunMigrationsWithPool(pool)
	require.NoError(t, err, "Error al ejecutar migraciones")

	// Verificar que todas las tablas existen
	t.Run("TablesExist", func(t *testing.T) {
		tables := []string{"applications", "oauth_providers", "users", "identities", "sessions"}
		for _, table := range tables {
			var exists bool
			err := pool.QueryRow(ctx,
				"SELECT EXISTS (SELECT FROM information_schema.tables WHERE table_name = $1)",
				table,
			).Scan(&exists)
			require.NoError(t, err)
			assert.True(t, exists, "Tabla %s no existe", table)
		}
	})

	// Verificar estructura de tabla applications
	t.Run("ApplicationsTableStructure", func(t *testing.T) {
		var count int
		err := pool.QueryRow(ctx, `
			SELECT COUNT(*) 
			FROM information_schema.columns 
			WHERE table_name = 'applications'
			AND column_name IN ('id', 'name', 'api_key', 'allowed_redirect_uris', 'cors_origins', 'created_at', 'updated_at')
		`).Scan(&count)
		require.NoError(t, err)
		assert.Equal(t, 7, count, "La tabla applications debe tener 7 columnas")
	})

	// Verificar estructura de tabla oauth_providers
	t.Run("OAuthProvidersTableStructure", func(t *testing.T) {
		var count int
		err := pool.QueryRow(ctx, `
			SELECT COUNT(*) 
			FROM information_schema.columns 
			WHERE table_name = 'oauth_providers'
			AND column_name IN ('id', 'app_id', 'provider', 'enabled', 'created_at', 'updated_at')
		`).Scan(&count)
		require.NoError(t, err)
		assert.Equal(t, 6, count, "La tabla oauth_providers debe tener 6 columnas")
	})

	// Verificar estructura de tabla users
	t.Run("UsersTableStructure", func(t *testing.T) {
		var count int
		err := pool.QueryRow(ctx, `
			SELECT COUNT(*) 
			FROM information_schema.columns 
			WHERE table_name = 'users'
			AND column_name IN ('id', 'app_id', 'email', 'name', 'avatar_url', 'email_verified', 'created_at', 'updated_at')
		`).Scan(&count)
		require.NoError(t, err)
		assert.Equal(t, 8, count, "La tabla users debe tener 8 columnas")
	})

	// Verificar estructura de tabla identities
	t.Run("IdentitiesTableStructure", func(t *testing.T) {
		var count int
		err := pool.QueryRow(ctx, `
			SELECT COUNT(*) 
			FROM information_schema.columns 
			WHERE table_name = 'identities'
			AND column_name IN ('id', 'user_id', 'provider', 'provider_user_id', 'provider_email', 'access_token', 'refresh_token', 'token_expires_at', 'created_at', 'updated_at')
		`).Scan(&count)
		require.NoError(t, err)
		assert.Equal(t, 10, count, "La tabla identities debe tener 10 columnas")
	})

	// Verificar estructura de tabla sessions
	t.Run("SessionsTableStructure", func(t *testing.T) {
		var count int
		err := pool.QueryRow(ctx, `
			SELECT COUNT(*) 
			FROM information_schema.columns 
			WHERE table_name = 'sessions'
			AND column_name IN ('id', 'user_id', 'app_id', 'token_hash', 'ip_address', 'user_agent', 'expires_at', 'created_at', 'last_used_at')
		`).Scan(&count)
		require.NoError(t, err)
		assert.Equal(t, 9, count, "La tabla sessions debe tener 9 columnas")
	})

	// Verificar índices
	t.Run("IndexesExist", func(t *testing.T) {
		indexes := []string{
			"idx_applications_api_key",
			"idx_oauth_providers_app_id",
			"idx_users_app_id",
			"idx_users_email",
			"idx_identities_user_id",
			"idx_identities_provider_user",
			"idx_sessions_user_id",
			"idx_sessions_token_hash",
			"idx_sessions_expires_at",
		}

		for _, idx := range indexes {
			var exists bool
			err := pool.QueryRow(ctx,
				"SELECT EXISTS (SELECT FROM pg_indexes WHERE indexname = $1)",
				idx,
			).Scan(&exists)
			require.NoError(t, err)
			assert.True(t, exists, "Índice %s no existe", idx)
		}
	})

	// Verificar triggers de updated_at
	t.Run("UpdatedAtTriggersExist", func(t *testing.T) {
		triggers := []string{
			"update_applications_updated_at",
			"update_oauth_providers_updated_at",
			"update_users_updated_at",
			"update_identities_updated_at",
		}

		for _, trigger := range triggers {
			var exists bool
			err := pool.QueryRow(ctx,
				"SELECT EXISTS (SELECT FROM pg_trigger WHERE tgname = $1)",
				trigger,
			).Scan(&exists)
			require.NoError(t, err)
			assert.True(t, exists, "Trigger %s no existe", trigger)
		}
	})
}

// TestForeignKeys verifica las relaciones entre tablas
func TestForeignKeys(t *testing.T) {
	ctx := context.Background()

	databaseURL := os.Getenv("DATABASE_URL")
	if databaseURL == "" {
		t.Skip("DATABASE_URL no configurado, saltando test de integración")
	}

	pool, err := pgxpool.New(ctx, databaseURL)
	require.NoError(t, err)
	defer pool.Close()

	// Primero ejecutar migraciones usando el pool del test
	err = RunMigrationsWithPool(pool)
	require.NoError(t, err)

	t.Run("CascadeDeleteApplications", func(t *testing.T) {
		// Insertar aplicación de prueba
		var appID string
		err := pool.QueryRow(ctx, `
			INSERT INTO applications (name, api_key, allowed_redirect_uris, cors_origins)
			VALUES ($1, $2, $3, $4)
			RETURNING id
		`, "Test Cascade App", "test-cascade-key", []string{"http://localhost"}, []string{"http://localhost"}).Scan(&appID)
		require.NoError(t, err)

		// Insertar oauth_provider asociado
		_, err = pool.Exec(ctx, `
			INSERT INTO oauth_providers (app_id, provider, enabled)
			VALUES ($1, 'google', true)
		`, appID)
		require.NoError(t, err)

		// Verificar que el provider existe
		var count int
		err = pool.QueryRow(ctx, "SELECT COUNT(*) FROM oauth_providers WHERE app_id = $1", appID).Scan(&count)
		require.NoError(t, err)
		assert.Equal(t, 1, count)

		// Eliminar la aplicación
		_, err = pool.Exec(ctx, "DELETE FROM applications WHERE id = $1", appID)
		require.NoError(t, err)

		// Verificar que el provider fue eliminado (CASCADE)
		err = pool.QueryRow(ctx, "SELECT COUNT(*) FROM oauth_providers WHERE app_id = $1", appID).Scan(&count)
		require.NoError(t, err)
		assert.Equal(t, 0, count, "El provider debería haberse eliminado en cascada")
	})

	t.Run("CascadeDeleteUsers", func(t *testing.T) {
		// Insertar aplicación y usuario
		var appID, userID string
		err := pool.QueryRow(ctx, `
			INSERT INTO applications (name, api_key)
			VALUES ($1, $2)
			RETURNING id
		`, "Test User Cascade", "test-user-cascade-key").Scan(&appID)
		require.NoError(t, err)

		err = pool.QueryRow(ctx, `
			INSERT INTO users (app_id, email, name)
			VALUES ($1, $2, $3)
			RETURNING id
		`, appID, "test@example.com", "Test User").Scan(&userID)
		require.NoError(t, err)

		// Insertar identity asociada
		_, err = pool.Exec(ctx, `
			INSERT INTO identities (user_id, provider, provider_user_id, provider_email)
			VALUES ($1, 'google', '12345', 'test@gmail.com')
		`, userID)
		require.NoError(t, err)

		// Insertar session asociada
		_, err = pool.Exec(ctx, `
			INSERT INTO sessions (user_id, app_id, token_hash, expires_at)
			VALUES ($1, $2, 'test-hash', $3)
		`, userID, appID, time.Now().Add(24*time.Hour))
		require.NoError(t, err)

		// Verificar que identity y session existen
		var identityCount, sessionCount int
		err = pool.QueryRow(ctx, "SELECT COUNT(*) FROM identities WHERE user_id = $1", userID).Scan(&identityCount)
		require.NoError(t, err)
		assert.Equal(t, 1, identityCount)

		err = pool.QueryRow(ctx, "SELECT COUNT(*) FROM sessions WHERE user_id = $1", userID).Scan(&sessionCount)
		require.NoError(t, err)
		assert.Equal(t, 1, sessionCount)

		// Eliminar el usuario
		_, err = pool.Exec(ctx, "DELETE FROM users WHERE id = $1", userID)
		require.NoError(t, err)

		// Verificar CASCADE
		err = pool.QueryRow(ctx, "SELECT COUNT(*) FROM identities WHERE user_id = $1", userID).Scan(&identityCount)
		require.NoError(t, err)
		assert.Equal(t, 0, identityCount, "Las identities deberían haberse eliminado en cascada")

		err = pool.QueryRow(ctx, "SELECT COUNT(*) FROM sessions WHERE user_id = $1", userID).Scan(&sessionCount)
		require.NoError(t, err)
		assert.Equal(t, 0, sessionCount, "Las sessions deberían haberse eliminado en cascada")
	})
}

// TestUniqueConstraints verifica las restricciones de unicidad
func TestUniqueConstraints(t *testing.T) {
	ctx := context.Background()

	databaseURL := os.Getenv("DATABASE_URL")
	if databaseURL == "" {
		t.Skip("DATABASE_URL no configurado, saltando test de integración")
	}

	pool, err := pgxpool.New(ctx, databaseURL)
	require.NoError(t, err)
	defer pool.Close()

	err = RunMigrationsWithPool(pool)
	require.NoError(t, err)

	t.Run("UniqueAPIKey", func(t *testing.T) {
		// Insertar primera aplicación
		_, err := pool.Exec(ctx, `
			INSERT INTO applications (name, api_key)
			VALUES ('App 1', 'unique-api-key-123')
		`)
		require.NoError(t, err)

		// Intentar insertar segunda con mismo api_key (debe fallar)
		_, err = pool.Exec(ctx, `
			INSERT INTO applications (name, api_key)
			VALUES ('App 2', 'unique-api-key-123')
		`)
		assert.Error(t, err, "Debería fallar por api_key duplicado")
	})

	t.Run("UniqueAppProvider", func(t *testing.T) {
		var appID string
		err := pool.QueryRow(ctx, `
			INSERT INTO applications (name, api_key)
			VALUES ('App OAuth Test', 'oauth-test-key')
			RETURNING id
		`).Scan(&appID)
		require.NoError(t, err)

		// Insertar provider
		_, err = pool.Exec(ctx, `
			INSERT INTO oauth_providers (app_id, provider, enabled)
			VALUES ($1, 'google', true)
		`, appID)
		require.NoError(t, err)

		// Intentar insertar mismo provider para misma app (debe fallar)
		_, err = pool.Exec(ctx, `
			INSERT INTO oauth_providers (app_id, provider, enabled)
			VALUES ($1, 'google', false)
		`, appID)
		assert.Error(t, err, "Debería fallar por combinación app_id+provider duplicada")
	})

	t.Run("UniqueUserProvider", func(t *testing.T) {
		var appID, userID string
		err := pool.QueryRow(ctx, `
			INSERT INTO applications (name, api_key)
			VALUES ('App Identity Test', 'identity-test-key')
			RETURNING id
		`).Scan(&appID)
		require.NoError(t, err)

		err = pool.QueryRow(ctx, `
			INSERT INTO users (app_id, email, name)
			VALUES ($1, 'user@test.com', 'Test')
			RETURNING id
		`, appID).Scan(&userID)
		require.NoError(t, err)

		// Insertar identity
		_, err = pool.Exec(ctx, `
			INSERT INTO identities (user_id, provider, provider_user_id)
			VALUES ($1, 'github', '67890')
		`, userID)
		require.NoError(t, err)

		// Intentar insertar misma combinación user_id+provider (debe fallar)
		_, err = pool.Exec(ctx, `
			INSERT INTO identities (user_id, provider, provider_user_id)
			VALUES ($1, 'github', '99999')
		`, userID)
		assert.Error(t, err, "Debería fallar por user_id+provider duplicado")
	})
}

// TestCheckConstraints verifica las restricciones CHECK
func TestCheckConstraints(t *testing.T) {
	ctx := context.Background()

	databaseURL := os.Getenv("DATABASE_URL")
	if databaseURL == "" {
		t.Skip("DATABASE_URL no configurado, saltando test de integración")
	}

	pool, err := pgxpool.New(ctx, databaseURL)
	require.NoError(t, err)
	defer pool.Close()

	err = RunMigrationsWithPool(pool)
	require.NoError(t, err)

	t.Run("InvalidOAuthProvider", func(t *testing.T) {
		var appID string
		err := pool.QueryRow(ctx, `
			INSERT INTO applications (name, api_key)
			VALUES ('App Check Test', 'check-test-key')
			RETURNING id
		`).Scan(&appID)
		require.NoError(t, err)

		// Intentar insertar provider inválido
		_, err = pool.Exec(ctx, `
			INSERT INTO oauth_providers (app_id, provider, enabled)
			VALUES ($1, 'invalid_provider', true)
		`, appID)
		assert.Error(t, err, "Debería fallar por provider inválido")
	})

	t.Run("ValidOAuthProviders", func(t *testing.T) {
		var appID string
		err := pool.QueryRow(ctx, `
			INSERT INTO applications (name, api_key)
			VALUES ('App Valid Providers', 'valid-providers-key')
			RETURNING id
		`).Scan(&appID)
		require.NoError(t, err)

		validProviders := []string{"google", "github", "facebook", "microsoft"}
		for _, provider := range validProviders {
			_, err = pool.Exec(ctx, `
				INSERT INTO oauth_providers (app_id, provider, enabled)
				VALUES ($1, $2, true)
			`, appID, provider)
			assert.NoError(t, err, "Provider %s debería ser válido", provider)
		}
	})
}

// TestUpdatedAtTrigger verifica que el trigger de updated_at funciona
func TestUpdatedAtTrigger(t *testing.T) {
	ctx := context.Background()

	databaseURL := os.Getenv("DATABASE_URL")
	if databaseURL == "" {
		t.Skip("DATABASE_URL no configurado, saltando test de integración")
	}

	pool, err := pgxpool.New(ctx, databaseURL)
	require.NoError(t, err)
	defer pool.Close()

	err = RunMigrationsWithPool(pool)
	require.NoError(t, err)

	t.Run("ApplicationUpdatedAt", func(t *testing.T) {
		var appID string
		var createdAt, updatedAt time.Time

		// Insertar aplicación
		err := pool.QueryRow(ctx, `
			INSERT INTO applications (name, api_key)
			VALUES ('Trigger Test App', 'trigger-test-key')
			RETURNING id, created_at, updated_at
		`).Scan(&appID, &createdAt, &updatedAt)
		require.NoError(t, err)

		// created_at y updated_at deben ser iguales inicialmente
		assert.True(t, createdAt.Equal(updatedAt) || createdAt.Sub(updatedAt) < time.Second)

		// Esperar un poco
		time.Sleep(1 * time.Second)

		// Actualizar
		_, err = pool.Exec(ctx, `
			UPDATE applications 
			SET name = 'Updated Name' 
			WHERE id = $1
		`, appID)
		require.NoError(t, err)

		// Verificar que updated_at cambió
		var newUpdatedAt time.Time
		err = pool.QueryRow(ctx, `
			SELECT updated_at FROM applications WHERE id = $1
		`, appID).Scan(&newUpdatedAt)
		require.NoError(t, err)

		assert.True(t, newUpdatedAt.After(updatedAt), "updated_at debería haber cambiado")
	})
}
