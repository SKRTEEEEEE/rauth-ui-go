package database

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/jackc/pgx/v5/pgxpool"
)

// RunMigrations ejecuta el archivo migrations.sql usando la conexión global DB
func RunMigrations() error {
	return RunMigrationsWithPool(DB)
}

// RunMigrationsWithPool ejecuta el archivo migrations.sql usando una pool específica
func RunMigrationsWithPool(pool *pgxpool.Pool) error {
	ctx := context.Background()

	if pool == nil {
		return fmt.Errorf("database pool is nil")
	}

	// Leer archivo de migraciones
	sqlBytes, err := readMigrationsFile()
	if err != nil {
		return err
	}

	// Ejecutar SQL
	_, err = pool.Exec(ctx, string(sqlBytes))
	if err != nil {
		return fmt.Errorf("error executing migrations: %w", err)
	}

	return nil
}

// readMigrationsFile intenta leer el archivo migrations.sql desde varias ubicaciones
func readMigrationsFile() ([]byte, error) {
	// Intentar leer desde la ruta relativa primero
	sqlBytes, err := os.ReadFile("database/migrations.sql")
	if err != nil {
		// Si falla, intentar desde el directorio actual (para tests)
		wd, _ := os.Getwd()
		migrationsPath := filepath.Join(wd, "..", "database", "migrations.sql")
		sqlBytes, err = os.ReadFile(migrationsPath)
		if err != nil {
			// Último intento: ruta absoluta desde la raíz del proyecto
			migrationsPath = filepath.Join(wd, "database", "migrations.sql")
			sqlBytes, err = os.ReadFile(migrationsPath)
			if err != nil {
				return nil, fmt.Errorf("error reading migrations file: %w", err)
			}
		}
	}
	return sqlBytes, nil
}
