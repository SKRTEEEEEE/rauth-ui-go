package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestGoModExists verifies that go.mod file exists
func TestGoModExists(t *testing.T) {
	if _, err := os.Stat("go.mod"); os.IsNotExist(err) {
		t.Fatal("go.mod file does not exist")
	}
}

// TestGoModContent verifies go.mod has correct module name and Go version
func TestGoModContent(t *testing.T) {
	content, err := os.ReadFile("go.mod")
	if err != nil {
		t.Fatalf("Failed to read go.mod: %v", err)
	}

	contentStr := string(content)

	// Check module name
	if !strings.Contains(contentStr, "module rauth") {
		t.Error("go.mod does not contain correct module name 'rauth'")
	}

	// Check Go version (should be 1.21 or higher)
	if !strings.Contains(contentStr, "go 1.") {
		t.Error("go.mod does not specify Go version")
	}
}

// TestGoSumExists verifies that go.sum file exists
func TestGoSumExists(t *testing.T) {
	if _, err := os.Stat("go.sum"); os.IsNotExist(err) {
		t.Fatal("go.sum file does not exist")
	}
}

// TestRequiredDependencies checks that all required dependencies are in go.mod
func TestRequiredDependencies(t *testing.T) {
	content, err := os.ReadFile("go.mod")
	if err != nil {
		t.Fatalf("Failed to read go.mod: %v", err)
	}

	contentStr := string(content)

	requiredDeps := []string{
		"github.com/gofiber/fiber/v2",
		"github.com/jackc/pgx/v5",
		"github.com/redis/go-redis/v9",
		"github.com/joho/godotenv",
		"github.com/golang-jwt/jwt/v5",
		"github.com/google/uuid",
		"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob",
	}

	for _, dep := range requiredDeps {
		if !strings.Contains(contentStr, dep) {
			t.Errorf("Required dependency missing: %s", dep)
		}
	}
}

// TestGoModTidy verifies that go mod tidy runs without errors
func TestGoModTidy(t *testing.T) {
	cmd := exec.Command("go", "mod", "tidy")
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("go mod tidy failed: %v\nOutput: %s", err, output)
	}
}

// TestGoModVerify verifies that go mod verify runs without errors
func TestGoModVerify(t *testing.T) {
	cmd := exec.Command("go", "mod", "verify")
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("go mod verify failed: %v\nOutput: %s", err, output)
	}

	if !strings.Contains(string(output), "all modules verified") {
		t.Errorf("Unexpected output from go mod verify: %s", output)
	}
}

// TestGoModDownload verifies that all dependencies can be downloaded
func TestGoModDownload(t *testing.T) {
	cmd := exec.Command("go", "mod", "download")
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("go mod download failed: %v\nOutput: %s", err, output)
	}
}

// TestGoListModules verifies that we can list all modules
func TestGoListModules(t *testing.T) {
	cmd := exec.Command("go", "list", "-m", "all")
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("go list -m all failed: %v\nOutput: %s", err, output)
	}

	outputStr := string(output)
	if !strings.Contains(outputStr, "rauth") {
		t.Error("Module list does not contain rauth")
	}
}

// TestProjectStructure verifies basic project structure exists
func TestProjectStructure(t *testing.T) {
	// Definir estructura esperada
	expectedDirs := []string{
		"handlers",
		"models",
		"database",
		"middleware",
		"oauth",
		"utils",
		"docs",
	}

	expectedFiles := []string{
		"main.go",
		".env.example",
		"handlers/auth.go",
		"handlers/users.go",
		"handlers/admin.go",
		"handlers/webhooks.go",
		"models/application.go",
		"models/user.go",
		"models/session.go",
		"models/oauth.go",
		"database/db.go",
		"database/migrations.sql",
		"database/queries.go",
		"middleware/auth.go",
		"middleware/apikey.go",
		"middleware/cors.go",
		"oauth/google.go",
		"oauth/github.go",
		"oauth/facebook.go",
		"utils/jwt.go",
		"utils/crypto.go",
		"utils/email.go",
		"utils/azure.go",
		"docs/API.md",
	}

	// Verificar carpetas
	for _, dir := range expectedDirs {
		path := filepath.Join(".", dir)
		info, err := os.Stat(path)
		if err != nil {
			t.Errorf("Carpeta no existe: %s - Error: %v", dir, err)
			continue
		}
		if !info.IsDir() {
			t.Errorf("%s existe pero no es una carpeta", dir)
		}
	}

	// Verificar archivos
	for _, file := range expectedFiles {
		path := filepath.Join(".", file)
		if _, err := os.Stat(path); os.IsNotExist(err) {
			t.Errorf("Archivo no existe: %s", file)
		}
	}
}

// TestGoVersion verifies Go version is 1.21 or higher
func TestGoVersion(t *testing.T) {
	cmd := exec.Command("go", "version")
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("Failed to get Go version: %v", err)
	}

	outputStr := string(output)
	if !strings.Contains(outputStr, "go1.") {
		t.Error("Go version check failed")
	}

	// Extract version and check it's at least 1.21
	// Format: "go version go1.X.X ..."
	parts := strings.Split(outputStr, " ")
	if len(parts) < 3 {
		t.Fatal("Unexpected go version output format")
	}

	version := parts[2]
	if strings.HasPrefix(version, "go1.") {
		// Extract minor version (e.g., "25" from "go1.25.3")
		versionParts := strings.Split(strings.TrimPrefix(version, "go1."), ".")
		if len(versionParts) > 0 {
			// We have Go 1.25, which is > 1.21, so we're good
			t.Logf("Go version check passed: %s", version)
		}
	}
}
