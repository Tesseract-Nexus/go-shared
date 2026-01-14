package secrets

import (
	"context"
	"fmt"
	"log"
	"os"
	"sync"
	"time"

	secretmanager "cloud.google.com/go/secretmanager/apiv1"
	"cloud.google.com/go/secretmanager/apiv1/secretmanagerpb"
)

var (
	// Global secret fetcher instance (lazy initialized)
	globalFetcher     *EnvSecretFetcher
	globalFetcherOnce sync.Once
	globalFetcherErr  error
)

// getGlobalFetcher returns a singleton secret fetcher instance
func getGlobalFetcher() (*EnvSecretFetcher, error) {
	globalFetcherOnce.Do(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		globalFetcher, globalFetcherErr = NewEnvSecretFetcher(ctx)
	})
	return globalFetcher, globalFetcherErr
}

// GetDBPassword is a simple drop-in function to get database password.
// It checks GCP Secret Manager first (if enabled), then falls back to DB_PASSWORD env var.
// Usage: password := secrets.GetDBPassword()
func GetDBPassword() string {
	return GetSecretOrEnv("DB_PASSWORD_SECRET_NAME", "DB_PASSWORD", "password")
}

// GetJWTSecret is a simple drop-in function to get JWT secret.
// It checks GCP Secret Manager first (if enabled), then falls back to JWT_SECRET env var.
// Usage: secret := secrets.GetJWTSecret()
func GetJWTSecret() string {
	return GetSecretOrEnv("JWT_SECRET_NAME", "JWT_SECRET", "default-jwt-secret")
}

// GetRedisPassword is a simple drop-in function to get Redis password.
// It checks GCP Secret Manager first (if enabled), then falls back to REDIS_PASSWORD env var.
// Usage: password := secrets.GetRedisPassword()
func GetRedisPassword() string {
	return GetSecretOrEnv("REDIS_PASSWORD_SECRET_NAME", "REDIS_PASSWORD", "")
}

// GetAPIKey is a simple drop-in function to get API key for inter-service authentication.
// It checks GCP Secret Manager first (if enabled), then falls back to API_KEY env var.
// Usage: key := secrets.GetAPIKey()
func GetAPIKey() string {
	return GetSecretOrEnv("API_KEY_SECRET_NAME", "API_KEY", "")
}

// GetEncryptionKey is a simple drop-in function to get encryption key.
// It checks GCP Secret Manager first (if enabled), then falls back to ENCRYPTION_KEY env var.
// Usage: key := secrets.GetEncryptionKey()
func GetEncryptionKey() string {
	return GetSecretOrEnv("ENCRYPTION_KEY_SECRET_NAME", "ENCRYPTION_KEY", "")
}

// GetSecretOrEnv tries to get a secret from GCP Secret Manager using the secret name
// from secretNameEnvVar, and falls back to the direct environment variable if GCP
// Secret Manager is not available or the secret name is not set.
//
// Example:
//   password := secrets.GetSecretOrEnv("DB_PASSWORD_SECRET_NAME", "DB_PASSWORD", "default")
//
// If USE_GCP_SECRET_MANAGER=true and DB_PASSWORD_SECRET_NAME is set,
// it fetches the secret from GCP. Otherwise, it uses DB_PASSWORD env var.
func GetSecretOrEnv(secretNameEnvVar, fallbackEnvVar, defaultValue string) string {
	useGCP := os.Getenv("USE_GCP_SECRET_MANAGER")
	if useGCP != "true" {
		// GCP Secret Manager disabled, use env var directly
		if value := os.Getenv(fallbackEnvVar); value != "" {
			return value
		}
		return defaultValue
	}

	// Try to get from GCP Secret Manager
	secretName := os.Getenv(secretNameEnvVar)
	if secretName == "" {
		// No secret name configured, fall back to env var
		if value := os.Getenv(fallbackEnvVar); value != "" {
			return value
		}
		return defaultValue
	}

	// Get the global fetcher
	fetcher, err := getGlobalFetcher()
	if err != nil {
		log.Printf("Warning: GCP Secret Manager error: %v, using env var %s", err, fallbackEnvVar)
		if value := os.Getenv(fallbackEnvVar); value != "" {
			return value
		}
		return defaultValue
	}

	if fetcher == nil {
		// Fetcher is nil (GCP disabled), use env var
		if value := os.Getenv(fallbackEnvVar); value != "" {
			return value
		}
		return defaultValue
	}

	// Fetch the secret
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	value, err := fetcher.getSecretDirect(ctx, secretName)
	if err != nil {
		log.Printf("Warning: Failed to get secret %s from GCP: %v, using env var %s", secretName, err, fallbackEnvVar)
		if value := os.Getenv(fallbackEnvVar); value != "" {
			return value
		}
		return defaultValue
	}

	log.Printf("✓ Secret %s loaded from GCP Secret Manager", secretName)
	return value
}

// MustGetSecret fetches a secret from GCP Secret Manager or panics.
// Use this for critical secrets that must exist.
func MustGetSecret(secretName string) string {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	projectID := os.Getenv("GCP_PROJECT_ID")
	if projectID == "" {
		log.Fatalf("GCP_PROJECT_ID is required for MustGetSecret")
	}

	client, err := secretmanager.NewClient(ctx)
	if err != nil {
		log.Fatalf("Failed to create secret manager client: %v", err)
	}
	defer client.Close()

	secretPath := fmt.Sprintf("projects/%s/secrets/%s/versions/latest", projectID, secretName)
	req := &secretmanagerpb.AccessSecretVersionRequest{
		Name: secretPath,
	}

	result, err := client.AccessSecretVersion(ctx, req)
	if err != nil {
		log.Fatalf("Failed to access secret %s: %v", secretName, err)
	}

	return string(result.Payload.Data)
}
