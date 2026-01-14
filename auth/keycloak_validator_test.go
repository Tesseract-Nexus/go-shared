package auth

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/sirupsen/logrus"
)

func createTestLogger() *logrus.Logger {
	logger := logrus.New()
	logger.SetLevel(logrus.DebugLevel)
	return logger
}

func createTestConfig() KeycloakConfig {
	return KeycloakConfig{
		CustomerIssuer:      "https://test-customer.example.com/realms/test",
		InternalIssuer:      "https://test-internal.example.com/realms/test",
		LegacyIssuer:        "tesseract-hub",
		LegacySecret:        "test-secret-key-for-testing-12345",
		JWKSCacheTTL:        5 * time.Minute,
		JWKSRefreshTimeout:  5 * time.Second,
		ClockSkew:           30 * time.Second,
		RequireExpiry:       true,
		EnableLegacySupport: true,
		AllowedIssuers: []string{
			"https://test-customer.example.com/realms/test",
			"https://test-internal.example.com/realms/test",
			"tesseract-hub",
		},
	}
}

func TestNewKeycloakValidator(t *testing.T) {
	logger := createTestLogger()
	config := createTestConfig()

	validator, err := NewKeycloakValidator(config, logger)
	if err != nil {
		t.Fatalf("Failed to create validator: %v", err)
	}

	if validator == nil {
		t.Fatal("Validator should not be nil")
	}
}

func TestNewKeycloakValidatorInvalidConfig(t *testing.T) {
	logger := createTestLogger()

	// Test with no issuers
	config := KeycloakConfig{}
	_, err := NewKeycloakValidator(config, logger)
	if err == nil {
		t.Fatal("Expected error for invalid config")
	}

	// Test with legacy enabled but no secret
	config = KeycloakConfig{
		CustomerIssuer:      "https://test.example.com/realms/test",
		EnableLegacySupport: true,
		LegacySecret:        "",
		JWKSCacheTTL:        5 * time.Minute,
	}
	_, err = NewKeycloakValidator(config, logger)
	if err == nil {
		t.Fatal("Expected error for legacy enabled without secret")
	}
}

func TestValidateLegacyToken(t *testing.T) {
	logger := createTestLogger()
	config := createTestConfig()

	validator, err := NewKeycloakValidator(config, logger)
	if err != nil {
		t.Fatalf("Failed to create validator: %v", err)
	}

	// Create a valid legacy token
	claims := &KeycloakClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   "user-123",
			Issuer:    "tesseract-hub",
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
		Email:    "test@example.com",
		TenantID: "tenant-123",
		Roles:    []string{"admin", "user"},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString([]byte(config.LegacySecret))
	if err != nil {
		t.Fatalf("Failed to sign token: %v", err)
	}

	// Validate the token
	ctx := context.Background()
	validatedClaims, err := validator.ValidateToken(ctx, tokenString)
	if err != nil {
		t.Fatalf("Token validation failed: %v", err)
	}

	if validatedClaims.GetUserID() != "user-123" {
		t.Errorf("Expected user ID 'user-123', got '%s'", validatedClaims.GetUserID())
	}

	if validatedClaims.Email != "test@example.com" {
		t.Errorf("Expected email 'test@example.com', got '%s'", validatedClaims.Email)
	}

	if validatedClaims.TenantID != "tenant-123" {
		t.Errorf("Expected tenant ID 'tenant-123', got '%s'", validatedClaims.TenantID)
	}
}

func TestValidateLegacyTokenExpired(t *testing.T) {
	logger := createTestLogger()
	config := createTestConfig()

	validator, err := NewKeycloakValidator(config, logger)
	if err != nil {
		t.Fatalf("Failed to create validator: %v", err)
	}

	// Create an expired token
	claims := &KeycloakClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   "user-123",
			Issuer:    "tesseract-hub",
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(-time.Hour)), // Expired
			IssuedAt:  jwt.NewNumericDate(time.Now().Add(-2 * time.Hour)),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString([]byte(config.LegacySecret))
	if err != nil {
		t.Fatalf("Failed to sign token: %v", err)
	}

	ctx := context.Background()
	_, err = validator.ValidateToken(ctx, tokenString)
	if err == nil {
		t.Fatal("Expected error for expired token")
	}

	if !IsTokenExpiredError(err) {
		t.Errorf("Expected token expired error, got: %v", err)
	}
}

func TestValidateLegacyTokenInvalidSignature(t *testing.T) {
	logger := createTestLogger()
	config := createTestConfig()

	validator, err := NewKeycloakValidator(config, logger)
	if err != nil {
		t.Fatalf("Failed to create validator: %v", err)
	}

	// Create a token with wrong secret
	claims := &KeycloakClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   "user-123",
			Issuer:    "tesseract-hub",
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString([]byte("wrong-secret"))
	if err != nil {
		t.Fatalf("Failed to sign token: %v", err)
	}

	ctx := context.Background()
	_, err = validator.ValidateToken(ctx, tokenString)
	if err == nil {
		t.Fatal("Expected error for invalid signature")
	}
}

func TestValidateTokenInvalidIssuer(t *testing.T) {
	logger := createTestLogger()
	config := createTestConfig()

	validator, err := NewKeycloakValidator(config, logger)
	if err != nil {
		t.Fatalf("Failed to create validator: %v", err)
	}

	// Create a token with invalid issuer
	claims := &KeycloakClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   "user-123",
			Issuer:    "invalid-issuer",
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString([]byte(config.LegacySecret))
	if err != nil {
		t.Fatalf("Failed to sign token: %v", err)
	}

	ctx := context.Background()
	_, err = validator.ValidateToken(ctx, tokenString)
	if err == nil {
		t.Fatal("Expected error for invalid issuer")
	}

	code := GetErrorCode(err)
	if code != "TOKEN_INVALID_ISSUER" {
		t.Errorf("Expected TOKEN_INVALID_ISSUER, got %s", code)
	}
}

func TestValidateMalformedToken(t *testing.T) {
	logger := createTestLogger()
	config := createTestConfig()

	validator, err := NewKeycloakValidator(config, logger)
	if err != nil {
		t.Fatalf("Failed to create validator: %v", err)
	}

	ctx := context.Background()

	// Test with completely invalid token
	_, err = validator.ValidateToken(ctx, "not.a.valid.token")
	if err == nil {
		t.Fatal("Expected error for malformed token")
	}

	// Test with empty token
	_, err = validator.ValidateToken(ctx, "")
	if err == nil {
		t.Fatal("Expected error for empty token")
	}
}

func TestValidateWithPublicKey(t *testing.T) {
	logger := createTestLogger()
	config := createTestConfig()

	validator, err := NewKeycloakValidator(config, logger)
	if err != nil {
		t.Fatalf("Failed to create validator: %v", err)
	}

	// Generate RSA key pair
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}

	// Create RS256 token
	claims := &KeycloakClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   "user-456",
			Issuer:    "https://test-customer.example.com/realms/test",
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
		Email:    "keycloak@example.com",
		TenantID: "tenant-456",
		RealmAccess: RealmAccess{
			Roles: []string{"admin", "staff"},
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tokenString, err := token.SignedString(privateKey)
	if err != nil {
		t.Fatalf("Failed to sign token: %v", err)
	}

	// Validate with public key
	validatedClaims, err := validator.ValidateWithPublicKey(tokenString, &privateKey.PublicKey)
	if err != nil {
		t.Fatalf("Token validation failed: %v", err)
	}

	if validatedClaims.GetUserID() != "user-456" {
		t.Errorf("Expected user ID 'user-456', got '%s'", validatedClaims.GetUserID())
	}

	if !validatedClaims.HasRole("admin") {
		t.Error("Expected user to have admin role")
	}
}

func TestValidatorStats(t *testing.T) {
	logger := createTestLogger()
	config := createTestConfig()

	validator, err := NewKeycloakValidator(config, logger)
	if err != nil {
		t.Fatalf("Failed to create validator: %v", err)
	}

	// Create a valid token
	claims := &KeycloakClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   "user-123",
			Issuer:    "tesseract-hub",
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, _ := token.SignedString([]byte(config.LegacySecret))

	ctx := context.Background()

	// Validate a few tokens
	for i := 0; i < 5; i++ {
		validator.ValidateToken(ctx, tokenString)
	}

	stats := validator.Stats()

	validationTotal, ok := stats["validation_total"].(int64)
	if !ok || validationTotal != 5 {
		t.Errorf("Expected validation_total to be 5, got %v", stats["validation_total"])
	}

	legacyTokens, ok := stats["legacy_tokens"].(int64)
	if !ok || legacyTokens != 5 {
		t.Errorf("Expected legacy_tokens to be 5, got %v", stats["legacy_tokens"])
	}
}

func TestLegacySupportDisabled(t *testing.T) {
	logger := createTestLogger()
	config := createTestConfig()
	config.EnableLegacySupport = false

	validator, err := NewKeycloakValidator(config, logger)
	if err != nil {
		t.Fatalf("Failed to create validator: %v", err)
	}

	// Create a legacy token
	claims := &KeycloakClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   "user-123",
			Issuer:    "tesseract-hub",
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, _ := token.SignedString([]byte(config.LegacySecret))

	ctx := context.Background()
	_, err = validator.ValidateToken(ctx, tokenString)
	if err == nil {
		t.Fatal("Expected error when legacy support is disabled")
	}
}
