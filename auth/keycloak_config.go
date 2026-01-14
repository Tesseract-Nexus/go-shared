package auth

import (
	"os"
	"strings"
	"time"
)

// KeycloakConfig holds configuration for Keycloak authentication
type KeycloakConfig struct {
	// Issuer URLs for different realms
	CustomerIssuer string `json:"customer_issuer"`
	InternalIssuer string `json:"internal_issuer"`

	// Legacy support (will be deprecated)
	LegacyIssuer string `json:"legacy_issuer"`
	LegacySecret string `json:"-"` // Never log secrets

	// JWKS Configuration
	JWKSCacheTTL       time.Duration `json:"jwks_cache_ttl"`
	JWKSRefreshTimeout time.Duration `json:"jwks_refresh_timeout"`

	// Token validation settings
	AllowedIssuers    []string      `json:"allowed_issuers"`
	ClockSkew         time.Duration `json:"clock_skew"`
	RequireExpiry     bool          `json:"require_expiry"`
	ValidateAudience  bool          `json:"validate_audience"`
	ExpectedAudiences []string      `json:"expected_audiences"`

	// Feature flags
	EnableLegacySupport bool `json:"enable_legacy_support"`
	StrictMode          bool `json:"strict_mode"`

	// Paths to skip authentication
	SkipPaths []string `json:"skip_paths"`

	// Metrics and logging
	EnableMetrics bool   `json:"enable_metrics"`
	LogLevel      string `json:"log_level"`
}

// DefaultKeycloakConfig returns a sensible default configuration
func DefaultKeycloakConfig() KeycloakConfig {
	return KeycloakConfig{
		CustomerIssuer: getEnvOrDefault("KEYCLOAK_CUSTOMER_ISSUER",
			"https://devtest-customer-idp.tesserix.app/realms/tesseract-customer"),
		InternalIssuer: getEnvOrDefault("KEYCLOAK_INTERNAL_ISSUER",
			"https://devtest-internal-idp.tesserix.app/realms/tesseract-internal"),
		LegacyIssuer: getEnvOrDefault("JWT_ISSUER", "tesseract-hub"),
		LegacySecret: os.Getenv("JWT_SECRET"),

		JWKSCacheTTL:       5 * time.Minute,
		JWKSRefreshTimeout: 10 * time.Second,

		ClockSkew:        30 * time.Second,
		RequireExpiry:    true,
		ValidateAudience: false,

		EnableLegacySupport: true, // Keep enabled during migration
		StrictMode:          false,

		SkipPaths: []string{
			"/health",
			"/ready",
			"/metrics",
			"/swagger",
		},

		EnableMetrics: true,
		LogLevel:      "info",
	}
}

// ProductionKeycloakConfig returns a hardened configuration for production
func ProductionKeycloakConfig() KeycloakConfig {
	config := DefaultKeycloakConfig()

	// Production issuer URLs
	config.CustomerIssuer = getEnvOrDefault("KEYCLOAK_CUSTOMER_ISSUER",
		"https://customer-idp.tesserix.app/realms/tesseract-customer")
	config.InternalIssuer = getEnvOrDefault("KEYCLOAK_INTERNAL_ISSUER",
		"https://internal-idp.tesserix.app/realms/tesseract-internal")

	// Stricter settings
	config.StrictMode = true
	config.ClockSkew = 10 * time.Second
	config.JWKSCacheTTL = 10 * time.Minute

	// Disable legacy after migration is complete
	config.EnableLegacySupport = getEnvOrDefault("ENABLE_LEGACY_AUTH", "false") == "true"

	return config
}

// StagingKeycloakConfig returns configuration for staging environment
func StagingKeycloakConfig() KeycloakConfig {
	config := DefaultKeycloakConfig()

	config.CustomerIssuer = getEnvOrDefault("KEYCLOAK_CUSTOMER_ISSUER",
		"https://staging-customer-idp.tesserix.app/realms/tesseract-customer")
	config.InternalIssuer = getEnvOrDefault("KEYCLOAK_INTERNAL_ISSUER",
		"https://staging-internal-idp.tesserix.app/realms/tesseract-internal")

	return config
}

// LoadKeycloakConfig loads configuration based on environment
func LoadKeycloakConfig() KeycloakConfig {
	env := strings.ToLower(os.Getenv("ENVIRONMENT"))

	var config KeycloakConfig
	switch env {
	case "production", "prod":
		config = ProductionKeycloakConfig()
	case "staging", "stage":
		config = StagingKeycloakConfig()
	default:
		config = DefaultKeycloakConfig()
	}

	// Build allowed issuers list
	config.AllowedIssuers = []string{
		config.CustomerIssuer,
		config.InternalIssuer,
	}
	if config.EnableLegacySupport && config.LegacyIssuer != "" {
		config.AllowedIssuers = append(config.AllowedIssuers, config.LegacyIssuer)
	}

	return config
}

// Validate checks if the configuration is valid
func (c *KeycloakConfig) Validate() error {
	if c.CustomerIssuer == "" && c.InternalIssuer == "" {
		return ErrNoIssuersConfigured
	}

	if c.EnableLegacySupport && c.LegacySecret == "" {
		return ErrLegacySecretRequired
	}

	if c.JWKSCacheTTL < time.Minute {
		return ErrInvalidCacheTTL
	}

	return nil
}

// IsSkipPath checks if a path should skip authentication
func (c *KeycloakConfig) IsSkipPath(path string) bool {
	for _, skipPath := range c.SkipPaths {
		if strings.HasPrefix(path, skipPath) {
			return true
		}
	}
	return false
}

// IsAllowedIssuer checks if an issuer is in the allowed list
func (c *KeycloakConfig) IsAllowedIssuer(issuer string) bool {
	for _, allowed := range c.AllowedIssuers {
		if issuer == allowed {
			return true
		}
	}
	return false
}

// IsLegacyIssuer checks if the issuer is the legacy issuer
func (c *KeycloakConfig) IsLegacyIssuer(issuer string) bool {
	return c.EnableLegacySupport && issuer == c.LegacyIssuer
}

// GetJWKSURL returns the JWKS URL for a given issuer
func (c *KeycloakConfig) GetJWKSURL(issuer string) string {
	if c.IsLegacyIssuer(issuer) {
		return "" // Legacy doesn't use JWKS
	}
	return issuer + "/protocol/openid-connect/certs"
}

func getEnvOrDefault(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}
