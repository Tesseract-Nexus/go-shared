package auth

import (
	"context"
	"crypto/rsa"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/sirupsen/logrus"
)

// KeycloakValidator validates JWT tokens from Keycloak
type KeycloakValidator struct {
	config    KeycloakConfig
	jwksCache *JWKSCache
	logger    *logrus.Entry

	// Metrics
	mu               sync.RWMutex
	validationTotal  int64
	validationOK     int64
	validationFailed int64
	legacyTokens     int64
	keycloakTokens   int64
}

// NewKeycloakValidator creates a new Keycloak token validator
func NewKeycloakValidator(config KeycloakConfig, logger *logrus.Logger) (*KeycloakValidator, error) {
	if err := config.Validate(); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}

	validator := &KeycloakValidator{
		config:    config,
		jwksCache: NewJWKSCache(config, logger),
		logger:    logger.WithField("component", "keycloak_validator"),
	}

	return validator, nil
}

// PreWarm warms up the JWKS cache
func (v *KeycloakValidator) PreWarm(ctx context.Context) error {
	return v.jwksCache.PreWarm(ctx)
}

// ValidateToken validates a JWT token and returns claims
func (v *KeycloakValidator) ValidateToken(ctx context.Context, tokenString string) (*KeycloakClaims, error) {
	v.mu.Lock()
	v.validationTotal++
	v.mu.Unlock()

	// Parse token without validation to get header and claims
	parser := jwt.NewParser(jwt.WithoutClaimsValidation())
	token, _, err := parser.ParseUnverified(tokenString, &KeycloakClaims{})
	if err != nil {
		v.recordFailure()
		return nil, NewTokenMalformedError(err)
	}

	claims, ok := token.Claims.(*KeycloakClaims)
	if !ok {
		v.recordFailure()
		return nil, NewTokenInvalidClaimsError(fmt.Errorf("unexpected claims type"))
	}

	// Check issuer
	issuer := claims.Issuer
	if !v.config.IsAllowedIssuer(issuer) {
		v.recordFailure()
		return nil, NewTokenInvalidIssuerError(issuer)
	}

	// Determine validation method based on issuer
	var validatedClaims *KeycloakClaims
	if v.config.IsLegacyIssuer(issuer) {
		validatedClaims, err = v.validateLegacyToken(tokenString)
		if err == nil {
			v.mu.Lock()
			v.legacyTokens++
			v.mu.Unlock()
		}
	} else {
		validatedClaims, err = v.validateKeycloakToken(ctx, tokenString, token.Header)
		if err == nil {
			v.mu.Lock()
			v.keycloakTokens++
			v.mu.Unlock()
		}
	}

	if err != nil {
		v.recordFailure()
		return nil, err
	}

	// Additional validation
	if err := v.validateClaims(validatedClaims); err != nil {
		v.recordFailure()
		return nil, err
	}

	v.mu.Lock()
	v.validationOK++
	v.mu.Unlock()

	return validatedClaims, nil
}

// validateKeycloakToken validates an RS256 token from Keycloak
func (v *KeycloakValidator) validateKeycloakToken(ctx context.Context, tokenString string, header map[string]interface{}) (*KeycloakClaims, error) {
	// Verify algorithm
	alg, ok := header["alg"].(string)
	if !ok || alg != "RS256" {
		return nil, NewTokenInvalidSignatureError(fmt.Errorf("expected RS256, got %v", alg))
	}

	// Get key ID from header
	kid, ok := header["kid"].(string)
	if !ok {
		return nil, NewTokenInvalidSignatureError(fmt.Errorf("missing kid in token header"))
	}

	// Parse claims to get issuer for JWKS lookup
	claims := &KeycloakClaims{}
	parser := jwt.NewParser(jwt.WithoutClaimsValidation())
	if _, _, err := parser.ParseUnverified(tokenString, claims); err != nil {
		return nil, NewTokenMalformedError(err)
	}

	issuer := claims.Issuer

	// Get public key from cache
	publicKey, err := v.jwksCache.GetKey(ctx, issuer, kid)
	if err != nil {
		return nil, err
	}

	// Parse and validate token with the public key
	validatedToken, err := jwt.ParseWithClaims(tokenString, &KeycloakClaims{}, func(token *jwt.Token) (interface{}, error) {
		// Verify signing method
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return publicKey, nil
	}, jwt.WithLeeway(v.config.ClockSkew))

	if err != nil {
		if strings.Contains(err.Error(), "expired") {
			return nil, NewTokenExpiredError()
		}
		return nil, NewTokenInvalidSignatureError(err)
	}

	if !validatedToken.Valid {
		return nil, NewTokenInvalidSignatureError(fmt.Errorf("token validation failed"))
	}

	validatedClaims, ok := validatedToken.Claims.(*KeycloakClaims)
	if !ok {
		return nil, NewTokenInvalidClaimsError(fmt.Errorf("unexpected claims type"))
	}

	return validatedClaims, nil
}

// validateLegacyToken validates an HS256 token (legacy auth-service tokens)
func (v *KeycloakValidator) validateLegacyToken(tokenString string) (*KeycloakClaims, error) {
	if !v.config.EnableLegacySupport {
		return nil, NewTokenInvalidIssuerError("legacy")
	}

	// Log warning about legacy token usage
	v.logger.Warn("Legacy HS256 token used - please migrate to Keycloak")

	// First try to parse as KeycloakClaims
	claims := &KeycloakClaims{}
	token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		// Verify signing method is HMAC
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(v.config.LegacySecret), nil
	}, jwt.WithLeeway(v.config.ClockSkew))

	if err != nil {
		if strings.Contains(err.Error(), "expired") {
			return nil, NewTokenExpiredError()
		}
		return nil, NewTokenInvalidSignatureError(err)
	}

	if !token.Valid {
		return nil, NewTokenInvalidSignatureError(fmt.Errorf("legacy token validation failed"))
	}

	validatedClaims, ok := token.Claims.(*KeycloakClaims)
	if !ok {
		return nil, NewTokenInvalidClaimsError(fmt.Errorf("unexpected claims type"))
	}

	return validatedClaims, nil
}

// validateClaims performs additional claim validation
func (v *KeycloakValidator) validateClaims(claims *KeycloakClaims) error {
	// Check expiration
	if v.config.RequireExpiry {
		if claims.ExpiresAt == nil {
			return NewTokenInvalidClaimsError(fmt.Errorf("missing expiration claim"))
		}
		if claims.IsExpired() {
			return NewTokenExpiredError()
		}
	}

	// Check not before
	if claims.NotBefore != nil && time.Now().Before(claims.NotBefore.Time.Add(-v.config.ClockSkew)) {
		return NewTokenNotYetValidError()
	}

	// Check audience if required
	if v.config.ValidateAudience && len(v.config.ExpectedAudiences) > 0 {
		audience := claims.Audience
		hasValidAudience := false
		for _, aud := range audience {
			for _, expected := range v.config.ExpectedAudiences {
				if aud == expected {
					hasValidAudience = true
					break
				}
			}
		}
		if !hasValidAudience {
			return NewTokenInvalidClaimsError(fmt.Errorf("invalid audience"))
		}
	}

	// Check for required claims
	if claims.GetUserID() == "" {
		return NewTokenInvalidClaimsError(fmt.Errorf("missing user ID (sub or user_id claim)"))
	}

	return nil
}

func (v *KeycloakValidator) recordFailure() {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.validationFailed++
}

// ValidateWithPublicKey validates a token with a known public key (for testing)
func (v *KeycloakValidator) ValidateWithPublicKey(tokenString string, publicKey *rsa.PublicKey) (*KeycloakClaims, error) {
	claims := &KeycloakClaims{}

	token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return publicKey, nil
	}, jwt.WithLeeway(v.config.ClockSkew))

	if err != nil {
		return nil, NewTokenInvalidSignatureError(err)
	}

	if !token.Valid {
		return nil, NewTokenInvalidSignatureError(fmt.Errorf("token validation failed"))
	}

	validatedClaims, ok := token.Claims.(*KeycloakClaims)
	if !ok {
		return nil, NewTokenInvalidClaimsError(fmt.Errorf("unexpected claims type"))
	}

	return validatedClaims, nil
}

// Stats returns validation statistics
func (v *KeycloakValidator) Stats() map[string]interface{} {
	v.mu.RLock()
	defer v.mu.RUnlock()

	return map[string]interface{}{
		"validation_total":  v.validationTotal,
		"validation_ok":     v.validationOK,
		"validation_failed": v.validationFailed,
		"legacy_tokens":     v.legacyTokens,
		"keycloak_tokens":   v.keycloakTokens,
		"success_rate": func() float64 {
			if v.validationTotal == 0 {
				return 0
			}
			return float64(v.validationOK) / float64(v.validationTotal) * 100
		}(),
		"jwks_cache": v.jwksCache.Stats(),
	}
}

// GetConfig returns the validator configuration (for debugging)
func (v *KeycloakValidator) GetConfig() KeycloakConfig {
	return v.config
}

// Global validator instance for convenience
var (
	globalValidator     *KeycloakValidator
	globalValidatorOnce sync.Once
	globalValidatorErr  error
)

// InitGlobalValidator initializes the global validator
func InitGlobalValidator(logger *logrus.Logger) error {
	globalValidatorOnce.Do(func() {
		config := LoadKeycloakConfig()
		globalValidator, globalValidatorErr = NewKeycloakValidator(config, logger)
		if globalValidatorErr == nil {
			// Pre-warm cache in background
			go func() {
				ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
				defer cancel()
				if err := globalValidator.PreWarm(ctx); err != nil {
					logger.WithError(err).Warn("Failed to pre-warm JWKS cache")
				}
			}()
		}
	})
	return globalValidatorErr
}

// GetGlobalValidator returns the global validator instance
func GetGlobalValidator() *KeycloakValidator {
	return globalValidator
}

// ValidateTokenGlobal validates a token using the global validator
func ValidateTokenGlobal(ctx context.Context, tokenString string) (*KeycloakClaims, error) {
	if globalValidator == nil {
		return nil, fmt.Errorf("global validator not initialized")
	}
	return globalValidator.ValidateToken(ctx, tokenString)
}
