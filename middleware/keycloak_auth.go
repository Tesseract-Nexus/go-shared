package middleware

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
	"github.com/Tesseract-Nexus/go-shared/auth"
)

// KeycloakAuthMiddleware provides JWT authentication using Keycloak
type KeycloakAuthMiddleware struct {
	validator *auth.KeycloakValidator
	config    auth.KeycloakConfig
	logger    *logrus.Entry
}

// NewKeycloakAuthMiddleware creates a new Keycloak authentication middleware
func NewKeycloakAuthMiddleware(logger *logrus.Logger) (*KeycloakAuthMiddleware, error) {
	config := auth.LoadKeycloakConfig()

	validator, err := auth.NewKeycloakValidator(config, logger)
	if err != nil {
		return nil, err
	}

	return &KeycloakAuthMiddleware{
		validator: validator,
		config:    config,
		logger:    logger.WithField("component", "keycloak_middleware"),
	}, nil
}

// NewKeycloakAuthMiddlewareWithConfig creates middleware with custom config
func NewKeycloakAuthMiddlewareWithConfig(config auth.KeycloakConfig, logger *logrus.Logger) (*KeycloakAuthMiddleware, error) {
	validator, err := auth.NewKeycloakValidator(config, logger)
	if err != nil {
		return nil, err
	}

	return &KeycloakAuthMiddleware{
		validator: validator,
		config:    config,
		logger:    logger.WithField("component", "keycloak_middleware"),
	}, nil
}

// PreWarm warms up the JWKS cache for faster first requests
func (m *KeycloakAuthMiddleware) PreWarm(ctx context.Context) error {
	return m.validator.PreWarm(ctx)
}

// Handler returns the Gin middleware handler
func (m *KeycloakAuthMiddleware) Handler() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Skip auth for configured paths
		if m.config.IsSkipPath(c.Request.URL.Path) {
			c.Next()
			return
		}

		// Get token from Authorization header
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			m.respondUnauthorized(c, auth.NewTokenMissingError())
			return
		}

		// Check if it's a Bearer token
		tokenParts := strings.Split(authHeader, " ")
		if len(tokenParts) != 2 || !strings.EqualFold(tokenParts[0], "Bearer") {
			m.respondUnauthorized(c, auth.NewTokenInvalidFormatError())
			return
		}

		tokenString := tokenParts[1]

		// Validate token with context timeout
		ctx, cancel := context.WithTimeout(c.Request.Context(), 10*time.Second)
		defer cancel()

		claims, err := m.validator.ValidateToken(ctx, tokenString)
		if err != nil {
			m.logger.WithError(err).WithField("path", c.Request.URL.Path).Debug("Token validation failed")
			m.respondWithAuthError(c, err)
			return
		}

		// Set claims in context for downstream handlers
		m.setClaimsInContext(c, claims)

		c.Next()
	}
}

// OptionalHandler returns middleware that allows but doesn't require authentication
func (m *KeycloakAuthMiddleware) OptionalHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Get token from Authorization header
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.Next()
			return
		}

		// Check if it's a Bearer token
		tokenParts := strings.Split(authHeader, " ")
		if len(tokenParts) != 2 || !strings.EqualFold(tokenParts[0], "Bearer") {
			c.Next()
			return
		}

		tokenString := tokenParts[1]

		// Validate token
		ctx, cancel := context.WithTimeout(c.Request.Context(), 10*time.Second)
		defer cancel()

		claims, err := m.validator.ValidateToken(ctx, tokenString)
		if err != nil {
			// Just continue without setting user context
			c.Next()
			return
		}

		// Set claims in context
		m.setClaimsInContext(c, claims)

		c.Next()
	}
}

// RequireRole returns middleware that requires a specific role
func (m *KeycloakAuthMiddleware) RequireRole(role string) gin.HandlerFunc {
	return func(c *gin.Context) {
		claims := m.getClaimsFromContext(c)
		if claims == nil {
			m.respondForbidden(c, auth.NewInsufficientPermissionError(role))
			return
		}

		if !claims.HasRole(role) {
			m.logger.WithFields(logrus.Fields{
				"user_id":       claims.GetUserID(),
				"required_role": role,
				"user_roles":    claims.GetRoles(),
			}).Debug("Role check failed")
			m.respondForbidden(c, auth.NewInsufficientPermissionError(role))
			return
		}

		c.Next()
	}
}

// RequireAnyRole returns middleware that requires any of the specified roles
func (m *KeycloakAuthMiddleware) RequireAnyRole(roles ...string) gin.HandlerFunc {
	return func(c *gin.Context) {
		claims := m.getClaimsFromContext(c)
		if claims == nil {
			m.respondForbidden(c, auth.NewInsufficientPermissionError(strings.Join(roles, " or ")))
			return
		}

		if !claims.HasAnyRole(roles...) {
			m.logger.WithFields(logrus.Fields{
				"user_id":        claims.GetUserID(),
				"required_roles": roles,
				"user_roles":     claims.GetRoles(),
			}).Debug("Role check failed")
			m.respondForbidden(c, auth.NewInsufficientPermissionError(strings.Join(roles, " or ")))
			return
		}

		c.Next()
	}
}

// RequireAllRoles returns middleware that requires all specified roles
func (m *KeycloakAuthMiddleware) RequireAllRoles(roles ...string) gin.HandlerFunc {
	return func(c *gin.Context) {
		claims := m.getClaimsFromContext(c)
		if claims == nil {
			m.respondForbidden(c, auth.NewInsufficientPermissionError(strings.Join(roles, " and ")))
			return
		}

		if !claims.HasAllRoles(roles...) {
			m.logger.WithFields(logrus.Fields{
				"user_id":        claims.GetUserID(),
				"required_roles": roles,
				"user_roles":     claims.GetRoles(),
			}).Debug("Role check failed")
			m.respondForbidden(c, auth.NewInsufficientPermissionError(strings.Join(roles, " and ")))
			return
		}

		c.Next()
	}
}

// RequireTenant returns middleware that validates tenant access
func (m *KeycloakAuthMiddleware) RequireTenant() gin.HandlerFunc {
	return func(c *gin.Context) {
		claims := m.getClaimsFromContext(c)
		if claims == nil {
			m.respondForbidden(c, auth.NewTenantMismatchError("", ""))
			return
		}

		// Super admin bypasses tenant check
		if claims.IsSuperAdmin() {
			c.Next()
			return
		}

		// Get tenant from URL parameter or header
		requestTenant := c.Param("tenant_id")
		if requestTenant == "" {
			requestTenant = c.GetHeader("X-Tenant-ID")
		}

		tokenTenant := claims.GetTenantID()

		// If no tenant in token and strict mode is enabled, reject
		if tokenTenant == "" && m.config.StrictMode {
			m.respondForbidden(c, auth.NewTenantMismatchError("", requestTenant))
			return
		}

		// If tenant specified in request, it must match token
		if requestTenant != "" && tokenTenant != "" && requestTenant != tokenTenant {
			m.logger.WithFields(logrus.Fields{
				"user_id":        claims.GetUserID(),
				"token_tenant":   tokenTenant,
				"request_tenant": requestTenant,
			}).Warn("Tenant mismatch")
			m.respondForbidden(c, auth.NewTenantMismatchError(tokenTenant, requestTenant))
			return
		}

		c.Next()
	}
}

// setClaimsInContext sets all claims in the Gin context
func (m *KeycloakAuthMiddleware) setClaimsInContext(c *gin.Context, claims *auth.KeycloakClaims) {
	// Store full claims object
	c.Set("claims", claims)
	c.Set("keycloak_claims", claims)

	// Set individual fields for backward compatibility
	c.Set("user_id", claims.GetUserID())
	c.Set("user_email", claims.GetEmail())
	c.Set("user_roles", claims.GetRoles())

	// Set tenant info
	if claims.GetTenantID() != "" {
		c.Set("tenant_id", claims.GetTenantID())
	}
	if claims.GetTenantSlug() != "" {
		c.Set("tenant_slug", claims.GetTenantSlug())
	}

	// Set additional OIDC claims
	c.Set("user_name", claims.GetFullName())
	c.Set("session_state", claims.SessionState)
	c.Set("token_issuer", claims.Issuer)

	// Set token expiration for refresh handling
	c.Set("token_expires_at", claims.GetExpiryTime())
	c.Set("token_should_refresh", claims.ShouldRefresh())
}

// getClaimsFromContext retrieves claims from context
func (m *KeycloakAuthMiddleware) getClaimsFromContext(c *gin.Context) *auth.KeycloakClaims {
	claims, exists := c.Get("keycloak_claims")
	if !exists {
		return nil
	}
	kc, ok := claims.(*auth.KeycloakClaims)
	if !ok {
		return nil
	}
	return kc
}

// respondUnauthorized sends a 401 response
func (m *KeycloakAuthMiddleware) respondUnauthorized(c *gin.Context, err error) {
	code := auth.GetErrorCode(err)
	c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
		"error":   "Unauthorized",
		"code":    code,
		"message": err.Error(),
	})
}

// respondForbidden sends a 403 response
func (m *KeycloakAuthMiddleware) respondForbidden(c *gin.Context, err error) {
	code := auth.GetErrorCode(err)
	c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
		"error":   "Forbidden",
		"code":    code,
		"message": err.Error(),
	})
}

// respondWithAuthError sends appropriate error response based on error type
func (m *KeycloakAuthMiddleware) respondWithAuthError(c *gin.Context, err error) {
	code := auth.GetErrorCode(err)

	// Token expired should still be 401 but with specific code
	if auth.IsTokenExpiredError(err) {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
			"error":   "Unauthorized",
			"code":    code,
			"message": "Token has expired",
		})
		return
	}

	m.respondUnauthorized(c, err)
}

// Stats returns middleware statistics
func (m *KeycloakAuthMiddleware) Stats() map[string]interface{} {
	return m.validator.Stats()
}

// GetConfig returns the current configuration
func (m *KeycloakAuthMiddleware) GetConfig() auth.KeycloakConfig {
	return m.config
}

// Helper functions for extracting claims from context

// GetUserID extracts user ID from Gin context
func GetUserID(c *gin.Context) string {
	if userID, exists := c.Get("user_id"); exists {
		if id, ok := userID.(string); ok {
			return id
		}
	}
	return ""
}

// GetUserEmail extracts user email from Gin context
func GetUserEmail(c *gin.Context) string {
	if email, exists := c.Get("user_email"); exists {
		if e, ok := email.(string); ok {
			return e
		}
	}
	return ""
}

// GetUserRoles extracts user roles from Gin context
func GetUserRoles(c *gin.Context) []string {
	if roles, exists := c.Get("user_roles"); exists {
		if r, ok := roles.([]string); ok {
			return r
		}
	}
	return nil
}

// GetTenantID extracts tenant ID from Gin context
func GetTenantID(c *gin.Context) string {
	if tenantID, exists := c.Get("tenant_id"); exists {
		if id, ok := tenantID.(string); ok {
			return id
		}
	}
	return ""
}

// GetTenantSlug extracts tenant slug from Gin context
func GetTenantSlug(c *gin.Context) string {
	if slug, exists := c.Get("tenant_slug"); exists {
		if s, ok := slug.(string); ok {
			return s
		}
	}
	return ""
}

// GetKeycloakClaims extracts full Keycloak claims from Gin context
func GetKeycloakClaims(c *gin.Context) *auth.KeycloakClaims {
	if claims, exists := c.Get("keycloak_claims"); exists {
		if kc, ok := claims.(*auth.KeycloakClaims); ok {
			return kc
		}
	}
	return nil
}

// HasRole checks if the current user has a specific role
func HasRole(c *gin.Context, role string) bool {
	claims := GetKeycloakClaims(c)
	if claims == nil {
		return false
	}
	return claims.HasRole(role)
}

// IsSuperAdmin checks if the current user is a super admin
func IsSuperAdmin(c *gin.Context) bool {
	claims := GetKeycloakClaims(c)
	if claims == nil {
		return false
	}
	return claims.IsSuperAdmin()
}

// IsTenantAdmin checks if the current user is a tenant admin
func IsTenantAdmin(c *gin.Context) bool {
	claims := GetKeycloakClaims(c)
	if claims == nil {
		return false
	}
	return claims.IsTenantAdmin()
}

// ShouldRefreshToken checks if token should be refreshed soon
func ShouldRefreshToken(c *gin.Context) bool {
	if shouldRefresh, exists := c.Get("token_should_refresh"); exists {
		if sr, ok := shouldRefresh.(bool); ok {
			return sr
		}
	}
	return false
}

// Global middleware instance for convenience
var (
	globalKeycloakMiddleware *KeycloakAuthMiddleware
)

// InitGlobalKeycloakMiddleware initializes the global middleware
func InitGlobalKeycloakMiddleware(logger *logrus.Logger) error {
	var err error
	globalKeycloakMiddleware, err = NewKeycloakAuthMiddleware(logger)
	if err != nil {
		return err
	}

	// Pre-warm JWKS cache in background
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if err := globalKeycloakMiddleware.PreWarm(ctx); err != nil {
			logger.WithError(err).Warn("Failed to pre-warm JWKS cache")
		}
	}()

	return nil
}

// GetGlobalKeycloakMiddleware returns the global middleware instance
func GetGlobalKeycloakMiddleware() *KeycloakAuthMiddleware {
	return globalKeycloakMiddleware
}

// KeycloakAuth returns the global middleware handler
func KeycloakAuth() gin.HandlerFunc {
	if globalKeycloakMiddleware == nil {
		return func(c *gin.Context) {
			c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
				"error": "Auth middleware not initialized",
			})
		}
	}
	return globalKeycloakMiddleware.Handler()
}

// KeycloakOptionalAuth returns the global optional auth handler
func KeycloakOptionalAuth() gin.HandlerFunc {
	if globalKeycloakMiddleware == nil {
		return func(c *gin.Context) {
			c.Next()
		}
	}
	return globalKeycloakMiddleware.OptionalHandler()
}
