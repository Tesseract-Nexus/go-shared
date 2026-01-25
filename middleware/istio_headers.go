package middleware

import (
	"encoding/json"
	"net/http"
	"os"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
)

// IstioAuthConfig configures the Istio auth middleware behavior
type IstioAuthConfig struct {
	// RequireAuth returns 401 if no valid JWT claims are present
	// Set to false for public endpoints that optionally use auth
	RequireAuth bool

	// AllowLegacyHeaders allows X-User-ID etc. headers when Istio headers are not present
	// Used during migration period
	AllowLegacyHeaders bool

	// SkipPaths is a list of path prefixes that bypass authentication
	// Used for internal service-to-service endpoints that don't have JWT tokens
	// Example: []string{"/api/v1/notifications/send", "/api/v1/internal/"}
	SkipPaths []string

	// Logger for security audit logging (optional)
	Logger *logrus.Entry
}

// AuthContext holds the authenticated user context from Istio JWT claims
type AuthContext struct {
	// UserID is the Keycloak subject (sub claim)
	UserID string `json:"user_id"`

	// Email from the JWT
	Email string `json:"email"`

	// Username is the preferred_username from Keycloak (for display)
	Username string `json:"username,omitempty"`

	// Name is the full name from Keycloak (name claim)
	Name string `json:"name,omitempty"`

	// TenantID is the tenant UUID
	TenantID string `json:"tenant_id"`

	// TenantSlug is the tenant slug
	TenantSlug string `json:"tenant_slug"`

	// StaffID is the staff member ID (for internal/admin users)
	StaffID string `json:"staff_id,omitempty"`

	// CustomerID is the customer ID (for B2C users)
	CustomerID string `json:"customer_id,omitempty"`

	// VendorID is the vendor ID (for vendor users)
	VendorID string `json:"vendor_id,omitempty"`

	// Roles is the list of Keycloak realm roles
	Roles []string `json:"roles"`

	// IsPlatformOwner indicates cross-tenant access (platform_owner claim)
	IsPlatformOwner bool `json:"is_platform_owner"`
}

// Context keys for storing auth data
const (
	AuthContextKey     = "auth_context"
	IstioAuthHeaderKey = "x-jwt-claim-sub"
)

// istioClaimHeaders maps Istio output header names to AuthContext fields
var istioClaimHeaders = map[string]string{
	"x-jwt-claim-sub":            "sub",
	"x-jwt-claim-email":          "email",
	"x-jwt-claim-tenant-id":      "tenant_id",
	"x-jwt-claim-tenant-slug":    "tenant_slug",
	"x-jwt-claim-staff-id":       "staff_id",
	"x-jwt-claim-customer-id":    "customer_id",
	"x-jwt-claim-vendor-id":      "vendor_id",
	"x-jwt-claim-roles":          "roles",
	"x-jwt-claim-platform-owner": "platform_owner",
}

// legacyHeaders that should be stripped when Istio auth is active
// These are headers that could be spoofed by clients
var legacyHeaders = []string{
	"X-User-ID",
	"X-User-Email",
	"X-Tenant-ID",
	"X-Tenant-Slug",
	"X-Staff-ID",
	"X-Customer-ID",
	"X-Vendor-ID",
	"X-User-Role",      // SECURITY: Prevent role spoofing - use x-jwt-claim-platform-owner instead
	"X-User-Name",      // SECURITY: Prevent name spoofing
	"X-Platform-Owner", // SECURITY: Prevent platform owner spoofing
}

// IstioAuth middleware reads JWT claims from Istio-injected headers
// and sets the AuthContext in the gin context for downstream handlers
func IstioAuth(config IstioAuthConfig) gin.HandlerFunc {
	// Check if Istio auth is enabled via environment variable
	istioAuthEnabled := os.Getenv("ISTIO_AUTH_ENABLED") != "false"

	return func(c *gin.Context) {
		// Check if this path should skip authentication
		for _, skipPath := range config.SkipPaths {
			if strings.HasPrefix(c.Request.URL.Path, skipPath) {
				// For skipped paths, still extract tenant info from legacy headers
				// This allows internal service-to-service calls to pass tenant context
				if tenantID := c.GetHeader("X-Tenant-ID"); tenantID != "" {
					c.Set("tenant_id", tenantID)
				}
				if tenantSlug := c.GetHeader("X-Tenant-Slug"); tenantSlug != "" {
					c.Set("tenant_slug", tenantSlug)
				}
				c.Next()
				return
			}
		}

		// Check for Istio JWT claim headers
		hasIstioAuth := c.GetHeader(IstioAuthHeaderKey) != ""

		if istioAuthEnabled && hasIstioAuth {
			// Parse Istio JWT claims
			authCtx := parseIstioHeaders(c)

			// Strip legacy headers to prevent spoofing
			stripLegacyHeaders(c, config.Logger)

			// Store auth context
			c.Set(AuthContextKey, authCtx)

			// Also set individual context values for backward compatibility
			c.Set("user_id", authCtx.UserID)
			c.Set("userId", authCtx.UserID) // camelCase for services using that convention
			c.Set("staff_id", authCtx.StaffID)
			c.Set("staffId", authCtx.StaffID) // camelCase for services using that convention
			c.Set("tenant_id", authCtx.TenantID)
			c.Set("tenantId", authCtx.TenantID) // camelCase for services using that convention
			c.Set("tenant_slug", authCtx.TenantSlug)
			c.Set("user_email", authCtx.Email) // Required for RBAC email fallback
			// Set username for audit logging - prefer name, then preferred_username, then email
			username := authCtx.Name
			if username == "" {
				username = authCtx.Username
			}
			if username == "" {
				username = authCtx.Email
			}
			c.Set("username", username)
			if authCtx.VendorID != "" {
				c.Set("vendor_id", authCtx.VendorID)
				c.Set("vendorId", authCtx.VendorID) // camelCase for services using that convention
			}
			c.Set("roles", authCtx.Roles)
			c.Set("is_platform_owner", authCtx.IsPlatformOwner)

			c.Next()
			return
		}

		// No Istio auth headers present
		if config.RequireAuth && !config.AllowLegacyHeaders {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error":   "unauthorized",
				"message": "Authentication required",
			})
			return
		}

		// During migration, allow legacy headers if configured
		if config.AllowLegacyHeaders {
			// Parse legacy headers (less trusted, but allows gradual migration)
			authCtx := parseLegacyHeaders(c)
			if authCtx != nil {
				c.Set(AuthContextKey, authCtx)
				c.Set("user_id", authCtx.UserID)
				c.Set("userId", authCtx.UserID) // camelCase for services using that convention
				c.Set("staff_id", authCtx.StaffID)
				c.Set("staffId", authCtx.StaffID) // camelCase for services using that convention
				c.Set("tenant_id", authCtx.TenantID)
				c.Set("tenantId", authCtx.TenantID) // camelCase for services using that convention
				c.Set("tenant_slug", authCtx.TenantSlug)
				c.Set("user_email", authCtx.Email) // Required for RBAC email fallback
				// Set username for audit logging - prefer email for legacy
				username := authCtx.Email
				if username == "" {
					username = authCtx.UserID
				}
				c.Set("username", username)
				if authCtx.VendorID != "" {
					c.Set("vendor_id", authCtx.VendorID)
					c.Set("vendorId", authCtx.VendorID) // camelCase for services using that convention
				}
			} else if config.RequireAuth {
				c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
					"error":   "unauthorized",
					"message": "Authentication required",
				})
				return
			}
		}

		c.Next()
	}
}

// parseIstioHeaders extracts AuthContext from Istio-injected JWT claim headers
func parseIstioHeaders(c *gin.Context) *AuthContext {
	authCtx := &AuthContext{}

	// Extract each claim from headers
	authCtx.UserID = c.GetHeader("x-jwt-claim-sub")
	authCtx.Email = c.GetHeader("x-jwt-claim-email")
	authCtx.Username = c.GetHeader("x-jwt-claim-preferred-username")
	authCtx.Name = c.GetHeader("x-jwt-claim-name")
	authCtx.TenantID = c.GetHeader("x-jwt-claim-tenant-id")
	authCtx.TenantSlug = c.GetHeader("x-jwt-claim-tenant-slug")
	authCtx.StaffID = c.GetHeader("x-jwt-claim-staff-id")
	authCtx.CustomerID = c.GetHeader("x-jwt-claim-customer-id")
	authCtx.VendorID = c.GetHeader("x-jwt-claim-vendor-id")

	// Parse roles (JSON array in header)
	rolesHeader := c.GetHeader("x-jwt-claim-roles")
	if rolesHeader != "" {
		// Istio may encode arrays as JSON strings
		if strings.HasPrefix(rolesHeader, "[") {
			var roles []string
			if err := json.Unmarshal([]byte(rolesHeader), &roles); err == nil {
				authCtx.Roles = roles
			}
		} else {
			// Single role or comma-separated
			authCtx.Roles = strings.Split(rolesHeader, ",")
		}
	}

	// Platform owner flag
	platformOwnerHeader := c.GetHeader("x-jwt-claim-platform-owner")
	authCtx.IsPlatformOwner = platformOwnerHeader == "true"

	return authCtx
}

// parseLegacyHeaders extracts AuthContext from legacy X-* headers
// Used during migration period when some requests may not have Istio auth
func parseLegacyHeaders(c *gin.Context) *AuthContext {
	userID := c.GetHeader("X-User-ID")
	if userID == "" {
		return nil
	}

	return &AuthContext{
		UserID:     userID,
		Email:      c.GetHeader("X-User-Email"),
		TenantID:   c.GetHeader("X-Tenant-ID"),
		TenantSlug: c.GetHeader("X-Tenant-Slug"),
		StaffID:    c.GetHeader("X-Staff-ID"),
		CustomerID: c.GetHeader("X-Customer-ID"),
		VendorID:   c.GetHeader("X-Vendor-ID"),
	}
}

// stripLegacyHeaders removes legacy headers that could be used for spoofing
// when Istio auth is present (Istio headers are trusted, legacy headers are not)
func stripLegacyHeaders(c *gin.Context, log *logrus.Entry) {
	for _, header := range legacyHeaders {
		if c.GetHeader(header) != "" {
			// Log the spoofing attempt
			if log != nil {
				log.WithFields(logrus.Fields{
					"header":    header,
					"value":     c.GetHeader(header),
					"client_ip": c.ClientIP(),
					"path":      c.Request.URL.Path,
				}).Warn("SECURITY: Legacy header present with Istio auth, stripping")
			}
			// Delete the header from the request
			c.Request.Header.Del(header)
		}
	}
}

// GetAuthContext retrieves the AuthContext from the gin context
func GetAuthContext(c *gin.Context) *AuthContext {
	if authCtx, exists := c.Get(AuthContextKey); exists {
		if ctx, ok := authCtx.(*AuthContext); ok {
			return ctx
		}
	}
	return nil
}

// GetIstioUserID retrieves the user ID from Istio auth context
func GetIstioUserID(c *gin.Context) string {
	if authCtx := GetAuthContext(c); authCtx != nil {
		return authCtx.UserID
	}
	// Fallback to direct context value
	if userID, exists := c.Get("user_id"); exists {
		if v, ok := userID.(string); ok {
			return v
		}
	}
	return ""
}

// GetIstioTenantID retrieves the tenant ID from Istio auth context
func GetIstioTenantID(c *gin.Context) string {
	if authCtx := GetAuthContext(c); authCtx != nil {
		return authCtx.TenantID
	}
	if tenantID, exists := c.Get("tenant_id"); exists {
		if v, ok := tenantID.(string); ok {
			return v
		}
	}
	return ""
}

// GetIstioStaffID retrieves the staff ID from Istio auth context
func GetIstioStaffID(c *gin.Context) string {
	if authCtx := GetAuthContext(c); authCtx != nil {
		return authCtx.StaffID
	}
	if staffID, exists := c.Get("staff_id"); exists {
		if v, ok := staffID.(string); ok {
			return v
		}
	}
	return ""
}

// GetIstioVendorID retrieves the vendor ID from Istio auth context
// Returns empty string for tenant-level staff (no vendor scope)
func GetIstioVendorID(c *gin.Context) string {
	if authCtx := GetAuthContext(c); authCtx != nil {
		return authCtx.VendorID
	}
	if vendorID, exists := c.Get("vendor_id"); exists {
		if v, ok := vendorID.(string); ok {
			return v
		}
	}
	return ""
}

// IsVendorScoped checks if the user has vendor-level scope
// Used to determine if vendor isolation should be enforced
func IsVendorScoped(c *gin.Context) bool {
	return GetIstioVendorID(c) != ""
}

// HasIstioRole checks if the authenticated user has the specified role
func HasIstioRole(c *gin.Context, role string) bool {
	if authCtx := GetAuthContext(c); authCtx != nil {
		for _, r := range authCtx.Roles {
			if r == role {
				return true
			}
		}
	}
	return false
}

// IsPlatformOwner checks if the user has platform owner access
func IsPlatformOwner(c *gin.Context) bool {
	if authCtx := GetAuthContext(c); authCtx != nil {
		return authCtx.IsPlatformOwner
	}
	return false
}

// RequireIstioRole middleware that checks for a specific role from Istio claims
func RequireIstioRole(role string) gin.HandlerFunc {
	return func(c *gin.Context) {
		if !HasIstioRole(c, role) {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
				"error":   "forbidden",
				"message": "Insufficient permissions",
			})
			return
		}
		c.Next()
	}
}

// RequireTenant middleware that ensures tenant context is present
func RequireTenant() gin.HandlerFunc {
	return func(c *gin.Context) {
		if GetIstioTenantID(c) == "" {
			c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{
				"error":   "tenant_required",
				"message": "Tenant context is required",
			})
			return
		}
		c.Next()
	}
}

// VendorScopeFilter middleware that sets the vendor scope filter for data isolation
// For vendor-scoped users, this sets a "vendor_scope_filter" context value that
// should be used by repositories to filter data by vendor_id
//
// Data isolation hierarchy:
//   - Platform Owner: Can access all tenants (no vendor filter)
//   - Tenant-level Staff (store_owner, store_admin, etc.): Can access all vendors in tenant
//   - Vendor-level Staff (vendor_owner, vendor_admin, etc.): Can ONLY access their vendor
func VendorScopeFilter() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Platform owners bypass vendor filtering
		if IsPlatformOwner(c) {
			c.Next()
			return
		}

		// Check if user has vendor-scoped role (has a vendor_id claim)
		vendorID := GetIstioVendorID(c)
		if vendorID != "" {
			// User is vendor-scoped: enforce vendor isolation
			c.Set("vendor_scope_filter", vendorID)
		}
		// Tenant-level users: no vendor_scope_filter means they can access all vendors

		c.Next()
	}
}

// GetVendorScopeFilter returns the vendor ID that should be used to filter data
// Returns empty string if no vendor filtering should be applied (tenant-level access)
// Services should use this in their repository queries:
//
//	if vendorFilter := middleware.GetVendorScopeFilter(c); vendorFilter != "" {
//	    query = query.Where("vendor_id = ?", vendorFilter)
//	}
func GetVendorScopeFilter(c *gin.Context) string {
	if vendorFilter, exists := c.Get("vendor_scope_filter"); exists {
		if v, ok := vendorFilter.(string); ok {
			return v
		}
	}
	return ""
}

// ActorInfo contains user identity and request information for audit logging and event publishing
// Use GetActorInfo() to extract this from the request context
type ActorInfo struct {
	// ActorID is the user's UUID (from JWT sub claim)
	ActorID string

	// ActorName is the display name for audit logs
	// Priority: name claim > preferred_username claim > email > user_id
	ActorName string

	// ActorEmail is the user's email address
	ActorEmail string

	// ClientIP is the client's IP address (from X-Forwarded-For or direct connection)
	// Used for audit logging and security tracking
	ClientIP string

	// UserAgent is the client's User-Agent header
	UserAgent string
}

// GetActorInfo extracts actor information from the Gin context for audit event publishing
// This is the standard way for all services to get user identity for NATS events
//
// Usage in handlers:
//
//	actor := middleware.GetActorInfo(c)
//	_ = h.eventsPublisher.PublishProductCreated(ctx, product, tenantID, actor.ActorID, actor.ActorName, actor.ActorEmail, actor.ClientIP)
func GetActorInfo(c *gin.Context) ActorInfo {
	actor := ActorInfo{}

	// Get user ID (UUID)
	actor.ActorID = c.GetString("user_id")

	// Get email
	if email, exists := c.Get("user_email"); exists && email != nil {
		actor.ActorEmail = email.(string)
	}

	// Get display name - the middleware already sets "username" with proper fallback
	if username, exists := c.Get("username"); exists && username != nil {
		actor.ActorName = username.(string)
	}

	// Final fallback: if actorName is still empty, use email
	// This handles edge cases where username context wasn't set
	if actor.ActorName == "" && actor.ActorEmail != "" {
		actor.ActorName = actor.ActorEmail
	}

	// Get client IP - check proxy headers first since Gin's ClientIP() requires trusted proxies config
	// Priority: X-Forwarded-For > X-Real-IP > X-Envoy-External-Address > Gin's ClientIP()
	actor.ClientIP = getClientIP(c)

	// Get User-Agent for additional context
	actor.UserAgent = c.GetHeader("User-Agent")

	return actor
}

// RequireVendorMatch middleware that ensures the request can access the specified vendor
// Use this for endpoints like GET /vendors/{vendorId}/products to validate access
// vendorIDParam is the name of the URL parameter containing the vendor ID
func RequireVendorMatch(vendorIDParam string) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Platform owners can access any vendor
		if IsPlatformOwner(c) {
			c.Next()
			return
		}

		// Get the requested vendor ID from URL
		requestedVendorID := c.Param(vendorIDParam)
		if requestedVendorID == "" {
			c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{
				"error":   "vendor_required",
				"message": "Vendor ID is required",
			})
			return
		}

		// Tenant-level users can access any vendor in their tenant
		userVendorID := GetIstioVendorID(c)
		if userVendorID == "" {
			// No vendor scope = tenant-level access
			c.Next()
			return
		}

		// Vendor-scoped users can only access their own vendor
		if userVendorID != requestedVendorID {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
				"error":   "vendor_forbidden",
				"message": "You do not have access to this vendor",
			})
			return
		}

		c.Next()
	}
}
