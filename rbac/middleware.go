package rbac

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// contextKey is a custom type for context keys to avoid collisions
type contextKey string

const (
	// AuthTokenContextKey is the context key for the auth token
	AuthTokenContextKey contextKey = "auth_token"
)

// Role priority levels (higher = more power)
// These match the database seed values in staff-service migrations
const (
	PriorityViewer          = 10  // Read-only access
	PriorityCustomerSupport = 50  // Order/customer support
	PrioritySpecialist      = 60  // Inventory/Order/Marketing Manager
	PriorityStoreManager    = 70  // Store operations manager
	PriorityStoreAdmin      = 90  // Full admin access (except finance)
	PriorityStoreOwner      = 100 // Full unrestricted access
)

// ErrorResponse represents a standard error response
type ErrorResponse struct {
	Success bool  `json:"success"`
	Error   Error `json:"error"`
}

// Error represents an error detail
type Error struct {
	Code    string                 `json:"code"`
	Message string                 `json:"message"`
	Field   string                 `json:"field,omitempty"`
	Details map[string]interface{} `json:"details,omitempty"`
}

// AuditLogEntry represents an RBAC audit log entry
type AuditLogEntry struct {
	TenantID      string     `json:"tenant_id"`
	VendorID      *string    `json:"vendor_id,omitempty"`
	Action        string     `json:"action"`
	EntityType    string     `json:"entity_type"`
	EntityID      *uuid.UUID `json:"entity_id,omitempty"`
	PerformedBy   *uuid.UUID `json:"performed_by,omitempty"`
	TargetStaffID *uuid.UUID `json:"target_staff_id,omitempty"`
	IPAddress     string     `json:"ip_address,omitempty"`
	UserAgent     string     `json:"user_agent,omitempty"`
	Notes         string     `json:"notes,omitempty"`
	CreatedAt     time.Time  `json:"created_at"`
}

// AuditLogger is the interface for audit logging
type AuditLogger interface {
	Log(entry *AuditLogEntry) error
}

// Middleware provides RBAC-based authorization middleware for Gin
type Middleware struct {
	client      *Client
	auditLogger AuditLogger
}

// NewMiddleware creates a new RBAC middleware
func NewMiddleware(client *Client, auditLogger AuditLogger) *Middleware {
	return &Middleware{
		client:      client,
		auditLogger: auditLogger,
	}
}

// NewMiddlewareWithURL creates a new RBAC middleware with a specific staff-service URL
func NewMiddlewareWithURL(staffServiceURL string, auditLogger AuditLogger) *Middleware {
	return &Middleware{
		client:      NewClient(staffServiceURL),
		auditLogger: auditLogger,
	}
}

// RequirePermission middleware that requires a specific permission
func (m *Middleware) RequirePermission(permission string) gin.HandlerFunc {
	return func(c *gin.Context) {
		tenantID, vendorID, staffID := m.extractContext(c)

		if staffID == uuid.Nil {
			m.forbidden(c, "User context not found", permission, nil)
			return
		}

		// Build context with auth token and user email for staff lookup
		ctx := m.buildContext(c)

		// Get effective permissions (includes priority) for both permission check and setting context
		permissions, err := m.client.GetEffectivePermissions(ctx, tenantID, vendorID, staffID)
		if err != nil {
			m.logPermissionDenied(c, permission, "failed to check permission: "+err.Error())
			m.forbidden(c, "Failed to verify permissions", permission, nil)
			return
		}

		// Set user_priority in context for use by handlers (e.g., approval workflows)
		c.Set("user_priority", permissions.Priority)

		// Store Owner (priority 100) has unrestricted access to all permissions
		allowed := permissions.Priority >= PriorityStoreOwner || m.client.hasPermission(permissions, permission)

		if !allowed {
			m.logPermissionDenied(c, permission, "permission denied")
			m.forbidden(c, "Insufficient permissions", permission, nil)
			return
		}

		c.Next()
	}
}

// RequireAnyPermission middleware that requires any of the specified permissions
func (m *Middleware) RequireAnyPermission(permissions ...string) gin.HandlerFunc {
	return func(c *gin.Context) {
		tenantID, vendorID, staffID := m.extractContext(c)

		if staffID == uuid.Nil {
			m.forbidden(c, "User context not found", "", permissions)
			return
		}

		// Build context with auth token and user email for staff lookup
		ctx := m.buildContext(c)

		allowed, err := m.client.CheckAnyPermission(ctx, tenantID, vendorID, staffID, permissions...)
		if err != nil {
			m.forbidden(c, "Failed to verify permissions", "", permissions)
			return
		}

		if !allowed {
			m.forbidden(c, "Insufficient permissions", "", permissions)
			return
		}

		c.Next()
	}
}

// RequireAllPermissions middleware that requires all specified permissions
func (m *Middleware) RequireAllPermissions(permissions ...string) gin.HandlerFunc {
	return func(c *gin.Context) {
		tenantID, vendorID, staffID := m.extractContext(c)

		if staffID == uuid.Nil {
			m.forbidden(c, "User context not found", "", permissions)
			return
		}

		// Build context with auth token and user email for staff lookup
		ctx := m.buildContext(c)

		allowed, err := m.client.CheckAllPermissions(ctx, tenantID, vendorID, staffID, permissions...)
		if err != nil {
			m.forbidden(c, "Failed to verify permissions", "", permissions)
			return
		}

		if !allowed {
			for _, perm := range permissions {
				hasIt, _ := m.client.CheckPermission(ctx, tenantID, vendorID, staffID, perm)
				if !hasIt {
					m.logPermissionDenied(c, perm, "missing required permission")
				}
			}
			m.forbidden(c, "Insufficient permissions", "", permissions)
			return
		}

		c.Next()
	}
}

// RequireMinPriority middleware that requires a minimum priority level
func (m *Middleware) RequireMinPriority(minPriority int) gin.HandlerFunc {
	return func(c *gin.Context) {
		tenantID, vendorID, staffID := m.extractContext(c)

		if staffID == uuid.Nil {
			m.forbidden(c, "User context not found", "", nil)
			return
		}

		// Build context with auth token and user email for staff lookup
		ctx := m.buildContext(c)

		priority, err := m.client.GetPriority(ctx, tenantID, vendorID, staffID)
		if err != nil {
			m.forbidden(c, "Failed to check user priority", "", nil)
			return
		}

		if priority < minPriority {
			c.JSON(http.StatusForbidden, ErrorResponse{
				Success: false,
				Error: Error{
					Code:    "INSUFFICIENT_PRIORITY",
					Message: "Your role does not have sufficient priority for this action",
				},
			})
			c.Abort()
			return
		}

		c.Set("user_priority", priority)
		c.Next()
	}
}

// RequireManager is a convenience middleware requiring Store Manager+ role (priority 70+)
func (m *Middleware) RequireManager() gin.HandlerFunc {
	return m.RequireMinPriority(PriorityStoreManager)
}

// RequireAdmin is a convenience middleware requiring Store Admin+ role (priority 90+)
func (m *Middleware) RequireAdmin() gin.HandlerFunc {
	return m.RequireMinPriority(PriorityStoreAdmin)
}

// RequireOwner is a convenience middleware requiring Store Owner role (priority 100)
func (m *Middleware) RequireOwner() gin.HandlerFunc {
	return m.RequireMinPriority(PriorityStoreOwner)
}

// Require2FA middleware that requires 2FA for sensitive operations
func (m *Middleware) Require2FA() gin.HandlerFunc {
	return func(c *gin.Context) {
		tenantID, _, staffID := m.extractContext(c)

		if staffID == uuid.Nil {
			m.forbidden(c, "User context not found", "", nil)
			return
		}

		// Build context with auth token and user email for staff lookup
		ctx := m.buildContext(c)

		// Get staff info to check 2FA status
		staffInfo, err := m.client.GetStaffInfo(ctx, tenantID, staffID)
		if err != nil {
			m.forbidden(c, "Failed to verify user identity", "", nil)
			return
		}

		// Check if 2FA is enabled
		if !staffInfo.TwoFactorEnabled {
			c.JSON(http.StatusForbidden, ErrorResponse{
				Success: false,
				Error: Error{
					Code:    "2FA_REQUIRED",
					Message: "Two-factor authentication is required for this operation",
				},
			})
			c.Abort()
			return
		}

		// Check if current session has 2FA verified
		twoFAVerified := c.GetBool("2fa_verified")
		if !twoFAVerified {
			c.JSON(http.StatusForbidden, ErrorResponse{
				Success: false,
				Error: Error{
					Code:    "2FA_NOT_VERIFIED",
					Message: "Please verify your two-factor authentication to continue",
				},
			})
			c.Abort()
			return
		}

		c.Next()
	}
}

// HasPermission checks if the user in the context has a specific permission
// This can be called from handlers to check permissions inline
func (m *Middleware) HasPermission(c *gin.Context, permission string) bool {
	tenantID, vendorID, staffID := m.extractContext(c)
	if staffID == uuid.Nil {
		return false
	}
	// Build context with auth token and user email for staff lookup
	ctx := m.buildContext(c)
	allowed, err := m.client.CheckPermission(ctx, tenantID, vendorID, staffID, permission)
	return err == nil && allowed
}

// VendorScopeFilter middleware that ensures vendor users only access their data
func (m *Middleware) VendorScopeFilter() gin.HandlerFunc {
	return func(c *gin.Context) {
		vendorID := c.GetString("vendor_id")

		if vendorID != "" {
			c.Set("vendor_scope_filter", vendorID)
		}

		c.Next()
	}
}

// AuditLog middleware that logs RBAC-related actions
func (m *Middleware) AuditLog(action, entityType string) gin.HandlerFunc {
	return func(c *gin.Context) {
		tenantID, vendorID, staffID := m.extractContext(c)

		// Process request
		c.Next()

		// Only log if request was successful (2xx or 3xx status)
		status := c.Writer.Status()
		if status < 200 || status >= 400 {
			return
		}

		// Skip if no audit logger configured
		if m.auditLogger == nil {
			return
		}

		// Create audit log entry
		var entityID *uuid.UUID
		if entityIDStr := c.Param("id"); entityIDStr != "" {
			if parsed, err := uuid.Parse(entityIDStr); err == nil {
				entityID = &parsed
			}
		}

		var targetStaffID *uuid.UUID
		if targetIDStr := c.Param("staffId"); targetIDStr != "" {
			if targetID, err := uuid.Parse(targetIDStr); err == nil {
				targetStaffID = &targetID
			}
		}

		entry := &AuditLogEntry{
			TenantID:      tenantID,
			VendorID:      vendorID,
			Action:        action,
			EntityType:    entityType,
			EntityID:      entityID,
			PerformedBy:   &staffID,
			TargetStaffID: targetStaffID,
			IPAddress:     c.ClientIP(),
			UserAgent:     c.GetHeader("User-Agent"),
			CreatedAt:     time.Now(),
		}

		// Log asynchronously to not block the response
		go func() {
			_ = m.auditLogger.Log(entry)
		}()
	}
}

// Helper methods

func (m *Middleware) extractContext(c *gin.Context) (tenantID string, vendorID *string, staffID uuid.UUID) {
	// Get tenant_id from gin context (set by auth middleware)
	tenantID = c.GetString("tenant_id")
	// Fallback to Istio JWT claim header (set by Istio or BFF)
	if tenantID == "" {
		tenantID = c.GetHeader("x-jwt-claim-tenant-id")
	}

	vendorIDStr := c.GetString("vendor_id")
	// Fallback to Istio JWT claim header for vendor
	if vendorIDStr == "" {
		vendorIDStr = c.GetHeader("x-jwt-claim-vendor-id")
	}
	if vendorIDStr != "" {
		vendorID = &vendorIDStr
	}

	// Try staff_id first, then fall back to user_id (auth middleware sets user_id)
	staffIDStr := c.GetString("staff_id")
	if staffIDStr == "" {
		staffIDStr = c.GetString("user_id")
	}
	// Fallback to Istio JWT claim header for user ID
	if staffIDStr == "" {
		staffIDStr = c.GetHeader("x-jwt-claim-sub")
	}
	if staffIDStr != "" {
		if parsed, err := uuid.Parse(staffIDStr); err == nil {
			staffID = parsed
		}
	}

	return
}

// buildContext creates a context with both auth token and user email
// Auth token is forwarded to staff-service for JWT validation
// User email provides fallback for email-based staff lookup in multi-tenant systems
func (m *Middleware) buildContext(c *gin.Context) context.Context {
	ctx := c.Request.Context()

	// Add auth token from Authorization header
	authHeader := c.GetHeader("Authorization")
	if authHeader != "" && strings.HasPrefix(authHeader, "Bearer ") {
		token := strings.TrimPrefix(authHeader, "Bearer ")
		ctx = context.WithValue(ctx, AuthTokenContextKey, token)
	}

	// Add user email for email-based staff lookup fallback
	// This is critical for multi-tenant systems where the auth user ID (e.g., Keycloak subject)
	// may not match the staff-service staff ID directly
	userEmail := c.GetString("user_email")
	if userEmail == "" {
		userEmail = c.GetHeader("x-jwt-claim-email")
	}

	if userEmail != "" {
		ctx = context.WithValue(ctx, ContextKeyUserEmail, userEmail)
	}

	return ctx
}

func (m *Middleware) forbidden(c *gin.Context, message, required string, requiredAny []string) {
	response := ErrorResponse{
		Success: false,
		Error: Error{
			Code:    "FORBIDDEN",
			Message: message,
		},
	}

	if required != "" {
		response.Error.Field = "permission"
		response.Error.Details = map[string]interface{}{
			"required": required,
		}
	}

	if len(requiredAny) > 0 {
		response.Error.Field = "permissions"
		response.Error.Details = map[string]interface{}{
			"required_any": requiredAny,
		}
	}

	c.JSON(http.StatusForbidden, response)
	c.Abort()
}

func (m *Middleware) logPermissionDenied(c *gin.Context, permission, reason string) {
	if m.auditLogger == nil {
		return
	}

	tenantID, vendorID, staffID := m.extractContext(c)

	entry := &AuditLogEntry{
		TenantID:    tenantID,
		VendorID:    vendorID,
		Action:      "permission_denied",
		EntityType:  "permission",
		PerformedBy: &staffID,
		IPAddress:   c.ClientIP(),
		UserAgent:   c.GetHeader("User-Agent"),
		Notes:       "Permission: " + permission + " - Reason: " + reason,
		CreatedAt:   time.Now(),
	}

	go func() {
		_ = m.auditLogger.Log(entry)
	}()
}
