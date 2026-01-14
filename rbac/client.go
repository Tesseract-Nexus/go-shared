package rbac

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/google/uuid"
)

// PermissionCheckRequest represents a request to check permissions
type PermissionCheckRequest struct {
	TenantID   string     `json:"tenant_id"`
	VendorID   *string    `json:"vendor_id,omitempty"`
	StaffID    uuid.UUID  `json:"staff_id"`
	Permission string     `json:"permission"`
}

// PermissionCheckResponse represents the response from permission check
type PermissionCheckResponse struct {
	Allowed  bool   `json:"allowed"`
	Priority int    `json:"priority"`
	Role     string `json:"role"`
}

// EffectivePermissions represents a user's effective permissions
type EffectivePermissions struct {
	Permissions    []Permission `json:"permissions"`
	Priority       int          `json:"maxPriority"` // Maps to staff-service's maxPriority field
	Role           string       `json:"role"`
	CanManageStaff bool         `json:"canManageStaff"`
	CanCreateRoles bool         `json:"canCreateRoles"`
}

// Permission represents a single permission
type Permission struct {
	ID          uuid.UUID `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	Category    string    `json:"category"`
}

// StaffInfo represents basic staff information for 2FA checks
type StaffInfo struct {
	ID               uuid.UUID `json:"id"`
	TenantID         string    `json:"tenant_id"`
	TwoFactorEnabled bool      `json:"two_factor_enabled"`
	Role             string    `json:"role"`
	Priority         int       `json:"priority"`
}

// Client provides methods to interact with staff-service for RBAC
type Client struct {
	baseURL    string
	httpClient *http.Client
	cache      *permissionCache
}

// permissionCache provides in-memory caching for permissions
type permissionCache struct {
	mu      sync.RWMutex
	entries map[string]*cacheEntry
	ttl     time.Duration
}

type cacheEntry struct {
	permissions *EffectivePermissions
	expiresAt   time.Time
}

// NewClient creates a new RBAC client
func NewClient(baseURL string) *Client {
	if baseURL == "" {
		baseURL = os.Getenv("STAFF_SERVICE_URL")
		if baseURL == "" {
			baseURL = "http://staff-service:8080"
		}
	}

	return &Client{
		baseURL: baseURL,
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
		},
		cache: &permissionCache{
			entries: make(map[string]*cacheEntry),
			ttl:     5 * time.Minute, // Cache permissions for 5 minutes
		},
	}
}

// CheckPermission checks if a user has a specific permission
// Store Owner (priority 100) has unrestricted access to all permissions
func (c *Client) CheckPermission(ctx context.Context, tenantID string, vendorID *string, staffID uuid.UUID, permission string) (bool, error) {
	permissions, err := c.GetEffectivePermissions(ctx, tenantID, vendorID, staffID)
	if err != nil {
		return false, err
	}

	// Store Owner (priority 100) has unrestricted access to all permissions
	if permissions.Priority >= PriorityStoreOwner {
		return true, nil
	}

	return c.hasPermission(permissions, permission), nil
}

// CheckAnyPermission checks if a user has any of the specified permissions
// Store Owner (priority 100) has unrestricted access to all permissions
func (c *Client) CheckAnyPermission(ctx context.Context, tenantID string, vendorID *string, staffID uuid.UUID, permissions ...string) (bool, error) {
	effectivePerms, err := c.GetEffectivePermissions(ctx, tenantID, vendorID, staffID)
	if err != nil {
		return false, err
	}

	// Store Owner (priority 100) has unrestricted access to all permissions
	if effectivePerms.Priority >= PriorityStoreOwner {
		return true, nil
	}

	for _, perm := range permissions {
		if c.hasPermission(effectivePerms, perm) {
			return true, nil
		}
	}

	return false, nil
}

// CheckAllPermissions checks if a user has all specified permissions
// Store Owner (priority 100) has unrestricted access to all permissions
func (c *Client) CheckAllPermissions(ctx context.Context, tenantID string, vendorID *string, staffID uuid.UUID, permissions ...string) (bool, error) {
	effectivePerms, err := c.GetEffectivePermissions(ctx, tenantID, vendorID, staffID)
	if err != nil {
		return false, err
	}

	// Store Owner (priority 100) has unrestricted access to all permissions
	if effectivePerms.Priority >= PriorityStoreOwner {
		return true, nil
	}

	for _, perm := range permissions {
		if !c.hasPermission(effectivePerms, perm) {
			return false, nil
		}
	}

	return true, nil
}

// ContextKey is a type for context keys
type ContextKey string

// Context keys for passing additional info
const (
	ContextKeyUserEmail ContextKey = "user_email"
)

// GetEffectivePermissions retrieves a user's effective permissions
func (c *Client) GetEffectivePermissions(ctx context.Context, tenantID string, vendorID *string, staffID uuid.UUID) (*EffectivePermissions, error) {
	// Check cache first
	cacheKey := c.buildCacheKey(tenantID, vendorID, staffID)
	if cached := c.cache.get(cacheKey); cached != nil {
		return cached, nil
	}

	// Build request URL
	url := fmt.Sprintf("%s/api/v1/rbac/staff/%s/effective-permissions", c.baseURL, staffID.String())

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Add tenant header
	req.Header.Set("X-Tenant-ID", tenantID)
	if vendorID != nil {
		req.Header.Set("X-Vendor-ID", *vendorID)
	}
	req.Header.Set("Content-Type", "application/json")

	// Forward auth token if present in context
	if token := ctx.Value(AuthTokenContextKey); token != nil {
		if tokenStr, ok := token.(string); ok {
			req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", tokenStr))
		}
	}

	// Forward user email if present in context (for email-based staff lookup fallback)
	if email := ctx.Value(ContextKeyUserEmail); email != nil {
		if emailStr, ok := email.(string); ok && emailStr != "" {
			req.Header.Set("X-User-Email", emailStr)
		}
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to call staff-service: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("staff-service returned status %d", resp.StatusCode)
	}

	var result struct {
		Success bool                  `json:"success"`
		Data    *EffectivePermissions `json:"data"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	if !result.Success || result.Data == nil {
		return nil, fmt.Errorf("staff-service returned unsuccessful response")
	}

	// Cache the result
	c.cache.set(cacheKey, result.Data)

	return result.Data, nil
}

// GetStaffInfo retrieves staff information for 2FA verification
func (c *Client) GetStaffInfo(ctx context.Context, tenantID string, staffID uuid.UUID) (*StaffInfo, error) {
	url := fmt.Sprintf("%s/api/v1/staff/%s", c.baseURL, staffID.String())

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("X-Tenant-ID", tenantID)
	req.Header.Set("Content-Type", "application/json")

	if token := ctx.Value(AuthTokenContextKey); token != nil {
		if tokenStr, ok := token.(string); ok {
			req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", tokenStr))
		}
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to call staff-service: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("staff-service returned status %d", resp.StatusCode)
	}

	var result struct {
		Success bool       `json:"success"`
		Data    *StaffInfo `json:"data"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return result.Data, nil
}

// GetPriority returns the user's role priority
func (c *Client) GetPriority(ctx context.Context, tenantID string, vendorID *string, staffID uuid.UUID) (int, error) {
	permissions, err := c.GetEffectivePermissions(ctx, tenantID, vendorID, staffID)
	if err != nil {
		return 0, err
	}
	return permissions.Priority, nil
}

// InvalidateCache invalidates the cache for a specific user
func (c *Client) InvalidateCache(tenantID string, vendorID *string, staffID uuid.UUID) {
	cacheKey := c.buildCacheKey(tenantID, vendorID, staffID)
	c.cache.delete(cacheKey)
}

// hasPermission checks if a permission exists in effective permissions
func (c *Client) hasPermission(perms *EffectivePermissions, permission string) bool {
	for _, p := range perms.Permissions {
		if p.Name == permission {
			return true
		}
		// Check wildcard permissions (e.g., "orders:*" matches "orders:read")
		if len(p.Name) > 2 && p.Name[len(p.Name)-2:] == ":*" {
			prefix := p.Name[:len(p.Name)-2]
			if len(permission) > len(prefix) && permission[:len(prefix)+1] == prefix+":" {
				return true
			}
		}
	}
	return false
}

// buildCacheKey creates a unique cache key for permission lookups
func (c *Client) buildCacheKey(tenantID string, vendorID *string, staffID uuid.UUID) string {
	vendorPart := "nil"
	if vendorID != nil {
		vendorPart = *vendorID
	}
	return fmt.Sprintf("%s:%s:%s", tenantID, vendorPart, staffID.String())
}

// Cache methods
func (pc *permissionCache) get(key string) *EffectivePermissions {
	pc.mu.RLock()
	defer pc.mu.RUnlock()

	entry, exists := pc.entries[key]
	if !exists || time.Now().After(entry.expiresAt) {
		return nil
	}
	return entry.permissions
}

func (pc *permissionCache) set(key string, perms *EffectivePermissions) {
	pc.mu.Lock()
	defer pc.mu.Unlock()

	pc.entries[key] = &cacheEntry{
		permissions: perms,
		expiresAt:   time.Now().Add(pc.ttl),
	}
}

func (pc *permissionCache) delete(key string) {
	pc.mu.Lock()
	defer pc.mu.Unlock()
	delete(pc.entries, key)
}
