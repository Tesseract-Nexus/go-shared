package auth

import (
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// KeycloakClaims represents claims from a Keycloak JWT token
type KeycloakClaims struct {
	jwt.RegisteredClaims

	// Standard OIDC claims
	Email         string `json:"email"`
	EmailVerified bool   `json:"email_verified"`
	Name          string `json:"name"`
	GivenName     string `json:"given_name"`
	FamilyName    string `json:"family_name"`
	PreferredName string `json:"preferred_username"`
	Locale        string `json:"locale,omitempty"`
	Zoneinfo      string `json:"zoneinfo,omitempty"`
	Picture       string `json:"picture,omitempty"`
	PhoneNumber   string `json:"phone_number,omitempty"`
	PhoneVerified bool   `json:"phone_number_verified,omitempty"`

	// Keycloak-specific claims
	RealmAccess    RealmAccess    `json:"realm_access,omitempty"`
	ResourceAccess ResourceAccess `json:"resource_access,omitempty"`

	// Custom claims (configured in Keycloak via mappers)
	TenantID    string   `json:"tenant_id,omitempty"`
	TenantSlug  string   `json:"tenant_slug,omitempty"`
	UserID      string   `json:"user_id,omitempty"`
	Roles       []string `json:"roles,omitempty"` // Flat roles list for legacy compatibility
	Permissions []string `json:"permissions,omitempty"`

	// Session information
	SessionState    string `json:"session_state,omitempty"`
	AuthorizedParty string `json:"azp,omitempty"` // Client ID
	Nonce           string `json:"nonce,omitempty"`
	AuthTime        int64  `json:"auth_time,omitempty"`
	Acr             string `json:"acr,omitempty"` // Authentication Context Class Reference

	// Token type (for distinguishing access vs ID tokens)
	TokenType string `json:"typ,omitempty"`
}

// RealmAccess contains realm-level roles
type RealmAccess struct {
	Roles []string `json:"roles"`
}

// ResourceAccess contains client-specific roles
type ResourceAccess map[string]ClientAccess

// ClientAccess contains roles for a specific client
type ClientAccess struct {
	Roles []string `json:"roles"`
}

// GetUserID returns the user ID, preferring custom claim over subject
func (c *KeycloakClaims) GetUserID() string {
	if c.UserID != "" {
		return c.UserID
	}
	return c.Subject
}

// GetEmail returns the email address
func (c *KeycloakClaims) GetEmail() string {
	return c.Email
}

// GetTenantID returns the tenant ID
func (c *KeycloakClaims) GetTenantID() string {
	return c.TenantID
}

// GetTenantSlug returns the tenant slug
func (c *KeycloakClaims) GetTenantSlug() string {
	return c.TenantSlug
}

// GetRoles returns all roles from various sources
func (c *KeycloakClaims) GetRoles() []string {
	roles := make([]string, 0)

	// Add realm roles
	roles = append(roles, c.RealmAccess.Roles...)

	// Add legacy flat roles
	roles = append(roles, c.Roles...)

	// Deduplicate
	return uniqueStrings(roles)
}

// GetClientRoles returns roles for a specific client
func (c *KeycloakClaims) GetClientRoles(clientID string) []string {
	if c.ResourceAccess == nil {
		return nil
	}
	if client, ok := c.ResourceAccess[clientID]; ok {
		return client.Roles
	}
	return nil
}

// HasRole checks if the user has a specific role
func (c *KeycloakClaims) HasRole(role string) bool {
	for _, r := range c.GetRoles() {
		if r == role || r == "super_admin" {
			return true
		}
	}
	return false
}

// HasAnyRole checks if the user has any of the specified roles
func (c *KeycloakClaims) HasAnyRole(roles ...string) bool {
	userRoles := c.GetRoles()
	for _, r := range userRoles {
		if r == "super_admin" {
			return true
		}
		for _, required := range roles {
			if r == required {
				return true
			}
		}
	}
	return false
}

// HasAllRoles checks if the user has all specified roles
func (c *KeycloakClaims) HasAllRoles(roles ...string) bool {
	userRoles := c.GetRoles()

	// Super admin bypasses all role checks
	for _, r := range userRoles {
		if r == "super_admin" {
			return true
		}
	}

	roleSet := make(map[string]bool)
	for _, r := range userRoles {
		roleSet[r] = true
	}

	for _, required := range roles {
		if !roleSet[required] {
			return false
		}
	}
	return true
}

// IsSuperAdmin checks if the user is a super admin
func (c *KeycloakClaims) IsSuperAdmin() bool {
	return c.HasRole("super_admin")
}

// IsTenantAdmin checks if the user is a tenant admin
func (c *KeycloakClaims) IsTenantAdmin() bool {
	return c.HasAnyRole("tenant_admin", "admin")
}

// IsStaff checks if the user is a staff member
func (c *KeycloakClaims) IsStaff() bool {
	return c.HasAnyRole("staff", "employee", "tenant_admin", "admin")
}

// GetFullName returns the user's full name
func (c *KeycloakClaims) GetFullName() string {
	if c.Name != "" {
		return c.Name
	}
	if c.GivenName != "" || c.FamilyName != "" {
		return c.GivenName + " " + c.FamilyName
	}
	return c.PreferredName
}

// GetExpiryTime returns the expiration time as time.Time
// Note: Named differently to avoid shadowing jwt.RegisteredClaims.GetExpirationTime()
func (c *KeycloakClaims) GetExpiryTime() time.Time {
	if c.ExpiresAt != nil {
		return c.ExpiresAt.Time
	}
	return time.Time{}
}

// GetIssuedTime returns the issued at time as time.Time
// Note: Named differently to avoid shadowing jwt.RegisteredClaims.GetIssuedAt()
func (c *KeycloakClaims) GetIssuedTime() time.Time {
	if c.IssuedAt != nil {
		return c.IssuedAt.Time
	}
	return time.Time{}
}

// IsExpired checks if the token is expired
func (c *KeycloakClaims) IsExpired() bool {
	if c.ExpiresAt == nil {
		return false
	}
	return time.Now().After(c.ExpiresAt.Time)
}

// TimeUntilExpiration returns duration until token expires
func (c *KeycloakClaims) TimeUntilExpiration() time.Duration {
	if c.ExpiresAt == nil {
		return time.Duration(0)
	}
	return time.Until(c.ExpiresAt.Time)
}

// ShouldRefresh checks if the token should be refreshed (5 min before expiry)
func (c *KeycloakClaims) ShouldRefresh() bool {
	return c.TimeUntilExpiration() < 5*time.Minute
}

// ToLegacyClaims converts to the legacy Claims type for backward compatibility
func (c *KeycloakClaims) ToLegacyClaims() *Claims {
	return &Claims{
		UserID:           c.GetUserID(),
		Email:            c.Email,
		TenantID:         c.TenantID,
		Roles:            c.GetRoles(),
		RegisteredClaims: c.RegisteredClaims,
	}
}

// uniqueStrings removes duplicates from a string slice
func uniqueStrings(input []string) []string {
	seen := make(map[string]bool)
	result := make([]string, 0, len(input))
	for _, s := range input {
		if !seen[s] && s != "" {
			seen[s] = true
			result = append(result, s)
		}
	}
	return result
}
