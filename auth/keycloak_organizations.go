package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// =============================================================================
// ORGANIZATION TYPES
// Keycloak 26+ Organizations feature for multi-tenant identity isolation
// =============================================================================

// OrganizationRepresentation represents a Keycloak Organization
// Organizations provide tenant isolation within a single realm
type OrganizationRepresentation struct {
	ID          string                             `json:"id,omitempty"`
	Name        string                             `json:"name,omitempty"`
	Alias       string                             `json:"alias,omitempty"` // URL-friendly identifier (e.g., tenant slug)
	Description string                             `json:"description,omitempty"`
	Enabled     bool                               `json:"enabled"`
	Attributes  map[string][]string                `json:"attributes,omitempty"`
	Domains     []OrganizationDomainRepresentation `json:"domains,omitempty"`
}

// OrganizationDomainRepresentation represents a verified domain for an Organization
// Domains can be used for automatic user assignment based on email domain
type OrganizationDomainRepresentation struct {
	Name     string `json:"name,omitempty"`     // Domain name (e.g., "example.com")
	Verified bool   `json:"verified,omitempty"` // Whether the domain ownership is verified
}

// OrganizationMemberRepresentation represents a user's membership in an Organization
// This is an extension of UserRepresentation with organization context
type OrganizationMemberRepresentation struct {
	ID                  string              `json:"id,omitempty"`
	Username            string              `json:"username,omitempty"`
	Email               string              `json:"email,omitempty"`
	FirstName           string              `json:"firstName,omitempty"`
	LastName            string              `json:"lastName,omitempty"`
	Enabled             bool                `json:"enabled"`
	EmailVerified       bool                `json:"emailVerified,omitempty"`
	Attributes          map[string][]string `json:"attributes,omitempty"`
	CreatedTimestamp    int64               `json:"createdTimestamp,omitempty"`
	MembershipType      string              `json:"membershipType,omitempty"`      // Organization membership type
	OrganizationId      string              `json:"organizationId,omitempty"`      // The organization this membership is for
}

// =============================================================================
// ORGANIZATION CRUD METHODS
// =============================================================================

// CreateOrganization creates a new organization in the realm
// Returns the organization ID extracted from the Location header
func (c *KeycloakAdminClient) CreateOrganization(ctx context.Context, org OrganizationRepresentation) (string, error) {
	resp, err := c.doRequest(ctx, "POST", "/organizations", org)
	if err != nil {
		return "", fmt.Errorf("failed to create organization: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusConflict {
		return "", fmt.Errorf("organization with name '%s' or alias '%s' already exists", org.Name, org.Alias)
	}

	if resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("failed to create organization: status %d, body: %s", resp.StatusCode, string(body))
	}

	// Extract organization ID from Location header
	location := resp.Header.Get("Location")
	if location == "" {
		return "", fmt.Errorf("organization created but no Location header returned")
	}

	// Location format: .../organizations/{org-id}
	parts := strings.Split(location, "/")
	if len(parts) == 0 {
		return "", fmt.Errorf("invalid Location header format: %s", location)
	}

	return parts[len(parts)-1], nil
}

// GetOrganization retrieves an organization by its ID
func (c *KeycloakAdminClient) GetOrganization(ctx context.Context, orgID string) (*OrganizationRepresentation, error) {
	resp, err := c.doRequest(ctx, "GET", fmt.Sprintf("/organizations/%s", orgID), nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get organization: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, nil
	}

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("failed to get organization: status %d, body: %s", resp.StatusCode, string(body))
	}

	var org OrganizationRepresentation
	if err := json.NewDecoder(resp.Body).Decode(&org); err != nil {
		return nil, fmt.Errorf("failed to decode organization: %w", err)
	}

	return &org, nil
}

// GetOrganizationByAlias retrieves an organization by its alias (URL-friendly identifier)
// This is useful for looking up organizations by tenant slug
func (c *KeycloakAdminClient) GetOrganizationByAlias(ctx context.Context, alias string) (*OrganizationRepresentation, error) {
	encodedAlias := url.QueryEscape(alias)
	resp, err := c.doRequest(ctx, "GET", fmt.Sprintf("/organizations?search=%s&exact=true", encodedAlias), nil)
	if err != nil {
		return nil, fmt.Errorf("failed to search organizations: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("failed to search organizations: status %d, body: %s", resp.StatusCode, string(body))
	}

	var orgs []OrganizationRepresentation
	if err := json.NewDecoder(resp.Body).Decode(&orgs); err != nil {
		return nil, fmt.Errorf("failed to decode organizations: %w", err)
	}

	// Find exact match by alias
	for _, org := range orgs {
		if strings.EqualFold(org.Alias, alias) {
			return &org, nil
		}
	}

	return nil, nil
}

// ListOrganizations lists all organizations in the realm
func (c *KeycloakAdminClient) ListOrganizations(ctx context.Context) ([]OrganizationRepresentation, error) {
	resp, err := c.doRequest(ctx, "GET", "/organizations", nil)
	if err != nil {
		return nil, fmt.Errorf("failed to list organizations: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("failed to list organizations: status %d, body: %s", resp.StatusCode, string(body))
	}

	var orgs []OrganizationRepresentation
	if err := json.NewDecoder(resp.Body).Decode(&orgs); err != nil {
		return nil, fmt.Errorf("failed to decode organizations: %w", err)
	}

	return orgs, nil
}

// ListOrganizationsWithPagination lists organizations with pagination support
func (c *KeycloakAdminClient) ListOrganizationsWithPagination(ctx context.Context, first, max int) ([]OrganizationRepresentation, error) {
	path := fmt.Sprintf("/organizations?first=%d&max=%d", first, max)
	resp, err := c.doRequest(ctx, "GET", path, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to list organizations: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("failed to list organizations: status %d, body: %s", resp.StatusCode, string(body))
	}

	var orgs []OrganizationRepresentation
	if err := json.NewDecoder(resp.Body).Decode(&orgs); err != nil {
		return nil, fmt.Errorf("failed to decode organizations: %w", err)
	}

	return orgs, nil
}

// UpdateOrganization updates an existing organization
func (c *KeycloakAdminClient) UpdateOrganization(ctx context.Context, orgID string, org OrganizationRepresentation) error {
	resp, err := c.doRequest(ctx, "PUT", fmt.Sprintf("/organizations/%s", orgID), org)
	if err != nil {
		return fmt.Errorf("failed to update organization: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return fmt.Errorf("organization not found: %s", orgID)
	}

	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("failed to update organization: status %d, body: %s", resp.StatusCode, string(body))
	}

	return nil
}

// DeleteOrganization deletes an organization
func (c *KeycloakAdminClient) DeleteOrganization(ctx context.Context, orgID string) error {
	resp, err := c.doRequest(ctx, "DELETE", fmt.Sprintf("/organizations/%s", orgID), nil)
	if err != nil {
		return fmt.Errorf("failed to delete organization: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil // Already deleted
	}

	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("failed to delete organization: status %d, body: %s", resp.StatusCode, string(body))
	}

	return nil
}

// =============================================================================
// ORGANIZATION MEMBERSHIP METHODS
// =============================================================================

// AddOrganizationMember adds a user to an organization
func (c *KeycloakAdminClient) AddOrganizationMember(ctx context.Context, orgID, userID string) error {
	resp, err := c.doRequest(ctx, "POST", fmt.Sprintf("/organizations/%s/members", orgID), userID)
	if err != nil {
		return fmt.Errorf("failed to add organization member: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return fmt.Errorf("organization or user not found")
	}

	if resp.StatusCode == http.StatusConflict {
		return nil // User is already a member, treat as success
	}

	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("failed to add organization member: status %d, body: %s", resp.StatusCode, string(body))
	}

	return nil
}

// RemoveOrganizationMember removes a user from an organization
func (c *KeycloakAdminClient) RemoveOrganizationMember(ctx context.Context, orgID, userID string) error {
	resp, err := c.doRequest(ctx, "DELETE", fmt.Sprintf("/organizations/%s/members/%s", orgID, userID), nil)
	if err != nil {
		return fmt.Errorf("failed to remove organization member: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil // Already removed or never existed
	}

	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("failed to remove organization member: status %d, body: %s", resp.StatusCode, string(body))
	}

	return nil
}

// GetOrganizationMembers lists all members of an organization
func (c *KeycloakAdminClient) GetOrganizationMembers(ctx context.Context, orgID string) ([]OrganizationMemberRepresentation, error) {
	resp, err := c.doRequest(ctx, "GET", fmt.Sprintf("/organizations/%s/members", orgID), nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get organization members: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("organization not found: %s", orgID)
	}

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("failed to get organization members: status %d, body: %s", resp.StatusCode, string(body))
	}

	var members []OrganizationMemberRepresentation
	if err := json.NewDecoder(resp.Body).Decode(&members); err != nil {
		return nil, fmt.Errorf("failed to decode organization members: %w", err)
	}

	return members, nil
}

// GetOrganizationMembersWithPagination lists organization members with pagination
func (c *KeycloakAdminClient) GetOrganizationMembersWithPagination(ctx context.Context, orgID string, first, max int) ([]OrganizationMemberRepresentation, error) {
	path := fmt.Sprintf("/organizations/%s/members?first=%d&max=%d", orgID, first, max)
	resp, err := c.doRequest(ctx, "GET", path, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get organization members: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("organization not found: %s", orgID)
	}

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("failed to get organization members: status %d, body: %s", resp.StatusCode, string(body))
	}

	var members []OrganizationMemberRepresentation
	if err := json.NewDecoder(resp.Body).Decode(&members); err != nil {
		return nil, fmt.Errorf("failed to decode organization members: %w", err)
	}

	return members, nil
}

// IsOrganizationMember checks if a user is a member of an organization
func (c *KeycloakAdminClient) IsOrganizationMember(ctx context.Context, orgID, userID string) (bool, error) {
	// Get the specific member
	resp, err := c.doRequest(ctx, "GET", fmt.Sprintf("/organizations/%s/members/%s", orgID, userID), nil)
	if err != nil {
		return false, fmt.Errorf("failed to check organization membership: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return false, nil
	}

	if resp.StatusCode == http.StatusOK {
		return true, nil
	}

	body, _ := io.ReadAll(resp.Body)
	return false, fmt.Errorf("failed to check organization membership: status %d, body: %s", resp.StatusCode, string(body))
}

// =============================================================================
// ORGANIZATION DOMAIN METHODS
// =============================================================================

// AddOrganizationDomain adds a domain to an organization
func (c *KeycloakAdminClient) AddOrganizationDomain(ctx context.Context, orgID string, domain OrganizationDomainRepresentation) error {
	resp, err := c.doRequest(ctx, "POST", fmt.Sprintf("/organizations/%s/domains", orgID), domain)
	if err != nil {
		return fmt.Errorf("failed to add organization domain: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return fmt.Errorf("organization not found: %s", orgID)
	}

	if resp.StatusCode == http.StatusConflict {
		return fmt.Errorf("domain '%s' already exists in this organization", domain.Name)
	}

	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("failed to add organization domain: status %d, body: %s", resp.StatusCode, string(body))
	}

	return nil
}

// RemoveOrganizationDomain removes a domain from an organization
func (c *KeycloakAdminClient) RemoveOrganizationDomain(ctx context.Context, orgID, domainName string) error {
	encodedDomain := url.PathEscape(domainName)
	resp, err := c.doRequest(ctx, "DELETE", fmt.Sprintf("/organizations/%s/domains/%s", orgID, encodedDomain), nil)
	if err != nil {
		return fmt.Errorf("failed to remove organization domain: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil // Already removed
	}

	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("failed to remove organization domain: status %d, body: %s", resp.StatusCode, string(body))
	}

	return nil
}

// GetOrganizationDomains lists all domains of an organization
func (c *KeycloakAdminClient) GetOrganizationDomains(ctx context.Context, orgID string) ([]OrganizationDomainRepresentation, error) {
	resp, err := c.doRequest(ctx, "GET", fmt.Sprintf("/organizations/%s/domains", orgID), nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get organization domains: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("organization not found: %s", orgID)
	}

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("failed to get organization domains: status %d, body: %s", resp.StatusCode, string(body))
	}

	var domains []OrganizationDomainRepresentation
	if err := json.NewDecoder(resp.Body).Decode(&domains); err != nil {
		return nil, fmt.Errorf("failed to decode organization domains: %w", err)
	}

	return domains, nil
}

// =============================================================================
// USER ORGANIZATION METHODS
// Methods to query organizations from the user's perspective
// =============================================================================

// GetUserOrganizations returns all organizations a user is a member of
func (c *KeycloakAdminClient) GetUserOrganizations(ctx context.Context, userID string) ([]OrganizationRepresentation, error) {
	resp, err := c.doRequest(ctx, "GET", fmt.Sprintf("/users/%s/organizations", userID), nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get user organizations: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("user not found: %s", userID)
	}

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("failed to get user organizations: status %d, body: %s", resp.StatusCode, string(body))
	}

	var orgs []OrganizationRepresentation
	if err := json.NewDecoder(resp.Body).Decode(&orgs); err != nil {
		return nil, fmt.Errorf("failed to decode user organizations: %w", err)
	}

	return orgs, nil
}

// =============================================================================
// HELPER FUNCTIONS
// =============================================================================

// BuildOrganizationAlias generates a URL-friendly alias from a tenant name
// This follows the same pattern as BuildIdPAlias for consistency
func BuildOrganizationAlias(tenantName string) string {
	// Lowercase and replace spaces with hyphens
	alias := strings.ToLower(tenantName)
	alias = strings.ReplaceAll(alias, " ", "-")

	// Keep only alphanumeric and hyphens
	var sb strings.Builder
	for _, c := range alias {
		if (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' {
			sb.WriteRune(c)
		}
	}
	alias = sb.String()

	// Truncate if too long (Organizations have alias length limits)
	if len(alias) > 100 {
		alias = alias[:100]
	}

	// Remove leading/trailing hyphens
	alias = strings.Trim(alias, "-")

	return alias
}

// CreateOrganizationForTenant creates an organization configured for a Tesserix tenant
// This is a convenience method that sets up the organization with standard attributes
func (c *KeycloakAdminClient) CreateOrganizationForTenant(ctx context.Context, tenantID, tenantName, tenantSlug string) (string, error) {
	return c.CreateOrganizationForTenantWithDomain(ctx, tenantID, tenantName, tenantSlug, "tesserix.app")
}

// CreateOrganizationForTenantWithDomain creates an organization configured for a Tesserix tenant
// with a custom base domain. The domain is set to {slug}.{baseDomain}.
func (c *KeycloakAdminClient) CreateOrganizationForTenantWithDomain(ctx context.Context, tenantID, tenantName, tenantSlug, baseDomain string) (string, error) {
	// Keycloak 26+ requires at least one domain for organizations
	// We use {slug}.{baseDomain} as the organization domain
	orgDomain := fmt.Sprintf("%s.%s", tenantSlug, baseDomain)

	org := OrganizationRepresentation{
		Name:        tenantName,
		Alias:       tenantSlug, // Use tenant slug as the organization alias
		Description: fmt.Sprintf("Organization for tenant: %s", tenantName),
		Enabled:     true,
		Attributes: map[string][]string{
			"tenant_id":   {tenantID},
			"tenant_slug": {tenantSlug},
		},
		Domains: []OrganizationDomainRepresentation{
			{
				Name:     orgDomain,
				Verified: true, // Mark as verified since we control the domain
			},
		},
	}

	return c.CreateOrganization(ctx, org)
}
