package auth

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// KeycloakAdminClient provides admin operations for KeyCloak
type KeycloakAdminClient struct {
	baseURL      string
	realm        string
	authRealm    string // Realm for admin authentication (typically "master")
	clientID     string
	clientSecret string
	username     string // For password grant (admin user)
	password     string // For password grant (admin password)
	httpClient   *http.Client
	tokenMu      sync.RWMutex
	accessToken  string
	tokenExpiry  time.Time
}

// KeycloakAdminConfig configuration for admin client
type KeycloakAdminConfig struct {
	BaseURL      string // e.g., "https://devtest-customer-idp.tesserix.app"
	Realm        string // Target realm for user management (e.g., "tesseract-customer")
	AuthRealm    string // Realm for admin authentication (defaults to "master" for password grant)
	ClientID     string // Admin client ID (e.g., "admin-cli")
	ClientSecret string // Admin client secret (for client_credentials grant)
	Username     string // Admin username (for password grant)
	Password     string // Admin password (for password grant)
	Timeout      time.Duration
}

// IdentityProviderConfig represents a KeyCloak Identity Provider configuration
type IdentityProviderConfig struct {
	Alias                     string            `json:"alias"`
	DisplayName               string            `json:"displayName,omitempty"`
	ProviderID                string            `json:"providerId"` // oidc, saml, google, microsoft
	Enabled                   bool              `json:"enabled"`
	TrustEmail                bool              `json:"trustEmail,omitempty"`
	StoreToken                bool              `json:"storeToken,omitempty"`
	AddReadTokenRoleOnCreate  bool              `json:"addReadTokenRoleOnCreate,omitempty"`
	AuthenticateByDefault     bool              `json:"authenticateByDefault,omitempty"`
	LinkOnly                  bool              `json:"linkOnly,omitempty"`
	FirstBrokerLoginFlowAlias string            `json:"firstBrokerLoginFlowAlias,omitempty"`
	PostBrokerLoginFlowAlias  string            `json:"postBrokerLoginFlowAlias,omitempty"`
	Config                    map[string]string `json:"config,omitempty"`
}

// OIDCProviderConfig represents OIDC-specific configuration
type OIDCProviderConfig struct {
	AuthorizationURL    string `json:"authorizationUrl"`
	TokenURL            string `json:"tokenUrl"`
	LogoutURL           string `json:"logoutUrl,omitempty"`
	UserInfoURL         string `json:"userInfoUrl,omitempty"`
	JwksURL             string `json:"jwksUrl,omitempty"`
	Issuer              string `json:"issuer,omitempty"`
	ClientID            string `json:"clientId"`
	ClientSecret        string `json:"clientSecret"`
	ClientAuthMethod    string `json:"clientAuthMethod,omitempty"` // client_secret_post, client_secret_basic
	DefaultScopes       string `json:"defaultScope,omitempty"`
	ValidateSignature   string `json:"validateSignature,omitempty"`
	UseJwksUrl          string `json:"useJwksUrl,omitempty"`
	SyncMode            string `json:"syncMode,omitempty"` // IMPORT, LEGACY, FORCE
	BackchannelSupported string `json:"backchannelSupported,omitempty"`
}

// SAMLProviderConfig represents SAML-specific configuration
type SAMLProviderConfig struct {
	EntityID                  string `json:"entityId"`
	SingleSignOnServiceURL    string `json:"singleSignOnServiceUrl"`
	SingleLogoutServiceURL    string `json:"singleLogoutServiceUrl,omitempty"`
	NameIDPolicyFormat        string `json:"nameIDPolicyFormat,omitempty"`
	PostBindingResponse       string `json:"postBindingResponse,omitempty"`
	PostBindingAuthnRequest   string `json:"postBindingAuthnRequest,omitempty"`
	WantAuthnRequestsSigned   string `json:"wantAuthnRequestsSigned,omitempty"`
	WantAssertionsSigned      string `json:"wantAssertionsSigned,omitempty"`
	WantAssertionsEncrypted   string `json:"wantAssertionsEncrypted,omitempty"`
	ForceAuthn                string `json:"forceAuthn,omitempty"`
	SignSpMetadata            string `json:"signSpMetadata,omitempty"`
	SignatureAlgorithm        string `json:"signatureAlgorithm,omitempty"`
	XMLSigKeyInfoKeyNameTransformer string `json:"xmlSigKeyInfoKeyNameTransformer,omitempty"`
	SyncMode                  string `json:"syncMode,omitempty"`
}

// IdPTestResult represents the result of testing an IdP connection
type IdPTestResult struct {
	Success       bool          `json:"success"`
	Message       string        `json:"message"`
	ResponseTime  time.Duration `json:"responseTime"`
	Details       interface{}   `json:"details,omitempty"`
}

// TokenResponse represents KeyCloak token response
type tokenResponse struct {
	AccessToken      string `json:"access_token"`
	ExpiresIn        int    `json:"expires_in"`
	RefreshExpiresIn int    `json:"refresh_expires_in"`
	RefreshToken     string `json:"refresh_token"`
	TokenType        string `json:"token_type"`
}

// NewKeycloakAdminClient creates a new KeyCloak admin client
func NewKeycloakAdminClient(config KeycloakAdminConfig) *KeycloakAdminClient {
	timeout := config.Timeout
	if timeout == 0 {
		timeout = 30 * time.Second
	}

	// Default authRealm to "master" for password grant (admin users are typically in master realm)
	authRealm := config.AuthRealm
	if authRealm == "" && config.Username != "" {
		authRealm = "master"
	}
	if authRealm == "" {
		authRealm = config.Realm // Fall back to target realm for client_credentials grant
	}

	return &KeycloakAdminClient{
		baseURL:      strings.TrimSuffix(config.BaseURL, "/"),
		realm:        config.Realm,
		authRealm:    authRealm,
		clientID:     config.ClientID,
		clientSecret: config.ClientSecret,
		username:     config.Username,
		password:     config.Password,
		httpClient: &http.Client{
			Timeout: timeout,
		},
	}
}

// authenticate obtains an admin access token
func (c *KeycloakAdminClient) authenticate(ctx context.Context) error {
	c.tokenMu.RLock()
	if c.accessToken != "" && time.Now().Before(c.tokenExpiry.Add(-30*time.Second)) {
		c.tokenMu.RUnlock()
		return nil
	}
	c.tokenMu.RUnlock()

	c.tokenMu.Lock()
	defer c.tokenMu.Unlock()

	// Double-check after acquiring write lock
	if c.accessToken != "" && time.Now().Before(c.tokenExpiry.Add(-30*time.Second)) {
		return nil
	}

	// Use authRealm for admin authentication (typically "master" for admin users)
	tokenURL := fmt.Sprintf("%s/realms/%s/protocol/openid-connect/token", c.baseURL, c.authRealm)

	data := url.Values{}
	data.Set("client_id", c.clientID)

	// Use password grant if username/password are provided, otherwise use client_credentials
	if c.username != "" && c.password != "" {
		data.Set("grant_type", "password")
		data.Set("username", c.username)
		data.Set("password", c.password)
	} else {
		data.Set("grant_type", "client_credentials")
		data.Set("client_secret", c.clientSecret)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", tokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		return fmt.Errorf("failed to create token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	// Add User-Agent to bypass Cloudflare WAF blocking server-to-server requests
	req.Header.Set("User-Agent", "Tesserix-Service/1.0 (Keycloak Admin Client)")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("token request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("token request failed with status %d: %s", resp.StatusCode, string(body))
	}

	var tokenResp tokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return fmt.Errorf("failed to decode token response: %w", err)
	}

	c.accessToken = tokenResp.AccessToken
	c.tokenExpiry = time.Now().Add(time.Duration(tokenResp.ExpiresIn) * time.Second)

	return nil
}

// doRequest performs an authenticated request
func (c *KeycloakAdminClient) doRequest(ctx context.Context, method, path string, body interface{}) (*http.Response, error) {
	if err := c.authenticate(ctx); err != nil {
		return nil, err
	}

	reqURL := fmt.Sprintf("%s/admin/realms/%s%s", c.baseURL, c.realm, path)

	var reqBody io.Reader
	if body != nil {
		jsonBody, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal request body: %w", err)
		}
		reqBody = bytes.NewReader(jsonBody)
	}

	req, err := http.NewRequestWithContext(ctx, method, reqURL, reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	c.tokenMu.RLock()
	req.Header.Set("Authorization", "Bearer "+c.accessToken)
	c.tokenMu.RUnlock()
	req.Header.Set("Content-Type", "application/json")
	// Add User-Agent to bypass Cloudflare WAF blocking server-to-server requests
	req.Header.Set("User-Agent", "Tesserix-Service/1.0 (Keycloak Admin Client)")

	return c.httpClient.Do(req)
}

// CreateIdentityProvider creates a new identity provider
func (c *KeycloakAdminClient) CreateIdentityProvider(ctx context.Context, config IdentityProviderConfig) error {
	resp, err := c.doRequest(ctx, "POST", "/identity-provider/instances", config)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusConflict {
		return fmt.Errorf("identity provider with alias '%s' already exists", config.Alias)
	}

	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusNoContent {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("failed to create identity provider: status %d, body: %s", resp.StatusCode, string(body))
	}

	return nil
}

// GetIdentityProvider retrieves an identity provider by alias
func (c *KeycloakAdminClient) GetIdentityProvider(ctx context.Context, alias string) (*IdentityProviderConfig, error) {
	resp, err := c.doRequest(ctx, "GET", fmt.Sprintf("/identity-provider/instances/%s", alias), nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, nil
	}

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("failed to get identity provider: status %d, body: %s", resp.StatusCode, string(body))
	}

	var config IdentityProviderConfig
	if err := json.NewDecoder(resp.Body).Decode(&config); err != nil {
		return nil, fmt.Errorf("failed to decode identity provider: %w", err)
	}

	return &config, nil
}

// UpdateIdentityProvider updates an existing identity provider
func (c *KeycloakAdminClient) UpdateIdentityProvider(ctx context.Context, alias string, config IdentityProviderConfig) error {
	resp, err := c.doRequest(ctx, "PUT", fmt.Sprintf("/identity-provider/instances/%s", alias), config)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("failed to update identity provider: status %d, body: %s", resp.StatusCode, string(body))
	}

	return nil
}

// DeleteIdentityProvider deletes an identity provider
func (c *KeycloakAdminClient) DeleteIdentityProvider(ctx context.Context, alias string) error {
	resp, err := c.doRequest(ctx, "DELETE", fmt.Sprintf("/identity-provider/instances/%s", alias), nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil // Already deleted
	}

	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("failed to delete identity provider: status %d, body: %s", resp.StatusCode, string(body))
	}

	return nil
}

// ListIdentityProviders lists all identity providers
func (c *KeycloakAdminClient) ListIdentityProviders(ctx context.Context) ([]IdentityProviderConfig, error) {
	resp, err := c.doRequest(ctx, "GET", "/identity-provider/instances", nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("failed to list identity providers: status %d, body: %s", resp.StatusCode, string(body))
	}

	var providers []IdentityProviderConfig
	if err := json.NewDecoder(resp.Body).Decode(&providers); err != nil {
		return nil, fmt.Errorf("failed to decode identity providers: %w", err)
	}

	return providers, nil
}

// TestIdentityProvider tests if an identity provider is reachable
func (c *KeycloakAdminClient) TestIdentityProvider(ctx context.Context, alias string) (*IdPTestResult, error) {
	start := time.Now()

	idp, err := c.GetIdentityProvider(ctx, alias)
	if err != nil {
		return &IdPTestResult{
			Success:      false,
			Message:      fmt.Sprintf("Failed to get identity provider: %v", err),
			ResponseTime: time.Since(start),
		}, nil
	}

	if idp == nil {
		return &IdPTestResult{
			Success:      false,
			Message:      "Identity provider not found",
			ResponseTime: time.Since(start),
		}, nil
	}

	// For OIDC providers, try to fetch the discovery document
	if idp.ProviderID == "oidc" {
		if issuer, ok := idp.Config["issuer"]; ok && issuer != "" {
			discoveryURL := strings.TrimSuffix(issuer, "/") + "/.well-known/openid-configuration"

			req, err := http.NewRequestWithContext(ctx, "GET", discoveryURL, nil)
			if err != nil {
				return &IdPTestResult{
					Success:      false,
					Message:      fmt.Sprintf("Failed to create discovery request: %v", err),
					ResponseTime: time.Since(start),
				}, nil
			}

			resp, err := c.httpClient.Do(req)
			if err != nil {
				return &IdPTestResult{
					Success:      false,
					Message:      fmt.Sprintf("Failed to fetch discovery document: %v", err),
					ResponseTime: time.Since(start),
				}, nil
			}
			defer resp.Body.Close()

			if resp.StatusCode != http.StatusOK {
				return &IdPTestResult{
					Success:      false,
					Message:      fmt.Sprintf("Discovery endpoint returned status %d", resp.StatusCode),
					ResponseTime: time.Since(start),
				}, nil
			}
		}
	}

	return &IdPTestResult{
		Success:      true,
		Message:      "Identity provider is reachable and configured correctly",
		ResponseTime: time.Since(start),
		Details:      idp,
	}, nil
}

// BuildMicrosoftEntraConfig builds KeyCloak IdP config for Microsoft Entra
func BuildMicrosoftEntraConfig(tenantID, alias, displayName, clientID, clientSecret string) IdentityProviderConfig {
	return IdentityProviderConfig{
		Alias:       alias,
		DisplayName: displayName,
		ProviderID:  "oidc",
		Enabled:     true,
		TrustEmail:  true,
		Config: map[string]string{
			"authorizationUrl":   fmt.Sprintf("https://login.microsoftonline.com/%s/oauth2/v2.0/authorize", tenantID),
			"tokenUrl":           fmt.Sprintf("https://login.microsoftonline.com/%s/oauth2/v2.0/token", tenantID),
			"logoutUrl":          fmt.Sprintf("https://login.microsoftonline.com/%s/oauth2/v2.0/logout", tenantID),
			"userInfoUrl":        "https://graph.microsoft.com/oidc/userinfo",
			"jwksUrl":            fmt.Sprintf("https://login.microsoftonline.com/%s/discovery/v2.0/keys", tenantID),
			"issuer":             fmt.Sprintf("https://login.microsoftonline.com/%s/v2.0", tenantID),
			"clientId":           clientID,
			"clientSecret":       clientSecret,
			"clientAuthMethod":   "client_secret_post",
			"defaultScope":       "openid email profile",
			"validateSignature":  "true",
			"useJwksUrl":         "true",
			"syncMode":           "IMPORT",
		},
	}
}

// BuildOktaOIDCConfig builds KeyCloak IdP config for Okta (OIDC)
func BuildOktaOIDCConfig(domain, alias, displayName, clientID, clientSecret string) IdentityProviderConfig {
	baseURL := fmt.Sprintf("https://%s", domain)

	return IdentityProviderConfig{
		Alias:       alias,
		DisplayName: displayName,
		ProviderID:  "oidc",
		Enabled:     true,
		TrustEmail:  true,
		Config: map[string]string{
			"authorizationUrl":   fmt.Sprintf("%s/oauth2/default/v1/authorize", baseURL),
			"tokenUrl":           fmt.Sprintf("%s/oauth2/default/v1/token", baseURL),
			"logoutUrl":          fmt.Sprintf("%s/oauth2/default/v1/logout", baseURL),
			"userInfoUrl":        fmt.Sprintf("%s/oauth2/default/v1/userinfo", baseURL),
			"jwksUrl":            fmt.Sprintf("%s/oauth2/default/v1/keys", baseURL),
			"issuer":             fmt.Sprintf("%s/oauth2/default", baseURL),
			"clientId":           clientID,
			"clientSecret":       clientSecret,
			"clientAuthMethod":   "client_secret_post",
			"defaultScope":       "openid email profile",
			"validateSignature":  "true",
			"useJwksUrl":         "true",
			"syncMode":           "IMPORT",
		},
	}
}

// BuildOktaSAMLConfig builds KeyCloak IdP config for Okta (SAML)
func BuildOktaSAMLConfig(domain, alias, displayName, entityID, metadataURL string) IdentityProviderConfig {
	return IdentityProviderConfig{
		Alias:       alias,
		DisplayName: displayName,
		ProviderID:  "saml",
		Enabled:     true,
		TrustEmail:  true,
		Config: map[string]string{
			"entityId":                    entityID,
			"singleSignOnServiceUrl":      metadataURL,
			"nameIDPolicyFormat":          "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
			"postBindingResponse":         "true",
			"postBindingAuthnRequest":     "true",
			"wantAuthnRequestsSigned":     "false",
			"wantAssertionsSigned":        "true",
			"wantAssertionsEncrypted":     "false",
			"signSpMetadata":              "false",
			"syncMode":                    "IMPORT",
		},
	}
}

// BuildGoogleConfig builds KeyCloak IdP config for Google OAuth
func BuildGoogleConfig(alias, displayName, clientID, clientSecret string) IdentityProviderConfig {
	return IdentityProviderConfig{
		Alias:       alias,
		DisplayName: displayName,
		ProviderID:  "google", // Keycloak has a built-in Google provider
		Enabled:     true,
		TrustEmail:  true,
		Config: map[string]string{
			"clientId":     clientID,
			"clientSecret": clientSecret,
			"defaultScope": "openid email profile",
			"syncMode":     "IMPORT",
		},
	}
}

// BuildIdPAlias generates a unique IdP alias for a tenant
func BuildIdPAlias(tenantID, provider string) string {
	// Sanitize tenant ID for use in alias
	sanitized := strings.ToLower(tenantID)
	sanitized = strings.ReplaceAll(sanitized, " ", "-")

	// Keep only alphanumeric and hyphens
	var sb strings.Builder
	for _, c := range sanitized {
		if (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' {
			sb.WriteRune(c)
		}
	}
	sanitized = sb.String()

	// Truncate if too long (KeyCloak has limits on alias length)
	if len(sanitized) > 50 {
		sanitized = sanitized[:50]
	}

	return fmt.Sprintf("tenant-%s-%s", sanitized, provider)
}

// =============================================================================
// USER MANAGEMENT TYPES
// =============================================================================

// UserRepresentation represents a Keycloak user
type UserRepresentation struct {
	ID                         string              `json:"id,omitempty"`
	Username                   string              `json:"username,omitempty"`
	Email                      string              `json:"email,omitempty"`
	FirstName                  string              `json:"firstName,omitempty"`
	LastName                   string              `json:"lastName,omitempty"`
	Enabled                    bool                `json:"enabled"`
	EmailVerified              bool                `json:"emailVerified,omitempty"`
	Attributes                 map[string][]string `json:"attributes,omitempty"`
	Credentials                []CredentialRepresentation `json:"credentials,omitempty"`
	RequiredActions            []string            `json:"requiredActions,omitempty"`
	RealmRoles                 []string            `json:"realmRoles,omitempty"`
	Groups                     []string            `json:"groups,omitempty"`
	FederatedIdentities        []FederatedIdentity `json:"federatedIdentities,omitempty"`
	CreatedTimestamp           int64               `json:"createdTimestamp,omitempty"`
}

// CredentialRepresentation represents user credentials
type CredentialRepresentation struct {
	ID             string `json:"id,omitempty"`
	Type           string `json:"type,omitempty"`           // password, otp, etc.
	Value          string `json:"value,omitempty"`          // The credential value
	Temporary      bool   `json:"temporary,omitempty"`      // If true, user must change on first login
	UserLabel      string `json:"userLabel,omitempty"`
	CreatedDate    int64  `json:"createdDate,omitempty"`
	SecretData     string `json:"secretData,omitempty"`
	CredentialData string `json:"credentialData,omitempty"`
}

// FederatedIdentity represents a link to an external identity provider
type FederatedIdentity struct {
	IdentityProvider string `json:"identityProvider,omitempty"`
	UserID           string `json:"userId,omitempty"`
	UserName         string `json:"userName,omitempty"`
}

// RoleRepresentation represents a Keycloak role
type RoleRepresentation struct {
	ID          string              `json:"id,omitempty"`
	Name        string              `json:"name,omitempty"`
	Description string              `json:"description,omitempty"`
	Composite   bool                `json:"composite,omitempty"`
	ClientRole  bool                `json:"clientRole,omitempty"`
	ContainerID string              `json:"containerId,omitempty"`
	Attributes  map[string][]string `json:"attributes,omitempty"`
}

// TokenResponse represents Keycloak token endpoint response (public)
type TokenResponse struct {
	AccessToken      string `json:"access_token"`
	ExpiresIn        int    `json:"expires_in"`
	RefreshExpiresIn int    `json:"refresh_expires_in"`
	RefreshToken     string `json:"refresh_token"`
	TokenType        string `json:"token_type"`
	IDToken          string `json:"id_token,omitempty"`
	Scope            string `json:"scope,omitempty"`
}

// =============================================================================
// USER MANAGEMENT METHODS
// =============================================================================

// CreateUser creates a new user in Keycloak and returns the user ID
func (c *KeycloakAdminClient) CreateUser(ctx context.Context, user UserRepresentation) (string, error) {
	resp, err := c.doRequest(ctx, "POST", "/users", user)
	if err != nil {
		return "", fmt.Errorf("failed to create user: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusConflict {
		return "", fmt.Errorf("user with username '%s' or email '%s' already exists", user.Username, user.Email)
	}

	if resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("failed to create user: status %d, body: %s", resp.StatusCode, string(body))
	}

	// Extract user ID from Location header
	location := resp.Header.Get("Location")
	if location == "" {
		return "", fmt.Errorf("user created but no Location header returned")
	}

	// Location format: .../users/{user-id}
	parts := strings.Split(location, "/")
	if len(parts) == 0 {
		return "", fmt.Errorf("invalid Location header format: %s", location)
	}

	return parts[len(parts)-1], nil
}

// GetUserByID retrieves a user by their ID
func (c *KeycloakAdminClient) GetUserByID(ctx context.Context, userID string) (*UserRepresentation, error) {
	resp, err := c.doRequest(ctx, "GET", fmt.Sprintf("/users/%s", userID), nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get user: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, nil
	}

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("failed to get user: status %d, body: %s", resp.StatusCode, string(body))
	}

	var user UserRepresentation
	if err := json.NewDecoder(resp.Body).Decode(&user); err != nil {
		return nil, fmt.Errorf("failed to decode user: %w", err)
	}

	return &user, nil
}

// GetUserByEmail retrieves a user by their email address
func (c *KeycloakAdminClient) GetUserByEmail(ctx context.Context, email string) (*UserRepresentation, error) {
	// URL encode the email for the query parameter
	encodedEmail := url.QueryEscape(email)
	resp, err := c.doRequest(ctx, "GET", fmt.Sprintf("/users?email=%s&exact=true", encodedEmail), nil)
	if err != nil {
		return nil, fmt.Errorf("failed to search users: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("failed to search users: status %d, body: %s", resp.StatusCode, string(body))
	}

	var users []UserRepresentation
	if err := json.NewDecoder(resp.Body).Decode(&users); err != nil {
		return nil, fmt.Errorf("failed to decode users: %w", err)
	}

	if len(users) == 0 {
		return nil, nil
	}

	// Return the first exact match
	for _, u := range users {
		if strings.EqualFold(u.Email, email) {
			return &u, nil
		}
	}

	return nil, nil
}

// GetUserByUsername retrieves a user by their username
func (c *KeycloakAdminClient) GetUserByUsername(ctx context.Context, username string) (*UserRepresentation, error) {
	encodedUsername := url.QueryEscape(username)
	resp, err := c.doRequest(ctx, "GET", fmt.Sprintf("/users?username=%s&exact=true", encodedUsername), nil)
	if err != nil {
		return nil, fmt.Errorf("failed to search users: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("failed to search users: status %d, body: %s", resp.StatusCode, string(body))
	}

	var users []UserRepresentation
	if err := json.NewDecoder(resp.Body).Decode(&users); err != nil {
		return nil, fmt.Errorf("failed to decode users: %w", err)
	}

	if len(users) == 0 {
		return nil, nil
	}

	// Return the first exact match
	for _, u := range users {
		if strings.EqualFold(u.Username, username) {
			return &u, nil
		}
	}

	return nil, nil
}

// UpdateUser updates an existing user
func (c *KeycloakAdminClient) UpdateUser(ctx context.Context, userID string, user UserRepresentation) error {
	resp, err := c.doRequest(ctx, "PUT", fmt.Sprintf("/users/%s", userID), user)
	if err != nil {
		return fmt.Errorf("failed to update user: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return fmt.Errorf("user not found: %s", userID)
	}

	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("failed to update user: status %d, body: %s", resp.StatusCode, string(body))
	}

	return nil
}

// UpdateUserAttributes updates only the attributes of a user
func (c *KeycloakAdminClient) UpdateUserAttributes(ctx context.Context, userID string, attributes map[string][]string) error {
	// First get the current user
	user, err := c.GetUserByID(ctx, userID)
	if err != nil {
		return err
	}
	if user == nil {
		return fmt.Errorf("user not found: %s", userID)
	}

	// Merge attributes
	if user.Attributes == nil {
		user.Attributes = make(map[string][]string)
	}
	for k, v := range attributes {
		user.Attributes[k] = v
	}

	return c.UpdateUser(ctx, userID, *user)
}

// DeleteUser deletes a user
func (c *KeycloakAdminClient) DeleteUser(ctx context.Context, userID string) error {
	resp, err := c.doRequest(ctx, "DELETE", fmt.Sprintf("/users/%s", userID), nil)
	if err != nil {
		return fmt.Errorf("failed to delete user: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil // Already deleted
	}

	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("failed to delete user: status %d, body: %s", resp.StatusCode, string(body))
	}

	return nil
}

// SetUserPassword sets a password for a user
func (c *KeycloakAdminClient) SetUserPassword(ctx context.Context, userID string, password string, temporary bool) error {
	credential := CredentialRepresentation{
		Type:      "password",
		Value:     password,
		Temporary: temporary,
	}

	resp, err := c.doRequest(ctx, "PUT", fmt.Sprintf("/users/%s/reset-password", userID), credential)
	if err != nil {
		return fmt.Errorf("failed to set password: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return fmt.Errorf("user not found: %s", userID)
	}

	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("failed to set password: status %d, body: %s", resp.StatusCode, string(body))
	}

	return nil
}

// SendVerificationEmail sends a verification email to the user
func (c *KeycloakAdminClient) SendVerificationEmail(ctx context.Context, userID string) error {
	resp, err := c.doRequest(ctx, "PUT", fmt.Sprintf("/users/%s/send-verify-email", userID), nil)
	if err != nil {
		return fmt.Errorf("failed to send verification email: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return fmt.Errorf("user not found: %s", userID)
	}

	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("failed to send verification email: status %d, body: %s", resp.StatusCode, string(body))
	}

	return nil
}

// SendPasswordResetEmail sends a password reset email to the user
func (c *KeycloakAdminClient) SendPasswordResetEmail(ctx context.Context, userID string) error {
	actions := []string{"UPDATE_PASSWORD"}
	resp, err := c.doRequest(ctx, "PUT", fmt.Sprintf("/users/%s/execute-actions-email", userID), actions)
	if err != nil {
		return fmt.Errorf("failed to send password reset email: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return fmt.Errorf("user not found: %s", userID)
	}

	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("failed to send password reset email: status %d, body: %s", resp.StatusCode, string(body))
	}

	return nil
}

// =============================================================================
// ROLE MANAGEMENT METHODS
// =============================================================================

// GetRealmRoles lists all realm-level roles
func (c *KeycloakAdminClient) GetRealmRoles(ctx context.Context) ([]RoleRepresentation, error) {
	resp, err := c.doRequest(ctx, "GET", "/roles", nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get realm roles: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("failed to get realm roles: status %d, body: %s", resp.StatusCode, string(body))
	}

	var roles []RoleRepresentation
	if err := json.NewDecoder(resp.Body).Decode(&roles); err != nil {
		return nil, fmt.Errorf("failed to decode roles: %w", err)
	}

	return roles, nil
}

// GetRealmRoleByName gets a realm role by name
func (c *KeycloakAdminClient) GetRealmRoleByName(ctx context.Context, roleName string) (*RoleRepresentation, error) {
	resp, err := c.doRequest(ctx, "GET", fmt.Sprintf("/roles/%s", roleName), nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get role: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, nil
	}

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("failed to get role: status %d, body: %s", resp.StatusCode, string(body))
	}

	var role RoleRepresentation
	if err := json.NewDecoder(resp.Body).Decode(&role); err != nil {
		return nil, fmt.Errorf("failed to decode role: %w", err)
	}

	return &role, nil
}

// CreateRealmRole creates a new realm-level role
func (c *KeycloakAdminClient) CreateRealmRole(ctx context.Context, role RoleRepresentation) error {
	resp, err := c.doRequest(ctx, "POST", "/roles", role)
	if err != nil {
		return fmt.Errorf("failed to create role: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusConflict {
		return fmt.Errorf("role '%s' already exists", role.Name)
	}

	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusNoContent {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("failed to create role: status %d, body: %s", resp.StatusCode, string(body))
	}

	return nil
}

// GetUserRealmRoles gets the realm-level roles assigned to a user
func (c *KeycloakAdminClient) GetUserRealmRoles(ctx context.Context, userID string) ([]RoleRepresentation, error) {
	resp, err := c.doRequest(ctx, "GET", fmt.Sprintf("/users/%s/role-mappings/realm", userID), nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get user roles: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("failed to get user roles: status %d, body: %s", resp.StatusCode, string(body))
	}

	var roles []RoleRepresentation
	if err := json.NewDecoder(resp.Body).Decode(&roles); err != nil {
		return nil, fmt.Errorf("failed to decode roles: %w", err)
	}

	return roles, nil
}

// AssignRealmRole assigns a realm-level role to a user
func (c *KeycloakAdminClient) AssignRealmRole(ctx context.Context, userID string, roleName string) error {
	// First, get the role to obtain its ID
	role, err := c.GetRealmRoleByName(ctx, roleName)
	if err != nil {
		return err
	}
	if role == nil {
		return fmt.Errorf("role not found: %s", roleName)
	}

	// Assign the role
	roles := []RoleRepresentation{*role}
	resp, err := c.doRequest(ctx, "POST", fmt.Sprintf("/users/%s/role-mappings/realm", userID), roles)
	if err != nil {
		return fmt.Errorf("failed to assign role: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("failed to assign role: status %d, body: %s", resp.StatusCode, string(body))
	}

	return nil
}

// RemoveRealmRole removes a realm-level role from a user
func (c *KeycloakAdminClient) RemoveRealmRole(ctx context.Context, userID string, roleName string) error {
	// First, get the role to obtain its ID
	role, err := c.GetRealmRoleByName(ctx, roleName)
	if err != nil {
		return err
	}
	if role == nil {
		return fmt.Errorf("role not found: %s", roleName)
	}

	// Remove the role
	roles := []RoleRepresentation{*role}
	resp, err := c.doRequest(ctx, "DELETE", fmt.Sprintf("/users/%s/role-mappings/realm", userID), roles)
	if err != nil {
		return fmt.Errorf("failed to remove role: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("failed to remove role: status %d, body: %s", resp.StatusCode, string(body))
	}

	return nil
}

// =============================================================================
// TOKEN OPERATIONS (for authentication flows)
// =============================================================================

// GetTokenWithPassword obtains tokens using the Resource Owner Password Grant
// This is used during migration to get tokens for a user after Keycloak registration
func (c *KeycloakAdminClient) GetTokenWithPassword(ctx context.Context, clientID, clientSecret, username, password string) (*TokenResponse, error) {
	tokenURL := fmt.Sprintf("%s/realms/%s/protocol/openid-connect/token", c.baseURL, c.realm)

	data := url.Values{}
	data.Set("grant_type", "password")
	data.Set("client_id", clientID)
	if clientSecret != "" {
		data.Set("client_secret", clientSecret)
	}
	data.Set("username", username)
	data.Set("password", password)
	data.Set("scope", "openid")

	req, err := http.NewRequestWithContext(ctx, "POST", tokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, fmt.Errorf("failed to create token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	// Add User-Agent to bypass Cloudflare WAF blocking server-to-server requests
	req.Header.Set("User-Agent", "Tesserix-Service/1.0 (Keycloak Admin Client)")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("token request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("token request failed with status %d: %s", resp.StatusCode, string(body))
	}

	var tokenResp TokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return nil, fmt.Errorf("failed to decode token response: %w", err)
	}

	return &tokenResp, nil
}

// RefreshToken refreshes an access token using a refresh token
func (c *KeycloakAdminClient) RefreshToken(ctx context.Context, clientID, clientSecret, refreshToken string) (*TokenResponse, error) {
	tokenURL := fmt.Sprintf("%s/realms/%s/protocol/openid-connect/token", c.baseURL, c.realm)

	data := url.Values{}
	data.Set("grant_type", "refresh_token")
	data.Set("client_id", clientID)
	if clientSecret != "" {
		data.Set("client_secret", clientSecret)
	}
	data.Set("refresh_token", refreshToken)

	req, err := http.NewRequestWithContext(ctx, "POST", tokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, fmt.Errorf("failed to create refresh token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	// Add User-Agent to bypass Cloudflare WAF blocking server-to-server requests
	req.Header.Set("User-Agent", "Tesserix-Service/1.0 (Keycloak Admin Client)")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("refresh token request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("refresh token request failed with status %d: %s", resp.StatusCode, string(body))
	}

	var tokenResp TokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return nil, fmt.Errorf("failed to decode token response: %w", err)
	}

	return &tokenResp, nil
}

// LogoutUser logs out a user by invalidating their session
func (c *KeycloakAdminClient) LogoutUser(ctx context.Context, userID string) error {
	resp, err := c.doRequest(ctx, "POST", fmt.Sprintf("/users/%s/logout", userID), nil)
	if err != nil {
		return fmt.Errorf("failed to logout user: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return fmt.Errorf("user not found: %s", userID)
	}

	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("failed to logout user: status %d, body: %s", resp.StatusCode, string(body))
	}

	return nil
}

// =============================================================================
// GROUP MANAGEMENT METHODS
// =============================================================================

// GroupRepresentation represents a Keycloak group
type GroupRepresentation struct {
	ID          string              `json:"id,omitempty"`
	Name        string              `json:"name,omitempty"`
	Path        string              `json:"path,omitempty"`
	SubGroups   []GroupRepresentation `json:"subGroups,omitempty"`
	Attributes  map[string][]string `json:"attributes,omitempty"`
	RealmRoles  []string            `json:"realmRoles,omitempty"`
	ClientRoles map[string][]string `json:"clientRoles,omitempty"`
}

// CreateGroup creates a new group
func (c *KeycloakAdminClient) CreateGroup(ctx context.Context, group GroupRepresentation) (string, error) {
	resp, err := c.doRequest(ctx, "POST", "/groups", group)
	if err != nil {
		return "", fmt.Errorf("failed to create group: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusConflict {
		return "", fmt.Errorf("group '%s' already exists", group.Name)
	}

	if resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("failed to create group: status %d, body: %s", resp.StatusCode, string(body))
	}

	// Extract group ID from Location header
	location := resp.Header.Get("Location")
	if location == "" {
		return "", fmt.Errorf("group created but no Location header returned")
	}

	parts := strings.Split(location, "/")
	if len(parts) == 0 {
		return "", fmt.Errorf("invalid Location header format: %s", location)
	}

	return parts[len(parts)-1], nil
}

// GetGroups lists all groups
func (c *KeycloakAdminClient) GetGroups(ctx context.Context) ([]GroupRepresentation, error) {
	resp, err := c.doRequest(ctx, "GET", "/groups", nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get groups: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("failed to get groups: status %d, body: %s", resp.StatusCode, string(body))
	}

	var groups []GroupRepresentation
	if err := json.NewDecoder(resp.Body).Decode(&groups); err != nil {
		return nil, fmt.Errorf("failed to decode groups: %w", err)
	}

	return groups, nil
}

// AddUserToGroup adds a user to a group
func (c *KeycloakAdminClient) AddUserToGroup(ctx context.Context, userID, groupID string) error {
	resp, err := c.doRequest(ctx, "PUT", fmt.Sprintf("/users/%s/groups/%s", userID, groupID), nil)
	if err != nil {
		return fmt.Errorf("failed to add user to group: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("failed to add user to group: status %d, body: %s", resp.StatusCode, string(body))
	}

	return nil
}

// RemoveUserFromGroup removes a user from a group
func (c *KeycloakAdminClient) RemoveUserFromGroup(ctx context.Context, userID, groupID string) error {
	resp, err := c.doRequest(ctx, "DELETE", fmt.Sprintf("/users/%s/groups/%s", userID, groupID), nil)
	if err != nil {
		return fmt.Errorf("failed to remove user from group: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("failed to remove user from group: status %d, body: %s", resp.StatusCode, string(body))
	}

	return nil
}

// =============================================================================
// CLIENT MANAGEMENT METHODS
// =============================================================================

// ClientRepresentation represents a Keycloak client
type ClientRepresentation struct {
	ID                        string   `json:"id,omitempty"`
	ClientID                  string   `json:"clientId,omitempty"`
	Name                      string   `json:"name,omitempty"`
	Description               string   `json:"description,omitempty"`
	Enabled                   bool     `json:"enabled,omitempty"`
	PublicClient              bool     `json:"publicClient,omitempty"`
	RedirectUris              []string `json:"redirectUris,omitempty"`
	WebOrigins                []string `json:"webOrigins,omitempty"`
	BaseURL                   string   `json:"baseUrl,omitempty"`
	RootURL                   string   `json:"rootUrl,omitempty"`
	AdminURL                  string   `json:"adminUrl,omitempty"`
	Protocol                  string   `json:"protocol,omitempty"`
	BearerOnly                bool     `json:"bearerOnly,omitempty"`
	ConsentRequired           bool     `json:"consentRequired,omitempty"`
	StandardFlowEnabled       bool     `json:"standardFlowEnabled,omitempty"`
	ImplicitFlowEnabled       bool     `json:"implicitFlowEnabled,omitempty"`
	DirectAccessGrantsEnabled bool     `json:"directAccessGrantsEnabled,omitempty"`
	ServiceAccountsEnabled    bool     `json:"serviceAccountsEnabled,omitempty"`
}

// GetClientByClientID retrieves a client by its clientId (not the internal ID)
func (c *KeycloakAdminClient) GetClientByClientID(ctx context.Context, clientID string) (*ClientRepresentation, error) {
	encodedClientID := url.QueryEscape(clientID)
	resp, err := c.doRequest(ctx, "GET", fmt.Sprintf("/clients?clientId=%s", encodedClientID), nil)
	if err != nil {
		return nil, fmt.Errorf("failed to search clients: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("failed to search clients: status %d, body: %s", resp.StatusCode, string(body))
	}

	var clients []ClientRepresentation
	if err := json.NewDecoder(resp.Body).Decode(&clients); err != nil {
		return nil, fmt.Errorf("failed to decode clients: %w", err)
	}

	if len(clients) == 0 {
		return nil, nil
	}

	// Return exact match
	for _, client := range clients {
		if client.ClientID == clientID {
			return &client, nil
		}
	}

	return nil, nil
}

// GetClientByID retrieves a client by its internal ID
func (c *KeycloakAdminClient) GetClientByID(ctx context.Context, id string) (*ClientRepresentation, error) {
	resp, err := c.doRequest(ctx, "GET", fmt.Sprintf("/clients/%s", id), nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get client: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, nil
	}

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("failed to get client: status %d, body: %s", resp.StatusCode, string(body))
	}

	var client ClientRepresentation
	if err := json.NewDecoder(resp.Body).Decode(&client); err != nil {
		return nil, fmt.Errorf("failed to decode client: %w", err)
	}

	return &client, nil
}

// UpdateClient updates an existing client
func (c *KeycloakAdminClient) UpdateClient(ctx context.Context, id string, client ClientRepresentation) error {
	resp, err := c.doRequest(ctx, "PUT", fmt.Sprintf("/clients/%s", id), client)
	if err != nil {
		return fmt.Errorf("failed to update client: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return fmt.Errorf("client not found: %s", id)
	}

	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("failed to update client: status %d, body: %s", resp.StatusCode, string(body))
	}

	return nil
}

// AddClientRedirectURIs adds redirect URIs to an existing client
// This is idempotent - it won't add URIs that already exist
func (c *KeycloakAdminClient) AddClientRedirectURIs(ctx context.Context, clientID string, newRedirectURIs []string) error {
	// First, get the client by its clientId
	client, err := c.GetClientByClientID(ctx, clientID)
	if err != nil {
		return fmt.Errorf("failed to get client: %w", err)
	}
	if client == nil {
		return fmt.Errorf("client not found: %s", clientID)
	}

	// Get full client details including all fields
	fullClient, err := c.GetClientByID(ctx, client.ID)
	if err != nil {
		return fmt.Errorf("failed to get full client details: %w", err)
	}
	if fullClient == nil {
		return fmt.Errorf("client not found by ID: %s", client.ID)
	}

	// Create a map of existing URIs for quick lookup
	existingURIs := make(map[string]bool)
	for _, uri := range fullClient.RedirectUris {
		existingURIs[uri] = true
	}

	// Add new URIs that don't already exist
	modified := false
	for _, uri := range newRedirectURIs {
		if !existingURIs[uri] {
			fullClient.RedirectUris = append(fullClient.RedirectUris, uri)
			existingURIs[uri] = true
			modified = true
		}
	}

	// Only update if we added new URIs
	if modified {
		if err := c.UpdateClient(ctx, fullClient.ID, *fullClient); err != nil {
			return fmt.Errorf("failed to update client redirect URIs: %w", err)
		}
	}

	return nil
}

// RemoveClientRedirectURIs removes redirect URIs from an existing client
func (c *KeycloakAdminClient) RemoveClientRedirectURIs(ctx context.Context, clientID string, urisToRemove []string) error {
	// First, get the client by its clientId
	client, err := c.GetClientByClientID(ctx, clientID)
	if err != nil {
		return fmt.Errorf("failed to get client: %w", err)
	}
	if client == nil {
		return fmt.Errorf("client not found: %s", clientID)
	}

	// Get full client details
	fullClient, err := c.GetClientByID(ctx, client.ID)
	if err != nil {
		return fmt.Errorf("failed to get full client details: %w", err)
	}
	if fullClient == nil {
		return fmt.Errorf("client not found by ID: %s", client.ID)
	}

	// Create a map of URIs to remove
	toRemove := make(map[string]bool)
	for _, uri := range urisToRemove {
		toRemove[uri] = true
	}

	// Filter out the URIs to remove
	var filteredURIs []string
	for _, uri := range fullClient.RedirectUris {
		if !toRemove[uri] {
			filteredURIs = append(filteredURIs, uri)
		}
	}

	// Only update if we removed any URIs
	if len(filteredURIs) != len(fullClient.RedirectUris) {
		fullClient.RedirectUris = filteredURIs
		if err := c.UpdateClient(ctx, fullClient.ID, *fullClient); err != nil {
			return fmt.Errorf("failed to update client redirect URIs: %w", err)
		}
	}

	return nil
}

// ============================================================================
// MULTI-TENANT CREDENTIAL ISOLATION - TOKEN EXCHANGE
// ============================================================================
// These methods support multi-tenant authentication where passwords are
// validated against tenant_credentials table, then tokens are obtained
// from Keycloak using token exchange (impersonation).

// ImpersonateUser obtains tokens for a user using token exchange (impersonation)
// This is used after validating tenant-specific credentials to get Keycloak tokens
// Requires the admin client to have the "impersonation" role in the realm
func (c *KeycloakAdminClient) ImpersonateUser(ctx context.Context, userID string, clientID string, clientSecret string) (*TokenResponse, error) {
	// Use token exchange grant type to get tokens for the target user
	// This requires:
	// 1. Admin client to have token-exchange permission
	// 2. Target client to allow impersonation
	tokenURL := fmt.Sprintf("%s/realms/%s/protocol/openid-connect/token", c.baseURL, c.realm)

	// First authenticate to get admin token
	if err := c.authenticate(ctx); err != nil {
		return nil, fmt.Errorf("failed to authenticate admin client: %w", err)
	}

	data := url.Values{}
	data.Set("grant_type", "urn:ietf:params:oauth:grant-type:token-exchange")
	data.Set("client_id", clientID)
	if clientSecret != "" {
		data.Set("client_secret", clientSecret)
	}
	data.Set("requested_token_type", "urn:ietf:params:oauth:token-type:access_token")
	data.Set("subject_token", c.accessToken)
	data.Set("subject_token_type", "urn:ietf:params:oauth:token-type:access_token")
	data.Set("requested_subject", userID)
	data.Set("scope", "openid")

	req, err := http.NewRequestWithContext(ctx, "POST", tokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, fmt.Errorf("failed to create token exchange request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	// Add User-Agent to bypass Cloudflare WAF blocking server-to-server requests
	req.Header.Set("User-Agent", "Tesserix-Service/1.0 (Keycloak Admin Client)")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("token exchange request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("token exchange failed with status %d: %s", resp.StatusCode, string(body))
	}

	var tokenResp TokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return nil, fmt.Errorf("failed to decode token exchange response: %w", err)
	}

	return &tokenResp, nil
}

// GetUserSessions returns active sessions for a user
// This can be used to validate that a user's session is still active
func (c *KeycloakAdminClient) GetUserSessions(ctx context.Context, userID string) ([]UserSession, error) {
	resp, err := c.doRequest(ctx, "GET", fmt.Sprintf("/users/%s/sessions", userID), nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("failed to get user sessions: %s", string(body))
	}

	var sessions []UserSession
	if err := json.NewDecoder(resp.Body).Decode(&sessions); err != nil {
		return nil, fmt.Errorf("failed to decode sessions: %w", err)
	}

	return sessions, nil
}

// UserSession represents a Keycloak user session
type UserSession struct {
	ID             string            `json:"id"`
	Username       string            `json:"username"`
	UserID         string            `json:"userId"`
	IPAddress      string            `json:"ipAddress"`
	Start          int64             `json:"start"`
	LastAccess     int64             `json:"lastAccess"`
	Clients        map[string]string `json:"clients"`
	RememberMe     bool              `json:"rememberMe"`
	TransientUser  bool              `json:"transientUser"`
}

// ValidateAndGetTokens validates tenant credentials and returns Keycloak tokens
// This is a convenience method that combines tenant credential validation
// with Keycloak token issuance for multi-tenant authentication
// Note: The actual credential validation should be done by TenantAuthService first
func (c *KeycloakAdminClient) GetTokensForValidatedUser(ctx context.Context, keycloakUserID string, clientID string, clientSecret string) (*TokenResponse, error) {
	// Try token exchange first (preferred method)
	tokens, err := c.ImpersonateUser(ctx, keycloakUserID, clientID, clientSecret)
	if err == nil {
		return tokens, nil
	}

	// If token exchange fails (not configured), fall back to direct grant
	// This requires knowing the user's Keycloak password, which may not be available
	// in a multi-tenant setup where passwords are tenant-specific
	return nil, fmt.Errorf("token exchange not available and direct grant requires Keycloak password: %w", err)
}

// CreateUserSession creates a new session for a user
// This can be used when token exchange is not available
// Returns a session ID that can be used to track the session
func (c *KeycloakAdminClient) CreateUserSession(ctx context.Context, userID string, clientID string, ipAddress string) (string, error) {
	// Note: Keycloak doesn't have a direct API to create sessions
	// Sessions are typically created through the token endpoint
	// This method is a placeholder for potential future implementation
	// using custom authenticators or other mechanisms
	return "", fmt.Errorf("direct session creation not supported, use token exchange or password grant")
}
