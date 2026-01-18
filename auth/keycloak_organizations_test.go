package auth

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// mockKeycloakServer creates a test server that simulates Keycloak API responses
func mockKeycloakServer(handler http.HandlerFunc) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Handle token endpoint for authentication
		if strings.HasSuffix(r.URL.Path, "/protocol/openid-connect/token") {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"access_token": "test-token",
				"expires_in":   3600,
				"token_type":   "Bearer",
			})
			return
		}
		// Delegate to the provided handler for other endpoints
		handler(w, r)
	}))
}

func createTestAdminClient(serverURL string) *KeycloakAdminClient {
	return NewKeycloakAdminClient(KeycloakAdminConfig{
		BaseURL:      serverURL,
		Realm:        "test-realm",
		ClientID:     "admin-cli",
		ClientSecret: "test-secret",
		Timeout:      5 * time.Second,
	})
}

// =============================================================================
// ORGANIZATION CRUD TESTS
// =============================================================================

func TestCreateOrganization(t *testing.T) {
	server := mockKeycloakServer(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" && strings.Contains(r.URL.Path, "/organizations") {
			w.Header().Set("Location", "http://test/admin/realms/test-realm/organizations/org-123")
			w.WriteHeader(http.StatusCreated)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	})
	defer server.Close()

	client := createTestAdminClient(server.URL)
	ctx := context.Background()

	org := OrganizationRepresentation{
		Name:    "Test Organization",
		Alias:   "test-org",
		Enabled: true,
	}

	orgID, err := client.CreateOrganization(ctx, org)
	if err != nil {
		t.Fatalf("CreateOrganization failed: %v", err)
	}

	if orgID != "org-123" {
		t.Errorf("Expected org ID 'org-123', got '%s'", orgID)
	}
}

func TestCreateOrganizationConflict(t *testing.T) {
	server := mockKeycloakServer(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" && strings.Contains(r.URL.Path, "/organizations") {
			w.WriteHeader(http.StatusConflict)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	})
	defer server.Close()

	client := createTestAdminClient(server.URL)
	ctx := context.Background()

	org := OrganizationRepresentation{
		Name:  "Test Organization",
		Alias: "test-org",
	}

	_, err := client.CreateOrganization(ctx, org)
	if err == nil {
		t.Fatal("Expected error for conflict")
	}

	if !strings.Contains(err.Error(), "already exists") {
		t.Errorf("Expected 'already exists' error, got: %v", err)
	}
}

func TestGetOrganization(t *testing.T) {
	expectedOrg := OrganizationRepresentation{
		ID:      "org-123",
		Name:    "Test Organization",
		Alias:   "test-org",
		Enabled: true,
	}

	server := mockKeycloakServer(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "GET" && strings.HasSuffix(r.URL.Path, "/organizations/org-123") {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(expectedOrg)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	})
	defer server.Close()

	client := createTestAdminClient(server.URL)
	ctx := context.Background()

	org, err := client.GetOrganization(ctx, "org-123")
	if err != nil {
		t.Fatalf("GetOrganization failed: %v", err)
	}

	if org == nil {
		t.Fatal("Expected organization, got nil")
	}

	if org.ID != expectedOrg.ID {
		t.Errorf("Expected ID '%s', got '%s'", expectedOrg.ID, org.ID)
	}

	if org.Name != expectedOrg.Name {
		t.Errorf("Expected Name '%s', got '%s'", expectedOrg.Name, org.Name)
	}

	if org.Alias != expectedOrg.Alias {
		t.Errorf("Expected Alias '%s', got '%s'", expectedOrg.Alias, org.Alias)
	}
}

func TestGetOrganizationNotFound(t *testing.T) {
	server := mockKeycloakServer(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "GET" && strings.Contains(r.URL.Path, "/organizations/") {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	})
	defer server.Close()

	client := createTestAdminClient(server.URL)
	ctx := context.Background()

	org, err := client.GetOrganization(ctx, "nonexistent")
	if err != nil {
		t.Fatalf("GetOrganization should not error for not found: %v", err)
	}

	if org != nil {
		t.Error("Expected nil for not found organization")
	}
}

func TestGetOrganizationByAlias(t *testing.T) {
	orgs := []OrganizationRepresentation{
		{ID: "org-123", Name: "Test Org", Alias: "test-org"},
		{ID: "org-456", Name: "Other Org", Alias: "other-org"},
	}

	server := mockKeycloakServer(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "GET" && strings.Contains(r.URL.Path, "/organizations") && strings.Contains(r.URL.RawQuery, "search=test-org") {
			w.Header().Set("Content-Type", "application/json")
			// Return only matching organization
			json.NewEncoder(w).Encode([]OrganizationRepresentation{orgs[0]})
			return
		}
		w.WriteHeader(http.StatusNotFound)
	})
	defer server.Close()

	client := createTestAdminClient(server.URL)
	ctx := context.Background()

	org, err := client.GetOrganizationByAlias(ctx, "test-org")
	if err != nil {
		t.Fatalf("GetOrganizationByAlias failed: %v", err)
	}

	if org == nil {
		t.Fatal("Expected organization, got nil")
	}

	if org.Alias != "test-org" {
		t.Errorf("Expected alias 'test-org', got '%s'", org.Alias)
	}
}

func TestListOrganizations(t *testing.T) {
	expectedOrgs := []OrganizationRepresentation{
		{ID: "org-1", Name: "Org 1", Alias: "org-1"},
		{ID: "org-2", Name: "Org 2", Alias: "org-2"},
	}

	server := mockKeycloakServer(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "GET" && strings.HasSuffix(r.URL.Path, "/organizations") {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(expectedOrgs)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	})
	defer server.Close()

	client := createTestAdminClient(server.URL)
	ctx := context.Background()

	orgs, err := client.ListOrganizations(ctx)
	if err != nil {
		t.Fatalf("ListOrganizations failed: %v", err)
	}

	if len(orgs) != 2 {
		t.Errorf("Expected 2 organizations, got %d", len(orgs))
	}
}

func TestUpdateOrganization(t *testing.T) {
	server := mockKeycloakServer(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "PUT" && strings.HasSuffix(r.URL.Path, "/organizations/org-123") {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	})
	defer server.Close()

	client := createTestAdminClient(server.URL)
	ctx := context.Background()

	org := OrganizationRepresentation{
		ID:      "org-123",
		Name:    "Updated Organization",
		Alias:   "updated-org",
		Enabled: true,
	}

	err := client.UpdateOrganization(ctx, "org-123", org)
	if err != nil {
		t.Fatalf("UpdateOrganization failed: %v", err)
	}
}

func TestUpdateOrganizationNotFound(t *testing.T) {
	server := mockKeycloakServer(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "PUT" && strings.Contains(r.URL.Path, "/organizations/") {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	})
	defer server.Close()

	client := createTestAdminClient(server.URL)
	ctx := context.Background()

	org := OrganizationRepresentation{Name: "Test"}

	err := client.UpdateOrganization(ctx, "nonexistent", org)
	if err == nil {
		t.Fatal("Expected error for not found organization")
	}

	if !strings.Contains(err.Error(), "not found") {
		t.Errorf("Expected 'not found' error, got: %v", err)
	}
}

func TestDeleteOrganization(t *testing.T) {
	server := mockKeycloakServer(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "DELETE" && strings.HasSuffix(r.URL.Path, "/organizations/org-123") {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	})
	defer server.Close()

	client := createTestAdminClient(server.URL)
	ctx := context.Background()

	err := client.DeleteOrganization(ctx, "org-123")
	if err != nil {
		t.Fatalf("DeleteOrganization failed: %v", err)
	}
}

func TestDeleteOrganizationNotFoundIsSuccess(t *testing.T) {
	server := mockKeycloakServer(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "DELETE" && strings.Contains(r.URL.Path, "/organizations/") {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	})
	defer server.Close()

	client := createTestAdminClient(server.URL)
	ctx := context.Background()

	// Deleting a non-existent org should not error (idempotent)
	err := client.DeleteOrganization(ctx, "nonexistent")
	if err != nil {
		t.Fatalf("DeleteOrganization should not error for not found: %v", err)
	}
}

// =============================================================================
// ORGANIZATION MEMBERSHIP TESTS
// =============================================================================

func TestAddOrganizationMember(t *testing.T) {
	server := mockKeycloakServer(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" && strings.HasSuffix(r.URL.Path, "/organizations/org-123/members") {
			w.WriteHeader(http.StatusCreated)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	})
	defer server.Close()

	client := createTestAdminClient(server.URL)
	ctx := context.Background()

	err := client.AddOrganizationMember(ctx, "org-123", "user-456")
	if err != nil {
		t.Fatalf("AddOrganizationMember failed: %v", err)
	}
}

func TestAddOrganizationMemberConflict(t *testing.T) {
	server := mockKeycloakServer(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" && strings.Contains(r.URL.Path, "/members") {
			w.WriteHeader(http.StatusConflict) // Already a member
			return
		}
		w.WriteHeader(http.StatusNotFound)
	})
	defer server.Close()

	client := createTestAdminClient(server.URL)
	ctx := context.Background()

	// Conflict should be treated as success (idempotent)
	err := client.AddOrganizationMember(ctx, "org-123", "user-456")
	if err != nil {
		t.Fatalf("AddOrganizationMember should succeed on conflict: %v", err)
	}
}

func TestRemoveOrganizationMember(t *testing.T) {
	server := mockKeycloakServer(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "DELETE" && strings.Contains(r.URL.Path, "/organizations/org-123/members/user-456") {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	})
	defer server.Close()

	client := createTestAdminClient(server.URL)
	ctx := context.Background()

	err := client.RemoveOrganizationMember(ctx, "org-123", "user-456")
	if err != nil {
		t.Fatalf("RemoveOrganizationMember failed: %v", err)
	}
}

func TestRemoveOrganizationMemberNotFoundIsSuccess(t *testing.T) {
	server := mockKeycloakServer(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "DELETE" && strings.Contains(r.URL.Path, "/members/") {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	})
	defer server.Close()

	client := createTestAdminClient(server.URL)
	ctx := context.Background()

	// Not found should be success (idempotent)
	err := client.RemoveOrganizationMember(ctx, "org-123", "user-456")
	if err != nil {
		t.Fatalf("RemoveOrganizationMember should succeed on not found: %v", err)
	}
}

func TestGetOrganizationMembers(t *testing.T) {
	expectedMembers := []OrganizationMemberRepresentation{
		{ID: "user-1", Username: "user1", Email: "user1@example.com"},
		{ID: "user-2", Username: "user2", Email: "user2@example.com"},
	}

	server := mockKeycloakServer(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "GET" && strings.HasSuffix(r.URL.Path, "/organizations/org-123/members") {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(expectedMembers)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	})
	defer server.Close()

	client := createTestAdminClient(server.URL)
	ctx := context.Background()

	members, err := client.GetOrganizationMembers(ctx, "org-123")
	if err != nil {
		t.Fatalf("GetOrganizationMembers failed: %v", err)
	}

	if len(members) != 2 {
		t.Errorf("Expected 2 members, got %d", len(members))
	}

	if members[0].Username != "user1" {
		t.Errorf("Expected username 'user1', got '%s'", members[0].Username)
	}
}

func TestIsOrganizationMember(t *testing.T) {
	server := mockKeycloakServer(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "GET" && strings.Contains(r.URL.Path, "/organizations/org-123/members/user-456") {
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(OrganizationMemberRepresentation{ID: "user-456"})
			return
		}
		if r.Method == "GET" && strings.Contains(r.URL.Path, "/organizations/org-123/members/user-789") {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	})
	defer server.Close()

	client := createTestAdminClient(server.URL)
	ctx := context.Background()

	// Test existing member
	isMember, err := client.IsOrganizationMember(ctx, "org-123", "user-456")
	if err != nil {
		t.Fatalf("IsOrganizationMember failed: %v", err)
	}
	if !isMember {
		t.Error("Expected user to be a member")
	}

	// Test non-member
	isMember, err = client.IsOrganizationMember(ctx, "org-123", "user-789")
	if err != nil {
		t.Fatalf("IsOrganizationMember failed: %v", err)
	}
	if isMember {
		t.Error("Expected user to not be a member")
	}
}

// =============================================================================
// ORGANIZATION DOMAIN TESTS
// =============================================================================

func TestAddOrganizationDomain(t *testing.T) {
	server := mockKeycloakServer(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" && strings.HasSuffix(r.URL.Path, "/organizations/org-123/domains") {
			w.WriteHeader(http.StatusCreated)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	})
	defer server.Close()

	client := createTestAdminClient(server.URL)
	ctx := context.Background()

	domain := OrganizationDomainRepresentation{
		Name:     "example.com",
		Verified: true,
	}

	err := client.AddOrganizationDomain(ctx, "org-123", domain)
	if err != nil {
		t.Fatalf("AddOrganizationDomain failed: %v", err)
	}
}

func TestRemoveOrganizationDomain(t *testing.T) {
	server := mockKeycloakServer(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "DELETE" && strings.Contains(r.URL.Path, "/organizations/org-123/domains/example.com") {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	})
	defer server.Close()

	client := createTestAdminClient(server.URL)
	ctx := context.Background()

	err := client.RemoveOrganizationDomain(ctx, "org-123", "example.com")
	if err != nil {
		t.Fatalf("RemoveOrganizationDomain failed: %v", err)
	}
}

func TestGetOrganizationDomains(t *testing.T) {
	expectedDomains := []OrganizationDomainRepresentation{
		{Name: "example.com", Verified: true},
		{Name: "test.com", Verified: false},
	}

	server := mockKeycloakServer(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "GET" && strings.HasSuffix(r.URL.Path, "/organizations/org-123/domains") {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(expectedDomains)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	})
	defer server.Close()

	client := createTestAdminClient(server.URL)
	ctx := context.Background()

	domains, err := client.GetOrganizationDomains(ctx, "org-123")
	if err != nil {
		t.Fatalf("GetOrganizationDomains failed: %v", err)
	}

	if len(domains) != 2 {
		t.Errorf("Expected 2 domains, got %d", len(domains))
	}

	if domains[0].Name != "example.com" {
		t.Errorf("Expected domain 'example.com', got '%s'", domains[0].Name)
	}
}

// =============================================================================
// USER ORGANIZATION TESTS
// =============================================================================

func TestGetUserOrganizations(t *testing.T) {
	expectedOrgs := []OrganizationRepresentation{
		{ID: "org-1", Name: "Org 1", Alias: "org-1"},
		{ID: "org-2", Name: "Org 2", Alias: "org-2"},
	}

	server := mockKeycloakServer(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "GET" && strings.HasSuffix(r.URL.Path, "/users/user-123/organizations") {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(expectedOrgs)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	})
	defer server.Close()

	client := createTestAdminClient(server.URL)
	ctx := context.Background()

	orgs, err := client.GetUserOrganizations(ctx, "user-123")
	if err != nil {
		t.Fatalf("GetUserOrganizations failed: %v", err)
	}

	if len(orgs) != 2 {
		t.Errorf("Expected 2 organizations, got %d", len(orgs))
	}
}

// =============================================================================
// HELPER FUNCTION TESTS
// =============================================================================

func TestBuildOrganizationAlias(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"Test Store", "test-store"},
		{"My Store 123", "my-store-123"},
		{"Store-Name", "store-name"},
		{"Store@#$Name", "storename"},
		{"  Spaces  ", "spaces"},
		{"UPPERCASE", "uppercase"},
		{"a-very-long-store-name-that-exceeds-one-hundred-characters-and-should-be-truncated-to-fit-within-limits-yes", "a-very-long-store-name-that-exceeds-one-hundred-characters-and-should-be-truncated-to-fit-within-lim"},
		{"---leading-trailing---", "leading-trailing"},
	}

	for _, tt := range tests {
		result := BuildOrganizationAlias(tt.input)
		if result != tt.expected {
			t.Errorf("BuildOrganizationAlias(%q) = %q, expected %q", tt.input, result, tt.expected)
		}
	}
}

func TestCreateOrganizationForTenant(t *testing.T) {
	var receivedOrg OrganizationRepresentation

	server := mockKeycloakServer(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" && strings.Contains(r.URL.Path, "/organizations") {
			json.NewDecoder(r.Body).Decode(&receivedOrg)
			w.Header().Set("Location", "http://test/admin/realms/test-realm/organizations/org-123")
			w.WriteHeader(http.StatusCreated)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	})
	defer server.Close()

	client := createTestAdminClient(server.URL)
	ctx := context.Background()

	orgID, err := client.CreateOrganizationForTenant(ctx, "tenant-uuid-123", "My Test Store", "my-test-store")
	if err != nil {
		t.Fatalf("CreateOrganizationForTenant failed: %v", err)
	}

	if orgID != "org-123" {
		t.Errorf("Expected org ID 'org-123', got '%s'", orgID)
	}

	if receivedOrg.Name != "My Test Store" {
		t.Errorf("Expected name 'My Test Store', got '%s'", receivedOrg.Name)
	}

	if receivedOrg.Alias != "my-test-store" {
		t.Errorf("Expected alias 'my-test-store', got '%s'", receivedOrg.Alias)
	}

	if receivedOrg.Attributes["tenant_id"][0] != "tenant-uuid-123" {
		t.Errorf("Expected tenant_id 'tenant-uuid-123', got '%s'", receivedOrg.Attributes["tenant_id"][0])
	}
}

// =============================================================================
// PAGINATION TESTS
// =============================================================================

func TestListOrganizationsWithPagination(t *testing.T) {
	server := mockKeycloakServer(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "GET" && strings.Contains(r.URL.Path, "/organizations") {
			// Verify pagination parameters
			first := r.URL.Query().Get("first")
			max := r.URL.Query().Get("max")

			if first != "10" || max != "20" {
				t.Errorf("Expected first=10&max=20, got first=%s&max=%s", first, max)
			}

			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode([]OrganizationRepresentation{
				{ID: "org-1", Name: "Org 1"},
			})
			return
		}
		w.WriteHeader(http.StatusNotFound)
	})
	defer server.Close()

	client := createTestAdminClient(server.URL)
	ctx := context.Background()

	orgs, err := client.ListOrganizationsWithPagination(ctx, 10, 20)
	if err != nil {
		t.Fatalf("ListOrganizationsWithPagination failed: %v", err)
	}

	if len(orgs) != 1 {
		t.Errorf("Expected 1 organization, got %d", len(orgs))
	}
}

func TestGetOrganizationMembersWithPagination(t *testing.T) {
	server := mockKeycloakServer(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "GET" && strings.Contains(r.URL.Path, "/organizations/org-123/members") {
			// Verify pagination parameters
			first := r.URL.Query().Get("first")
			max := r.URL.Query().Get("max")

			if first != "0" || max != "50" {
				t.Errorf("Expected first=0&max=50, got first=%s&max=%s", first, max)
			}

			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode([]OrganizationMemberRepresentation{
				{ID: "user-1", Username: "user1"},
			})
			return
		}
		w.WriteHeader(http.StatusNotFound)
	})
	defer server.Close()

	client := createTestAdminClient(server.URL)
	ctx := context.Background()

	members, err := client.GetOrganizationMembersWithPagination(ctx, "org-123", 0, 50)
	if err != nil {
		t.Fatalf("GetOrganizationMembersWithPagination failed: %v", err)
	}

	if len(members) != 1 {
		t.Errorf("Expected 1 member, got %d", len(members))
	}
}
