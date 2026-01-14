package testutil

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

// ============================================
// RBAC TEST TEMPLATES
// ============================================

// RBACTestConfig defines the configuration for RBAC tests
type RBACTestConfig struct {
	Permission    string
	MinPriority   int
	AllowedRoles  []string
	DeniedRoles   []string
}

// RoleWithPriority represents a role and its priority level
type RoleWithPriority struct {
	Name     string
	Priority int
}

// Standard role priorities matching packages/go-shared/rbac/permissions.go
var StandardRoles = []RoleWithPriority{
	{Name: "viewer", Priority: 10},
	{Name: "customer_support", Priority: 50},
	{Name: "store_manager", Priority: 70},
	{Name: "store_admin", Priority: 90},
	{Name: "store_owner", Priority: 100},
}

// Permission constants for testing
const (
	// Orders permissions
	TestPermOrdersView   = "orders:view"
	TestPermOrdersCreate = "orders:create"
	TestPermOrdersEdit   = "orders:update"
	TestPermOrdersDelete = "orders:delete"
	TestPermOrdersCancel = "orders:cancel"
	TestPermOrdersRefund = "orders:refund"

	// Products permissions
	TestPermProductsView   = "catalog:products:view"
	TestPermProductsCreate = "catalog:products:create"
	TestPermProductsEdit   = "catalog:products:update"
	TestPermProductsDelete = "catalog:products:delete"

	// Staff permissions
	TestPermStaffView   = "team:staff:view"
	TestPermStaffCreate = "team:staff:create"
	TestPermStaffEdit   = "team:staff:update"
	TestPermStaffDelete = "team:staff:delete"

	// Settings permissions
	TestPermSettingsView = "settings:view"
	TestPermSettingsEdit = "settings:update"

	// Priority levels
	PriorityViewer          = 10
	PriorityCustomerSupport = 50
	PriorityStoreManager    = 70
	PriorityStoreAdmin      = 90
	PriorityStoreOwner      = 100
)

// ============================================
// RBAC TEST HELPERS
// ============================================

// CreateTestUserWithRole creates a test user with specific role and permissions
func CreateTestUserWithRole(tenantID, role string, priority int, permissions []string) TestUser {
	user := CreateTestUser(tenantID)
	user.Role = role
	user.Permissions = permissions
	return user
}

// SetupRBACTestRouter creates a router with RBAC middleware for testing
func SetupRBACTestRouter(
	requirePermissionMiddleware func(permission string) gin.HandlerFunc,
	requireMinPriorityMiddleware func(minPriority int) gin.HandlerFunc,
) *gin.Engine {
	gin.SetMode(gin.TestMode)
	router := gin.New()

	// Test endpoint requiring specific permission
	router.GET("/permission-test/:permission", func(c *gin.Context) {
		permission := c.Param("permission")
		middleware := requirePermissionMiddleware(permission)
		middleware(c)
		if !c.IsAborted() {
			c.JSON(http.StatusOK, gin.H{"status": "authorized"})
		}
	})

	// Test endpoint requiring minimum priority
	router.GET("/priority-test/:minPriority", func(c *gin.Context) {
		// Note: In real implementation, parse minPriority from param
		c.JSON(http.StatusOK, gin.H{"status": "authorized"})
	})

	return router
}

// ============================================
// PERMISSION TEST SUITE TEMPLATES
// ============================================

// RBACTestSuite represents a complete RBAC test suite
type RBACTestSuite struct {
	t          *testing.T
	tenantID   string
	router     *gin.Engine
	jwtSecret  string
}

// NewRBACTestSuite creates a new RBAC test suite
func NewRBACTestSuite(t *testing.T, router *gin.Engine) *RBACTestSuite {
	return &RBACTestSuite{
		t:         t,
		tenantID:  "test-tenant-rbac",
		router:    router,
		jwtSecret: "test-secret-key",
	}
}

// TestRequirePermission tests single permission requirement
func (s *RBACTestSuite) TestRequirePermission(permission string, allowedRoles, deniedRoles []RoleWithPriority) {
	s.t.Helper()

	// Test allowed roles
	for _, role := range allowedRoles {
		s.t.Run(fmt.Sprintf("RBAC_Allowed_%s_%s", permission, role.Name), func(t *testing.T) {
			user := CreateTestUserWithRole(s.tenantID, role.Name, role.Priority, []string{permission})
			token := GenerateTestJWT(user, s.jwtSecret, 3600)

			req := httptest.NewRequest(http.MethodGet, "/protected", nil)
			req.Header.Set("Authorization", "Bearer "+token)
			req.Header.Set("X-Tenant-ID", s.tenantID)

			w := httptest.NewRecorder()
			s.router.ServeHTTP(w, req)

			if w.Code == http.StatusForbidden || w.Code == http.StatusUnauthorized {
				t.Errorf("Expected access granted for role %s with permission %s, got status %d",
					role.Name, permission, w.Code)
			}
		})
	}

	// Test denied roles
	for _, role := range deniedRoles {
		s.t.Run(fmt.Sprintf("RBAC_Denied_%s_%s", permission, role.Name), func(t *testing.T) {
			user := CreateTestUserWithRole(s.tenantID, role.Name, role.Priority, []string{})
			token := GenerateTestJWT(user, s.jwtSecret, 3600)

			req := httptest.NewRequest(http.MethodGet, "/protected", nil)
			req.Header.Set("Authorization", "Bearer "+token)
			req.Header.Set("X-Tenant-ID", s.tenantID)

			w := httptest.NewRecorder()
			s.router.ServeHTTP(w, req)

			if w.Code == http.StatusOK {
				t.Errorf("Expected access denied for role %s without permission %s, got status %d",
					role.Name, permission, w.Code)
			}
		})
	}
}

// TestRequireMinPriority tests minimum priority requirement
func (s *RBACTestSuite) TestRequireMinPriority(minPriority int) {
	s.t.Helper()

	for _, role := range StandardRoles {
		expectedAllowed := role.Priority >= minPriority

		s.t.Run(fmt.Sprintf("RBAC_Priority_%d_%s", minPriority, role.Name), func(t *testing.T) {
			user := CreateTestUserWithRole(s.tenantID, role.Name, role.Priority, []string{})
			token := GenerateTestJWT(user, s.jwtSecret, 3600)

			req := httptest.NewRequest(http.MethodGet, "/priority-protected", nil)
			req.Header.Set("Authorization", "Bearer "+token)
			req.Header.Set("X-Tenant-ID", s.tenantID)

			w := httptest.NewRecorder()
			s.router.ServeHTTP(w, req)

			if expectedAllowed && (w.Code == http.StatusForbidden || w.Code == http.StatusUnauthorized) {
				t.Errorf("Expected access granted for role %s (priority %d) with min priority %d, got status %d",
					role.Name, role.Priority, minPriority, w.Code)
			}
			if !expectedAllowed && w.Code == http.StatusOK {
				t.Errorf("Expected access denied for role %s (priority %d) with min priority %d, got status %d",
					role.Name, role.Priority, minPriority, w.Code)
			}
		})
	}
}

// ============================================
// CROSS-TENANT RBAC TESTS
// ============================================

// TestCrossTenantRBACIsolation verifies RBAC permissions don't leak across tenants
func TestCrossTenantRBACIsolation(t *testing.T, router *gin.Engine, jwtSecret string) {
	tenantA := "tenant-a-rbac"
	tenantB := "tenant-b-rbac"

	testCases := []struct {
		name           string
		userTenant     string
		requestTenant  string
		permission     string
		expectAccess   bool
	}{
		{
			name:          "Same tenant access allowed",
			userTenant:    tenantA,
			requestTenant: tenantA,
			permission:    TestPermOrdersView,
			expectAccess:  true,
		},
		{
			name:          "Cross tenant access denied",
			userTenant:    tenantA,
			requestTenant: tenantB,
			permission:    TestPermOrdersView,
			expectAccess:  false,
		},
		{
			name:          "Admin from tenant A cannot access tenant B",
			userTenant:    tenantA,
			requestTenant: tenantB,
			permission:    TestPermStaffEdit,
			expectAccess:  false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			user := CreateTestUserWithRole(tc.userTenant, "store_admin", PriorityStoreAdmin, []string{tc.permission})
			token := GenerateTestJWT(user, jwtSecret, 3600)

			req := httptest.NewRequest(http.MethodGet, "/protected", nil)
			req.Header.Set("Authorization", "Bearer "+token)
			req.Header.Set("X-Tenant-ID", tc.requestTenant)

			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)

			gotAccess := w.Code == http.StatusOK
			if gotAccess != tc.expectAccess {
				t.Errorf("Expected access=%v, got access=%v (status %d)", tc.expectAccess, gotAccess, w.Code)
			}
		})
	}
}

// ============================================
// ROLE HIERARCHY TESTS
// ============================================

// TestRoleHierarchy tests that role priority is enforced correctly
func TestRoleHierarchy(t *testing.T, router *gin.Engine, jwtSecret, tenantID string) {
	hierarchyTests := []struct {
		name            string
		endpoint        string
		requiredLevel   string
		allowedRoles    []string
		deniedRoles     []string
	}{
		{
			name:          "Owner-only endpoints",
			endpoint:      "/owner-only",
			requiredLevel: "owner",
			allowedRoles:  []string{"store_owner"},
			deniedRoles:   []string{"store_admin", "store_manager", "customer_support", "viewer"},
		},
		{
			name:          "Admin-or-above endpoints",
			endpoint:      "/admin-only",
			requiredLevel: "admin",
			allowedRoles:  []string{"store_owner", "store_admin"},
			deniedRoles:   []string{"store_manager", "customer_support", "viewer"},
		},
		{
			name:          "Manager-or-above endpoints",
			endpoint:      "/manager-only",
			requiredLevel: "manager",
			allowedRoles:  []string{"store_owner", "store_admin", "store_manager"},
			deniedRoles:   []string{"customer_support", "viewer"},
		},
	}

	for _, tc := range hierarchyTests {
		t.Run(tc.name, func(t *testing.T) {
			// Test allowed roles
			for _, roleName := range tc.allowedRoles {
				role := getRoleByName(roleName)
				user := CreateTestUserWithRole(tenantID, role.Name, role.Priority, []string{})
				token := GenerateTestJWT(user, jwtSecret, 3600)

				req := httptest.NewRequest(http.MethodGet, tc.endpoint, nil)
				req.Header.Set("Authorization", "Bearer "+token)
				req.Header.Set("X-Tenant-ID", tenantID)

				w := httptest.NewRecorder()
				router.ServeHTTP(w, req)

				if w.Code == http.StatusForbidden || w.Code == http.StatusUnauthorized {
					t.Errorf("Role %s should have access to %s", roleName, tc.endpoint)
				}
			}

			// Test denied roles
			for _, roleName := range tc.deniedRoles {
				role := getRoleByName(roleName)
				user := CreateTestUserWithRole(tenantID, role.Name, role.Priority, []string{})
				token := GenerateTestJWT(user, jwtSecret, 3600)

				req := httptest.NewRequest(http.MethodGet, tc.endpoint, nil)
				req.Header.Set("Authorization", "Bearer "+token)
				req.Header.Set("X-Tenant-ID", tenantID)

				w := httptest.NewRecorder()
				router.ServeHTTP(w, req)

				if w.Code == http.StatusOK {
					t.Errorf("Role %s should NOT have access to %s", roleName, tc.endpoint)
				}
			}
		})
	}
}

// getRoleByName returns role details by name
func getRoleByName(name string) RoleWithPriority {
	for _, role := range StandardRoles {
		if role.Name == name {
			return role
		}
	}
	return RoleWithPriority{Name: name, Priority: 0}
}

// ============================================
// PERMISSION COMBINATION TESTS
// ============================================

// TestRequireAnyPermission tests OR logic for permissions
func TestRequireAnyPermission(t *testing.T, router *gin.Engine, jwtSecret, tenantID string) {
	testCases := []struct {
		name             string
		requiredPerms    []string
		userPerms        []string
		expectAccess     bool
	}{
		{
			name:          "Has first of required permissions",
			requiredPerms: []string{TestPermOrdersView, TestPermOrdersEdit},
			userPerms:     []string{TestPermOrdersView},
			expectAccess:  true,
		},
		{
			name:          "Has second of required permissions",
			requiredPerms: []string{TestPermOrdersView, TestPermOrdersEdit},
			userPerms:     []string{TestPermOrdersEdit},
			expectAccess:  true,
		},
		{
			name:          "Has both required permissions",
			requiredPerms: []string{TestPermOrdersView, TestPermOrdersEdit},
			userPerms:     []string{TestPermOrdersView, TestPermOrdersEdit},
			expectAccess:  true,
		},
		{
			name:          "Has none of required permissions",
			requiredPerms: []string{TestPermOrdersView, TestPermOrdersEdit},
			userPerms:     []string{TestPermProductsView},
			expectAccess:  false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			user := CreateTestUserWithRole(tenantID, "store_admin", PriorityStoreAdmin, tc.userPerms)
			token := GenerateTestJWT(user, jwtSecret, 3600)

			req := httptest.NewRequest(http.MethodGet, "/any-permission", nil)
			req.Header.Set("Authorization", "Bearer "+token)
			req.Header.Set("X-Tenant-ID", tenantID)

			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)

			gotAccess := w.Code == http.StatusOK
			if gotAccess != tc.expectAccess {
				t.Errorf("Expected access=%v with perms %v requiring any of %v, got status %d",
					tc.expectAccess, tc.userPerms, tc.requiredPerms, w.Code)
			}
		})
	}
}

// TestRequireAllPermissions tests AND logic for permissions
func TestRequireAllPermissions(t *testing.T, router *gin.Engine, jwtSecret, tenantID string) {
	testCases := []struct {
		name             string
		requiredPerms    []string
		userPerms        []string
		expectAccess     bool
	}{
		{
			name:          "Has all required permissions",
			requiredPerms: []string{TestPermOrdersView, TestPermOrdersEdit},
			userPerms:     []string{TestPermOrdersView, TestPermOrdersEdit, TestPermProductsView},
			expectAccess:  true,
		},
		{
			name:          "Missing one required permission",
			requiredPerms: []string{TestPermOrdersView, TestPermOrdersEdit},
			userPerms:     []string{TestPermOrdersView},
			expectAccess:  false,
		},
		{
			name:          "Has none of required permissions",
			requiredPerms: []string{TestPermOrdersView, TestPermOrdersEdit},
			userPerms:     []string{TestPermProductsView},
			expectAccess:  false,
		},
		{
			name:          "Has exact required permissions",
			requiredPerms: []string{TestPermOrdersView, TestPermOrdersEdit},
			userPerms:     []string{TestPermOrdersView, TestPermOrdersEdit},
			expectAccess:  true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			user := CreateTestUserWithRole(tenantID, "store_admin", PriorityStoreAdmin, tc.userPerms)
			token := GenerateTestJWT(user, jwtSecret, 3600)

			req := httptest.NewRequest(http.MethodGet, "/all-permissions", nil)
			req.Header.Set("Authorization", "Bearer "+token)
			req.Header.Set("X-Tenant-ID", tenantID)

			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)

			gotAccess := w.Code == http.StatusOK
			if gotAccess != tc.expectAccess {
				t.Errorf("Expected access=%v with perms %v requiring all of %v, got status %d",
					tc.expectAccess, tc.userPerms, tc.requiredPerms, w.Code)
			}
		})
	}
}

// ============================================
// EDGE CASE TESTS
// ============================================

// TestRBACEdgeCases tests edge cases in RBAC implementation
func TestRBACEdgeCases(t *testing.T, router *gin.Engine, jwtSecret, tenantID string) {
	testCases := []struct {
		name         string
		setupUser    func() (TestUser, string)
		expectStatus int
	}{
		{
			name: "Empty permissions array",
			setupUser: func() (TestUser, string) {
				user := CreateTestUserWithRole(tenantID, "viewer", PriorityViewer, []string{})
				token := GenerateTestJWT(user, jwtSecret, 3600)
				return user, token
			},
			expectStatus: http.StatusForbidden,
		},
		{
			name: "Nil permissions",
			setupUser: func() (TestUser, string) {
				user := CreateTestUser(tenantID)
				user.Permissions = nil
				token := GenerateTestJWT(user, jwtSecret, 3600)
				return user, token
			},
			expectStatus: http.StatusForbidden,
		},
		{
			name: "Invalid permission format",
			setupUser: func() (TestUser, string) {
				user := CreateTestUserWithRole(tenantID, "admin", PriorityStoreAdmin, []string{"invalid"})
				token := GenerateTestJWT(user, jwtSecret, 3600)
				return user, token
			},
			expectStatus: http.StatusForbidden,
		},
		{
			name: "Case sensitivity in permissions",
			setupUser: func() (TestUser, string) {
				user := CreateTestUserWithRole(tenantID, "admin", PriorityStoreAdmin, []string{"ORDERS:VIEW"})
				token := GenerateTestJWT(user, jwtSecret, 3600)
				return user, token
			},
			expectStatus: http.StatusForbidden, // Permissions should be case-sensitive
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			_, token := tc.setupUser()

			req := httptest.NewRequest(http.MethodGet, "/protected", nil)
			req.Header.Set("Authorization", "Bearer "+token)
			req.Header.Set("X-Tenant-ID", tenantID)

			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)

			if w.Code != tc.expectStatus {
				t.Errorf("Expected status %d, got %d", tc.expectStatus, w.Code)
			}
		})
	}
}

// ============================================
// RESOURCE-SPECIFIC PERMISSION TESTS
// ============================================

// ResourcePermissionTest defines a resource-specific permission test
type ResourcePermissionTest struct {
	Resource       string
	ViewPerm       string
	CreatePerm     string
	EditPerm       string
	DeletePerm     string
}

// StandardResourcePermissions returns standard CRUD permission tests
func StandardResourcePermissions() []ResourcePermissionTest {
	return []ResourcePermissionTest{
		{
			Resource:   "orders",
			ViewPerm:   TestPermOrdersView,
			CreatePerm: TestPermOrdersCreate,
			EditPerm:   TestPermOrdersEdit,
			DeletePerm: TestPermOrdersDelete,
		},
		{
			Resource:   "products",
			ViewPerm:   TestPermProductsView,
			CreatePerm: TestPermProductsCreate,
			EditPerm:   TestPermProductsEdit,
			DeletePerm: TestPermProductsDelete,
		},
		{
			Resource:   "staff",
			ViewPerm:   TestPermStaffView,
			CreatePerm: TestPermStaffCreate,
			EditPerm:   TestPermStaffEdit,
			DeletePerm: TestPermStaffDelete,
		},
	}
}

// TestResourcePermissions tests CRUD permissions for a resource
func TestResourcePermissions(t *testing.T, router *gin.Engine, jwtSecret, tenantID string, resource ResourcePermissionTest) {
	operations := []struct {
		name       string
		method     string
		endpoint   string
		permission string
	}{
		{"View", http.MethodGet, "/" + resource.Resource, resource.ViewPerm},
		{"Create", http.MethodPost, "/" + resource.Resource, resource.CreatePerm},
		{"Edit", http.MethodPut, "/" + resource.Resource + "/123", resource.EditPerm},
		{"Delete", http.MethodDelete, "/" + resource.Resource + "/123", resource.DeletePerm},
	}

	for _, op := range operations {
		// Test with permission
		t.Run(fmt.Sprintf("%s_%s_WithPerm", resource.Resource, op.name), func(t *testing.T) {
			user := CreateTestUserWithRole(tenantID, "admin", PriorityStoreAdmin, []string{op.permission})
			token := GenerateTestJWT(user, jwtSecret, 3600)

			req := httptest.NewRequest(op.method, op.endpoint, nil)
			req.Header.Set("Authorization", "Bearer "+token)
			req.Header.Set("X-Tenant-ID", tenantID)

			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)

			if w.Code == http.StatusForbidden {
				t.Errorf("Expected access with permission %s, got 403", op.permission)
			}
		})

		// Test without permission
		t.Run(fmt.Sprintf("%s_%s_WithoutPerm", resource.Resource, op.name), func(t *testing.T) {
			user := CreateTestUserWithRole(tenantID, "admin", PriorityStoreAdmin, []string{})
			token := GenerateTestJWT(user, jwtSecret, 3600)

			req := httptest.NewRequest(op.method, op.endpoint, nil)
			req.Header.Set("Authorization", "Bearer "+token)
			req.Header.Set("X-Tenant-ID", tenantID)

			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)

			if w.Code == http.StatusOK {
				t.Errorf("Expected 403 without permission %s, got %d", op.permission, w.Code)
			}
		})
	}
}
