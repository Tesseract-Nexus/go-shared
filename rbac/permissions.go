package rbac

// Permission constants for all services
// These should match the permissions defined in staff-service migrations

// Orders permissions - matches database exactly
const (
	PermissionOrdersRead    = "orders:view"
	PermissionOrdersView    = "orders:view"
	PermissionOrdersCreate  = "orders:create"
	PermissionOrdersUpdate  = "orders:edit"
	PermissionOrdersEdit    = "orders:edit"
	PermissionOrdersCancel  = "orders:cancel"
	PermissionOrdersRefund  = "orders:refund"
	PermissionOrdersShip    = "orders:fulfill"
	PermissionOrdersFulfill = "orders:fulfill"
	PermissionOrdersExport  = "orders:export"
)

// Returns permissions
const (
	PermissionReturnsRead    = "returns:read"
	PermissionReturnsCreate  = "returns:create"
	PermissionReturnsApprove = "returns:approve"
	PermissionReturnsReject  = "returns:reject"
	PermissionReturnsRefund  = "returns:refund"
	PermissionReturnsInspect = "returns:inspect"
)

// Payments permissions
const (
	PermissionPaymentsRead          = "payments:read"
	PermissionPaymentsRefund        = "payments:refund"
	PermissionPaymentsGatewayRead   = "payments:gateway:read"
	PermissionPaymentsGatewayManage = "payments:gateway:manage"
	PermissionPaymentsFeesManage    = "payments:fees:manage"
)

// Payment Methods Configuration permissions
// Granular permissions for multi-region payment methods management
const (
	PermissionPaymentsMethodsView   = "payments:methods:view"   // View available payment methods and configs
	PermissionPaymentsMethodsEnable = "payments:methods:enable" // Enable/disable payment methods for the store
	PermissionPaymentsMethodsConfig = "payments:methods:config" // Configure credentials (Owner only - sensitive)
	PermissionPaymentsMethodsTest   = "payments:methods:test"   // Test payment method connections
)

// Products permissions - uses catalog:products:* format from database
const (
	PermissionProductsRead    = "catalog:products:view"
	PermissionProductsView    = "catalog:products:view"
	PermissionProductsCreate  = "catalog:products:create"
	PermissionProductsUpdate  = "catalog:products:edit"
	PermissionProductsEdit    = "catalog:products:edit"
	PermissionProductsDelete  = "catalog:products:delete"
	PermissionProductsPublish = "catalog:products:publish"
	PermissionProductsPricing = "catalog:pricing:manage"
	PermissionProductsImport  = "catalog:products:import"
	PermissionProductsExport  = "catalog:products:export"
)

// Categories permissions - uses catalog:categories:* format from database
const (
	PermissionCategoriesRead   = "catalog:categories:view"
	PermissionCategoriesView   = "catalog:categories:view"
	PermissionCategoriesCreate = "catalog:categories:manage"
	PermissionCategoriesUpdate = "catalog:categories:manage"
	PermissionCategoriesManage = "catalog:categories:manage"
	PermissionCategoriesDelete = "catalog:categories:manage"
	PermissionCatalogAll       = "catalog:*"
)

// Inventory permissions
const (
	PermissionInventoryRead   = "inventory:stock:view"
	PermissionInventoryUpdate = "inventory:stock:adjust"
	PermissionInventoryAdjust = "inventory:stock:adjust"

	// Additional granular inventory permissions
	PermissionInventoryHistoryView      = "inventory:history:view"
	PermissionInventoryAlertsManage     = "inventory:alerts:manage"
	PermissionInventoryTransfersView    = "inventory:transfers:view"
	PermissionInventoryTransfersManage  = "inventory:transfers:manage"
	PermissionInventoryWarehousesView   = "inventory:warehouses:view"
	PermissionInventoryWarehousesManage = "inventory:warehouses:manage"
)

// Vendors permissions (marketplace)
const (
	PermissionVendorsRead    = "vendors:read"
	PermissionVendorsCreate  = "vendors:create"
	PermissionVendorsUpdate  = "vendors:update"
	PermissionVendorsApprove = "vendors:approve"
	PermissionVendorsManage  = "vendors:manage"
	PermissionVendorsPayout  = "vendors:payout"
)

// Staff permissions - uses team:staff:* format from database
const (
	PermissionStaffRead       = "team:staff:view"
	PermissionStaffView       = "team:staff:view"
	PermissionStaffCreate     = "team:staff:create"
	PermissionStaffUpdate     = "team:staff:edit"
	PermissionStaffEdit       = "team:staff:edit"
	PermissionStaffDelete     = "team:staff:delete"
	PermissionStaffInvite     = "team:staff:create" // invite uses create permission
	PermissionStaffImport     = "team:staff:create"
	PermissionStaffExport     = "team:staff:view"
	PermissionStaffRoleAssign = "team:roles:assign"
)

// Roles permissions - uses team:roles:* format from database
const (
	PermissionRolesRead   = "team:roles:view"
	PermissionRolesView   = "team:roles:view"
	PermissionRolesCreate = "team:roles:create"
	PermissionRolesUpdate = "team:roles:edit"
	PermissionRolesEdit   = "team:roles:edit"
	PermissionRolesDelete = "team:roles:delete"
	PermissionRolesAssign = "team:roles:assign"
)

// Department permissions - uses team:departments:* format from database
const (
	PermissionDepartmentsRead   = "team:departments:view"
	PermissionDepartmentsView   = "team:departments:view"
	PermissionDepartmentsCreate = "team:departments:manage"
	PermissionDepartmentsUpdate = "team:departments:manage"
	PermissionDepartmentsManage = "team:departments:manage"
	PermissionDepartmentsDelete = "team:departments:manage"
)

// Team permissions - uses team:teams:* format from database
const (
	PermissionTeamsRead   = "team:teams:view"
	PermissionTeamsView   = "team:teams:view"
	PermissionTeamsCreate = "team:teams:manage"
	PermissionTeamsUpdate = "team:teams:manage"
	PermissionTeamsManage = "team:teams:manage"
	PermissionTeamsDelete = "team:teams:manage"
)

// Customers permissions - matches database exactly
const (
	PermissionCustomersRead   = "customers:view"
	PermissionCustomersView   = "customers:view"
	PermissionCustomersCreate = "customers:create"
	PermissionCustomersUpdate = "customers:edit"
	PermissionCustomersEdit   = "customers:edit"
	PermissionCustomersDelete = "customers:delete"
	PermissionCustomersExport = "customers:export"
	PermissionCustomersLock   = "customers:lock" // Lock/unlock customer accounts
)

// Tickets permissions
const (
	PermissionTicketsRead     = "tickets:read"
	PermissionTicketsCreate   = "tickets:create"
	PermissionTicketsUpdate   = "tickets:update"
	PermissionTicketsAssign   = "tickets:assign"
	PermissionTicketsEscalate = "tickets:escalate"
	PermissionTicketsResolve  = "tickets:resolve"
)

// Coupons permissions - these map to marketing:coupons:* in database
const (
	PermissionCouponsRead   = "marketing:coupons:view"   // Maps to database permission
	PermissionCouponsCreate = "marketing:coupons:manage" // Maps to database permission
	PermissionCouponsUpdate = "marketing:coupons:manage" // Maps to database permission
	PermissionCouponsDelete = "marketing:coupons:manage" // Maps to database permission
)

// Reviews permissions
const (
	PermissionReviewsRead     = "reviews:read"
	PermissionReviewsModerate = "reviews:moderate"
	PermissionReviewsRespond  = "reviews:respond"
	PermissionReviewsDelete   = "reviews:delete"
)

// Analytics permissions
const (
	PermissionAnalyticsRead          = "analytics:dashboard:view"
	PermissionAnalyticsDashboardView = "analytics:dashboard:view"
	PermissionAnalyticsReportsView   = "analytics:reports:view"
	PermissionAnalyticsSalesView     = "analytics:sales:view"
	PermissionAnalyticsProductsView  = "analytics:products:view"
	PermissionAnalyticsRealtimeView  = "analytics:realtime:view"
	PermissionAnalyticsExport        = "analytics:reports:export"
)

// Audit permissions
const (
	PermissionAuditRead   = "audit:read"
	PermissionAuditExport = "audit:export"
)

// Settings permissions
const (
	PermissionSettingsRead   = "settings:read"
	PermissionSettingsUpdate = "settings:update"
)

// Storefronts permissions
const (
	PermissionStorefrontsRead   = "storefronts:read"
	PermissionStorefrontsCreate = "storefronts:create"
	PermissionStorefrontsUpdate = "storefronts:update"
	PermissionStorefrontsDelete = "storefronts:delete"
)

// Shipping permissions
const (
	PermissionShippingRead   = "shipping:read"
	PermissionShippingCreate = "shipping:create"
	PermissionShippingUpdate = "shipping:update"
	PermissionShippingManage = "shipping:manage"
)

// Notifications permissions
const (
	PermissionNotificationsRead   = "notifications:read"
	PermissionNotificationsManage = "notifications:manage"
)

// Approvals permissions
const (
	PermissionApprovalsRead    = "approvals:read"
	PermissionApprovalsCreate  = "approvals:create"
	PermissionApprovalsApprove = "approvals:approve"
	PermissionApprovalsReject  = "approvals:reject"
	PermissionApprovalsManage  = "approvals:manage"
)

// Delegations permissions
const (
	PermissionDelegationsRead   = "delegations:read"   // Admin can view all delegations
	PermissionDelegationsManage = "delegations:manage" // Admin can manage any delegation
)

// Gift Cards permissions - match database migration (008_giftcards_tax_locations_permissions.up.sql)
const (
	PermissionGiftCardsView   = "giftcards:view"
	PermissionGiftCardsRead   = "giftcards:view" // Alias for backwards compatibility
	PermissionGiftCardsCreate = "giftcards:create"
	PermissionGiftCardsEdit   = "giftcards:edit"
	PermissionGiftCardsUpdate = "giftcards:edit" // Alias for backwards compatibility
	PermissionGiftCardsDelete = "giftcards:delete"
	PermissionGiftCardsRedeem = "giftcards:redeem"
	PermissionGiftCardsManage = "giftcards:edit" // Alias for backwards compatibility
)

// Marketing permissions - match database migration exactly
const (
	// Coupons
	PermissionMarketingCouponsView   = "marketing:coupons:view"
	PermissionMarketingCouponsManage = "marketing:coupons:manage"

	// Campaigns
	PermissionMarketingCampaignsView   = "marketing:campaigns:view"
	PermissionMarketingCampaignsManage = "marketing:campaigns:manage"

	// Email
	PermissionMarketingEmailSend = "marketing:email:send"

	// Reviews
	PermissionMarketingReviewsView     = "marketing:reviews:view"
	PermissionMarketingReviewsModerate = "marketing:reviews:moderate"

	// Banners
	PermissionMarketingBannersManage = "marketing:banners:manage"

	// Loyalty (from migration 008)
	PermissionMarketingLoyaltyView         = "marketing:loyalty:view"
	PermissionMarketingLoyaltyManage       = "marketing:loyalty:manage"
	PermissionMarketingLoyaltyPointsAdjust = "marketing:loyalty:points:adjust"

	// Abandoned Carts (from migration 008)
	PermissionMarketingCartsView    = "marketing:carts:view"
	PermissionMarketingCartsRecover = "marketing:carts:recover"

	// Segments (from migration 008)
	PermissionMarketingSegmentsView   = "marketing:segments:view"
	PermissionMarketingSegmentsManage = "marketing:segments:manage"

	// Legacy/Generic aliases for backward compatibility
	PermissionMarketingRead   = "marketing:coupons:view"   // Maps to view coupons
	PermissionMarketingCreate = "marketing:campaigns:manage" // Maps to manage campaigns
	PermissionMarketingUpdate = "marketing:campaigns:manage"
	PermissionMarketingManage = "marketing:campaigns:manage"
)

// Tax permissions
const (
	PermissionTaxRead   = "tax:read"
	PermissionTaxCreate = "tax:create"
	PermissionTaxUpdate = "tax:update"
	PermissionTaxManage = "tax:manage"
)

// Location permissions
const (
	PermissionLocationsRead   = "locations:read"
	PermissionLocationsCreate = "locations:create"
	PermissionLocationsUpdate = "locations:update"
	PermissionLocationsDelete = "locations:delete"
)

// Enterprise SSO Integration permissions (Owner-only)
const (
	PermissionIntegrationsSSOView    = "integrations:sso:view"
	PermissionIntegrationsSSOManage  = "integrations:sso:manage"
	PermissionIntegrationsSCIMView   = "integrations:scim:view"
	PermissionIntegrationsSCIMManage = "integrations:scim:manage"
)

// Ad Manager permissions - Campaign management
const (
	PermissionAdsCampaignsView    = "ads:campaigns:view"
	PermissionAdsCampaignsCreate  = "ads:campaigns:create"
	PermissionAdsCampaignsEdit    = "ads:campaigns:edit"
	PermissionAdsCampaignsDelete  = "ads:campaigns:delete"
	PermissionAdsCampaignsApprove = "ads:campaigns:approve"
	PermissionAdsCampaignsPause   = "ads:campaigns:pause"
)

// Ad Manager permissions - Creatives
const (
	PermissionAdsCreativesView    = "ads:creatives:view"
	PermissionAdsCreativesManage  = "ads:creatives:manage"
	PermissionAdsCreativesApprove = "ads:creatives:approve"
)

// Ad Manager permissions - Billing
const (
	PermissionAdsBillingView       = "ads:billing:view"
	PermissionAdsBillingManage     = "ads:billing:manage"
	PermissionAdsBillingRefund     = "ads:billing:refund"
	PermissionAdsBillingTiersManage = "ads:billing:tiers:manage"
	PermissionAdsRevenueView       = "ads:revenue:view"
)

// Ad Manager permissions - Targeting
const (
	PermissionAdsTargetingView   = "ads:targeting:view"
	PermissionAdsTargetingManage = "ads:targeting:manage"
)

// Ad Manager permissions - Analytics
const (
	PermissionAdsAnalyticsView   = "ads:analytics:view"
	PermissionAdsAnalyticsExport = "ads:analytics:export"
)

// Ad Manager permissions - Placements
const (
	PermissionAdsPlacementsView   = "ads:placements:view"
	PermissionAdsPlacementsManage = "ads:placements:manage"
)

// Wildcard permissions
const (
	PermissionOrdersAll      = "orders:*"
	PermissionProductsAll    = "products:*"
	PermissionStaffAll       = "staff:*"
	PermissionPaymentsAll    = "payments:*"
	PermissionCustomersAll   = "customers:*"
	PermissionAnalyticsAll   = "analytics:*"
	PermissionSettingsAll    = "settings:*"
	PermissionStorefrontsAll = "storefronts:*"
	PermissionAdsAll         = "ads:*"
)

// RoleToPermissions maps role names to their default permissions
// This is for reference - actual permissions are managed in staff-service
var RoleToPermissions = map[string][]string{
	"owner": {
		// Owner has all permissions (including billing, settings, etc.)
		PermissionOrdersAll, PermissionProductsAll, PermissionCatalogAll, PermissionStaffAll,
		PermissionPaymentsAll, PermissionCustomersAll, PermissionAnalyticsAll,
		PermissionSettingsAll, PermissionStorefrontsAll,
		// Approval permissions - owner can manage all approvals
		PermissionApprovalsManage, PermissionApprovalsRead, PermissionApprovalsCreate,
		PermissionApprovalsApprove, PermissionApprovalsReject,
		// Customer lock permission
		PermissionCustomersLock,
		// Payment methods - owner has full access including credential configuration
		PermissionPaymentsMethodsView, PermissionPaymentsMethodsEnable,
		PermissionPaymentsMethodsConfig, PermissionPaymentsMethodsTest,
	},
	"admin": {
		// Admin has most permissions except billing
		PermissionOrdersAll, PermissionProductsAll, PermissionCatalogAll, PermissionStaffRead,
		PermissionStaffInvite, PermissionPaymentsRead, PermissionPaymentsRefund,
		PermissionCustomersAll, PermissionAnalyticsAll,
		// Approval permissions - admin can approve and reject
		PermissionApprovalsRead, PermissionApprovalsApprove, PermissionApprovalsReject,
		// Customer lock permission
		PermissionCustomersLock,
		// Payment methods - admin can view, enable/disable, and test (NOT configure credentials)
		PermissionPaymentsMethodsView, PermissionPaymentsMethodsEnable, PermissionPaymentsMethodsTest,
		// Settings and storefront permissions - admin can modify store settings and themes
		PermissionSettingsRead, PermissionSettingsUpdate,
		PermissionStorefrontsRead, PermissionStorefrontsUpdate,
	},
	"manager": {
		// Manager can manage day-to-day operations
		PermissionOrdersRead, PermissionOrdersUpdate, PermissionOrdersCancel,
		PermissionOrdersRefund, PermissionProductsRead, PermissionProductsCreate,
		PermissionProductsUpdate, PermissionReturnsApprove, PermissionTicketsRead,
		PermissionTicketsUpdate, PermissionApprovalsRead,
		// Payment methods - manager can view for support context
		PermissionPaymentsMethodsView,
		// Settings and storefront permissions - manager can modify store settings and themes
		PermissionSettingsRead, PermissionSettingsUpdate,
		PermissionStorefrontsRead, PermissionStorefrontsUpdate,
	},
	"member": {
		// Member can do basic operations
		PermissionOrdersRead, PermissionOrdersUpdate, PermissionOrdersShip,
		PermissionProductsRead, PermissionProductsCreate, PermissionProductsUpdate,
		PermissionTicketsRead, PermissionTicketsCreate, PermissionReturnsRead,
	},
	"viewer": {
		// Viewer can only read
		PermissionOrdersRead, PermissionProductsRead, PermissionCustomersRead,
		PermissionAnalyticsRead, PermissionTicketsRead, PermissionReturnsRead,
	},
}
