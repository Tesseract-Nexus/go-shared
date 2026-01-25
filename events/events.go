// Package events provides shared event types for NATS messaging across services.
// All services should use these types to ensure consistent event schemas.
//
// Usage:
//
//	import "github.com/Tesseract-Nexus/go-shared/events"
//
//	// Create and publish an order event
//	event := events.NewOrderEvent(events.OrderCreated, tenantID)
//	event.OrderNumber = "ORD-001"
//	event.CustomerEmail = "customer@example.com"
//	if err := event.Validate(); err != nil {
//	    return err
//	}
//	publisher.Publish(event)
package events

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"
)

// Event type constants - use these when publishing/subscribing
const (
	// Order events
	OrderCreated   = "order.created"
	OrderConfirmed = "order.confirmed"
	OrderPaid      = "order.paid"
	OrderShipped   = "order.shipped"
	OrderDelivered = "order.delivered"
	OrderCancelled = "order.cancelled"
	OrderRefunded  = "order.refunded"

	// Payment events
	PaymentPending   = "payment.pending"
	PaymentCaptured  = "payment.captured"
	PaymentSucceeded = "payment.succeeded"
	PaymentFailed    = "payment.failed"
	PaymentRefunded  = "payment.refunded"

	// Customer events
	CustomerRegistered = "customer.registered"
	CustomerCreated    = "customer.created"
	CustomerUpdated    = "customer.updated"
	CustomerDeleted    = "customer.deleted"

	// Auth events
	PasswordReset      = "auth.password_reset"
	PasswordChanged    = "auth.password_changed"
	VerificationCode   = "auth.verification_code"
	EmailVerified      = "auth.email_verified"
	PhoneVerified      = "auth.phone_verified"
	LoginSuccess       = "auth.login_success"
	LoginFailed        = "auth.login_failed"
	AccountLocked      = "auth.account_locked"
	AccountUnlocked    = "auth.account_unlocked"

	// Inventory events
	InventoryLowStock    = "inventory.low_stock"
	InventoryOutOfStock  = "inventory.out_of_stock"
	InventoryRestocked   = "inventory.restocked"
	InventoryAdjusted    = "inventory.adjusted"

	// Product events
	ProductCreated   = "product.created"
	ProductUpdated   = "product.updated"
	ProductDeleted   = "product.deleted"
	ProductPublished = "product.published"
	ProductArchived  = "product.archived"

	// Return events
	ReturnRequested = "return.requested"
	ReturnApproved  = "return.approved"
	ReturnRejected  = "return.rejected"
	ReturnCompleted = "return.completed"

	// Review events
	ReviewCreated   = "review.created"
	ReviewApproved  = "review.approved"
	ReviewRejected  = "review.rejected"

	// Coupon events
	CouponCreated = "coupon.created"
	CouponApplied = "coupon.applied"
	CouponExpired = "coupon.expired"
	CouponUpdated = "coupon.updated"
	CouponDeleted = "coupon.deleted"

	// Vendor events
	VendorCreated     = "vendor.created"
	VendorUpdated     = "vendor.updated"
	VendorApproved    = "vendor.approved"
	VendorRejected    = "vendor.rejected"
	VendorSuspended   = "vendor.suspended"
	VendorReactivated = "vendor.reactivated"

	// Gift card events
	GiftCardCreated    = "gift_card.created"
	GiftCardActivated  = "gift_card.activated"
	GiftCardApplied    = "gift_card.applied"
	GiftCardExpired    = "gift_card.expired"
	GiftCardRefunded   = "gift_card.refunded"

	// Support ticket events
	TicketCreated        = "ticket.created"
	TicketUpdated        = "ticket.updated"
	TicketAssigned       = "ticket.assigned"
	TicketStatusChanged  = "ticket.status_changed"
	TicketCommentAdded   = "ticket.comment_added"
	TicketResolved       = "ticket.resolved"
	TicketClosed         = "ticket.closed"
	TicketReopened       = "ticket.reopened"

	// Staff events
	StaffCreated     = "staff.created"
	StaffUpdated     = "staff.updated"
	StaffDeactivated = "staff.deactivated"
	StaffReactivated = "staff.reactivated"
	StaffRoleChanged = "staff.role_changed"

	// Tenant events
	TenantCreated              = "tenant.created"
	TenantActivated            = "tenant.activated"
	TenantDeactivated          = "tenant.deactivated"
	TenantSettingsUpdated      = "tenant.settings_updated"
	TenantSubscriptionChanged  = "tenant.subscription_changed"
	TenantVerificationRequested = "tenant.verification.requested" // Email verification link needed
	TenantVerificationCompleted = "tenant.verification.completed" // Email verified, ready for password setup
	TenantOnboardingCompleted   = "tenant.onboarding.completed"   // Full onboarding complete, send welcome pack

	// Custom Domain events
	DomainAdded             = "domain.added"              // New custom domain registered
	DomainVerified          = "domain.verified"           // DNS verification successful
	DomainSSLProvisioned    = "domain.ssl_provisioned"    // SSL certificate issued
	DomainActivated         = "domain.activated"          // Domain is now live and serving traffic
	DomainFailed            = "domain.failed"             // Domain setup failed (DNS/SSL/routing)
	DomainRemoved           = "domain.removed"            // Domain deleted by user
	DomainMigrated          = "domain.migrated"           // Domain migrated from built-in subdomain
	DomainSSLExpiringSoon   = "domain.ssl_expiring_soon"  // SSL certificate expiring within 30 days
	DomainHealthCheckFailed = "domain.health_check_failed" // Domain health check failed

	// Approval events
	ApprovalRequested = "approval.requested" // New approval request created
	ApprovalGranted   = "approval.granted"   // Request was approved
	ApprovalRejected  = "approval.rejected"  // Request was rejected
	ApprovalCancelled = "approval.cancelled" // Request was cancelled by requester
	ApprovalExpired   = "approval.expired"   // Request expired without decision
	ApprovalEscalated = "approval.escalated" // Request escalated to higher authority

	// Tax events
	TaxCalculated          = "tax.calculated"
	TaxJurisdictionCreated = "tax.jurisdiction.created"
	TaxJurisdictionUpdated = "tax.jurisdiction.updated"
	TaxJurisdictionDeleted = "tax.jurisdiction.deleted"
	TaxRateCreated         = "tax.rate.created"
	TaxRateUpdated         = "tax.rate.updated"
	TaxExemptionCreated    = "tax.exemption.created"
	TaxExemptionExpired    = "tax.exemption.expired"

	// Settings events
	SettingsUpdated     = "settings.updated"
	SettingsCreated     = "settings.created"
	SettingsBulkUpdated = "settings.bulk_updated"

	// Verification events
	VerificationCodeSent   = "verification.code_sent"
	VerificationVerified   = "verification.verified"
	VerificationFailed     = "verification.failed"
	VerificationExpired    = "verification.expired"

	// Document events
	DocumentUploaded   = "document.uploaded"
	DocumentProcessed  = "document.processed"
	DocumentDeleted    = "document.deleted"
	DocumentExpired    = "document.expired"
	DocumentVerified   = "document.verified"

	// Location events
	LocationGeocoded      = "location.geocoded"
	LocationReverseLooked = "location.reverse_looked"
	LocationCached        = "location.cached"

	// QR events
	QRGenerated = "qr.generated"
	QRScanned   = "qr.scanned"
	QRExpired   = "qr.expired"

	// Analytics events
	AnalyticsEventTracked = "analytics.event_tracked"
	AnalyticsPageViewed   = "analytics.page_viewed"
	AnalyticsGoalCompleted = "analytics.goal_completed"
)

// NATS stream names
const (
	StreamOrders       = "ORDER_EVENTS"
	StreamPayments     = "PAYMENT_EVENTS"
	StreamCustomers    = "CUSTOMER_EVENTS"
	StreamAuth         = "AUTH_EVENTS"
	StreamInventory    = "INVENTORY_EVENTS"
	StreamProducts     = "PRODUCT_EVENTS"
	StreamReturns      = "RETURN_EVENTS"
	StreamReviews      = "REVIEW_EVENTS"
	StreamCoupons      = "COUPON_EVENTS"
	StreamVendors      = "VENDOR_EVENTS"
	StreamGiftCards    = "GIFT_CARD_EVENTS"
	StreamTickets      = "TICKET_EVENTS"
	StreamStaff        = "STAFF_EVENTS"
	StreamTenants      = "TENANT_EVENTS"
	StreamApprovals    = "APPROVAL_EVENTS"
	StreamCategories   = "CATEGORY_EVENTS"
	StreamShipping     = "SHIPPING_EVENTS"
	StreamTax          = "TAX_EVENTS"
	StreamSettings     = "SETTINGS_EVENTS"
	StreamVerification = "VERIFICATION_EVENTS"
	StreamDocuments    = "DOCUMENT_EVENTS"
	StreamLocation     = "LOCATION_EVENTS"
	StreamQR           = "QR_EVENTS"
	StreamAnalytics    = "ANALYTICS_EVENTS"
	StreamDomains      = "DOMAIN_EVENTS"
)

// Validation errors
var (
	ErrMissingEventType     = errors.New("event type is required")
	ErrMissingTenantID      = errors.New("tenant ID is required")
	ErrMissingOrderNumber   = errors.New("order number is required")
	ErrMissingCustomerEmail = errors.New("customer email is required")
	ErrMissingCustomerName  = errors.New("customer name is required")
	ErrInvalidEmail         = errors.New("invalid email format")
	ErrMissingPaymentID     = errors.New("payment ID is required")
	ErrMissingAmount        = errors.New("amount is required")
	ErrMissingCurrency      = errors.New("currency is required")
	ErrMissingUserID        = errors.New("user ID is required")
	ErrMissingItems         = errors.New("at least one item is required for inventory events")
)

var emailRegex = regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`)

// Validatable interface for events that can be validated
type Validatable interface {
	Validate() error
}

// BaseEvent contains common fields for all events
type BaseEvent struct {
	EventType   string    `json:"eventType"`
	TenantID    string    `json:"tenantId"`
	SourceID    string    `json:"sourceId,omitempty"`
	Timestamp   time.Time `json:"timestamp"`
	TraceID     string    `json:"traceId,omitempty"`     // For distributed tracing
	CorrelationID string  `json:"correlationId,omitempty"` // For request correlation
}

// Validate validates the base event fields
func (e *BaseEvent) Validate() error {
	if e.EventType == "" {
		return ErrMissingEventType
	}
	if e.TenantID == "" {
		return ErrMissingTenantID
	}
	return nil
}

// SetTimestamp sets the timestamp if not already set
func (e *BaseEvent) SetTimestamp() {
	if e.Timestamp.IsZero() {
		e.Timestamp = time.Now().UTC()
	}
}

// Address represents a shipping/billing address
type Address struct {
	Name       string `json:"name"`
	Company    string `json:"company,omitempty"`
	Line1      string `json:"line1"`
	Line2      string `json:"line2,omitempty"`
	City       string `json:"city"`
	State      string `json:"state"`
	PostalCode string `json:"postalCode"`
	Country    string `json:"country"`
	Phone      string `json:"phone,omitempty"`
	Email      string `json:"email,omitempty"`
}

// IsEmpty checks if the address has any data
func (a *Address) IsEmpty() bool {
	return a == nil || (a.Name == "" && a.Line1 == "" && a.City == "")
}

// FormatOneLine returns a single line representation
func (a *Address) FormatOneLine() string {
	if a == nil {
		return ""
	}
	parts := []string{}
	if a.Name != "" {
		parts = append(parts, a.Name)
	}
	if a.Line1 != "" {
		parts = append(parts, a.Line1)
	}
	if a.City != "" {
		cityState := a.City
		if a.State != "" {
			cityState += ", " + a.State
		}
		if a.PostalCode != "" {
			cityState += " " + a.PostalCode
		}
		parts = append(parts, cityState)
	}
	return strings.Join(parts, ", ")
}

// OrderItem represents an item in an order
type OrderItem struct {
	ProductID   string  `json:"productId"`
	VariantID   string  `json:"variantId,omitempty"`
	SKU         string  `json:"sku,omitempty"`
	Name        string  `json:"name"`
	Description string  `json:"description,omitempty"`
	ImageURL    string  `json:"imageUrl,omitempty"`
	Quantity    int     `json:"quantity"`
	UnitPrice   float64 `json:"unitPrice"`
	TotalPrice  float64 `json:"totalPrice"`
	Currency    string  `json:"currency,omitempty"`
	VendorID    string  `json:"vendorId,omitempty"`
	VendorName  string  `json:"vendorName,omitempty"`
	Weight      float64 `json:"weight,omitempty"`
	WeightUnit  string  `json:"weightUnit,omitempty"` // kg, lb, oz, g
	TaxAmount   float64 `json:"taxAmount,omitempty"`
	DiscountAmount float64 `json:"discountAmount,omitempty"`
}

// CalculateTotalPrice calculates and sets the total price
func (i *OrderItem) CalculateTotalPrice() {
	i.TotalPrice = float64(i.Quantity) * i.UnitPrice
}

// OrderEvent represents an order-related event
type OrderEvent struct {
	BaseEvent

	// Order identification
	OrderID     string `json:"orderId"`
	OrderNumber string `json:"orderNumber"`
	OrderDate   string `json:"orderDate,omitempty"`

	// Customer info (works for both authenticated and anonymous)
	CustomerID    string `json:"customerId,omitempty"` // Empty for anonymous/guest
	CustomerEmail string `json:"customerEmail"`
	CustomerPhone string `json:"customerPhone,omitempty"`
	CustomerName  string `json:"customerName"`
	IsAnonymous   bool   `json:"isAnonymous,omitempty"` // True for guest checkout
	IsGuest       bool   `json:"isGuest,omitempty"`     // Alias for isAnonymous

	// Order items
	Items         []OrderItem `json:"items,omitempty"`
	ItemCount     int         `json:"itemCount,omitempty"`
	TotalQuantity int         `json:"totalQuantity,omitempty"`

	// Pricing
	Subtotal     float64 `json:"subtotal,omitempty"`
	Discount     float64 `json:"discount,omitempty"`
	DiscountCode string  `json:"discountCode,omitempty"`
	ShippingCost float64 `json:"shippingCost,omitempty"`
	Tax          float64 `json:"tax,omitempty"`
	TaxRate      float64 `json:"taxRate,omitempty"`
	TotalAmount  float64 `json:"totalAmount"`
	Currency     string  `json:"currency"`

	// Order details
	Status           string   `json:"status"`
	PaymentStatus    string   `json:"paymentStatus,omitempty"`
	FulfillmentStatus string  `json:"fulfillmentStatus,omitempty"`
	PaymentMethod    string   `json:"paymentMethod,omitempty"`
	PaymentProvider  string   `json:"paymentProvider,omitempty"`
	Notes            string   `json:"notes,omitempty"`
	Tags             []string `json:"tags,omitempty"`
	Source           string   `json:"source,omitempty"` // web, mobile, api, pos

	// Shipping
	ShippingAddress   *Address `json:"shippingAddress,omitempty"`
	BillingAddress    *Address `json:"billingAddress,omitempty"`
	ShippingMethod    string   `json:"shippingMethod,omitempty"`
	TrackingURL       string   `json:"trackingUrl,omitempty"`
	TrackingNumber    string   `json:"trackingNumber,omitempty"`
	CarrierName       string   `json:"carrierName,omitempty"`
	CarrierCode       string   `json:"carrierCode,omitempty"`
	EstimatedDelivery string   `json:"estimatedDelivery,omitempty"`
	DeliveryDate      string   `json:"deliveryDate,omitempty"`
	DeliveryTime      string   `json:"deliveryTime,omitempty"`

	// Cancellation/Refund
	CancellationReason string  `json:"cancellationReason,omitempty"`
	CancelledBy        string  `json:"cancelledBy,omitempty"` // customer, admin, system
	RefundAmount       float64 `json:"refundAmount,omitempty"`
	RefundReason       string  `json:"refundReason,omitempty"`

	// Metadata
	Metadata map[string]interface{} `json:"metadata,omitempty"`
}

// Validate validates the order event
func (e *OrderEvent) Validate() error {
	if err := e.BaseEvent.Validate(); err != nil {
		return err
	}
	if e.OrderNumber == "" {
		return ErrMissingOrderNumber
	}
	if e.CustomerEmail == "" {
		return ErrMissingCustomerEmail
	}
	if !emailRegex.MatchString(e.CustomerEmail) {
		return ErrInvalidEmail
	}
	if e.CustomerName == "" {
		return ErrMissingCustomerName
	}
	if e.Currency == "" {
		return ErrMissingCurrency
	}
	return nil
}

// CalculateTotals recalculates order totals from items
func (e *OrderEvent) CalculateTotals() {
	e.Subtotal = 0
	e.TotalQuantity = 0
	for i := range e.Items {
		e.Items[i].CalculateTotalPrice()
		e.Subtotal += e.Items[i].TotalPrice
		e.TotalQuantity += e.Items[i].Quantity
	}
	e.ItemCount = len(e.Items)
	e.TotalAmount = e.Subtotal - e.Discount + e.ShippingCost + e.Tax
}

// GetSubject returns the NATS subject for this event
func (e *OrderEvent) GetSubject() string {
	return e.EventType
}

// GetStream returns the NATS stream name for this event
func (e *OrderEvent) GetStream() string {
	return StreamOrders
}

// PaymentEvent represents a payment-related event
type PaymentEvent struct {
	BaseEvent

	// Payment identification
	PaymentID     string `json:"paymentId"`
	TransactionID string `json:"transactionId,omitempty"`
	ExternalID    string `json:"externalId,omitempty"` // Provider's payment ID

	// Associated order
	OrderID     string `json:"orderId"`
	OrderNumber string `json:"orderNumber"`

	// Customer info
	CustomerID    string `json:"customerId,omitempty"`
	CustomerEmail string `json:"customerEmail"`
	CustomerPhone string `json:"customerPhone,omitempty"`
	CustomerName  string `json:"customerName"`

	// Payment details
	Amount        float64 `json:"amount"`
	Currency      string  `json:"currency"`
	Provider      string  `json:"provider"`      // stripe, razorpay, paypal, etc.
	Method        string  `json:"method,omitempty"` // card, upi, wallet, bank_transfer
	CardBrand     string  `json:"cardBrand,omitempty"` // visa, mastercard, amex
	CardLast4     string  `json:"cardLast4,omitempty"`
	Status        string  `json:"status"`
	StatusMessage string  `json:"statusMessage,omitempty"`

	// Error info (for failed payments)
	ErrorCode    string `json:"errorCode,omitempty"`
	ErrorMessage string `json:"errorMessage,omitempty"`
	DeclineCode  string `json:"declineCode,omitempty"`

	// Retry info
	RetryURL    string `json:"retryUrl,omitempty"`
	RetryCount  int    `json:"retryCount,omitempty"`
	NextRetryAt string `json:"nextRetryAt,omitempty"`
	MaxRetries  int    `json:"maxRetries,omitempty"`

	// Refund info
	RefundID     string  `json:"refundId,omitempty"`
	RefundAmount float64 `json:"refundAmount,omitempty"`
	RefundReason string  `json:"refundReason,omitempty"`

	// Metadata
	Metadata map[string]interface{} `json:"metadata,omitempty"`
}

// Validate validates the payment event
func (e *PaymentEvent) Validate() error {
	if err := e.BaseEvent.Validate(); err != nil {
		return err
	}
	if e.PaymentID == "" {
		return ErrMissingPaymentID
	}
	if e.Amount <= 0 {
		return ErrMissingAmount
	}
	if e.Currency == "" {
		return ErrMissingCurrency
	}
	if e.CustomerEmail != "" && !emailRegex.MatchString(e.CustomerEmail) {
		return ErrInvalidEmail
	}
	return nil
}

// GetSubject returns the NATS subject for this event
func (e *PaymentEvent) GetSubject() string {
	return e.EventType
}

// GetStream returns the NATS stream name for this event
func (e *PaymentEvent) GetStream() string {
	return StreamPayments
}

// CustomerEvent represents a customer-related event
type CustomerEvent struct {
	BaseEvent

	// Customer identification
	CustomerID    string `json:"customerId"`
	CustomerEmail string `json:"customerEmail"`
	CustomerName  string `json:"customerName"`
	CustomerPhone string `json:"customerPhone,omitempty"`

	// Customer details
	FirstName    string   `json:"firstName,omitempty"`
	LastName     string   `json:"lastName,omitempty"`
	DisplayName  string   `json:"displayName,omitempty"`
	AvatarURL    string   `json:"avatarUrl,omitempty"`
	DateOfBirth  string   `json:"dateOfBirth,omitempty"`
	Gender       string   `json:"gender,omitempty"`
	Locale       string   `json:"locale,omitempty"`
	Timezone     string   `json:"timezone,omitempty"`
	Tags         []string `json:"tags,omitempty"`

	// Marketing
	AcceptsMarketing    bool   `json:"acceptsMarketing,omitempty"`
	MarketingOptInDate  string `json:"marketingOptInDate,omitempty"`
	MarketingOptOutDate string `json:"marketingOptOutDate,omitempty"`

	// Referral
	ReferralCode string `json:"referralCode,omitempty"`
	ReferredBy   string `json:"referredBy,omitempty"`

	// Welcome/Promo
	WelcomeOffer string `json:"welcomeOffer,omitempty"`
	PromoCode    string `json:"promoCode,omitempty"`

	// Verification
	EmailVerified bool   `json:"emailVerified,omitempty"`
	PhoneVerified bool   `json:"phoneVerified,omitempty"`

	// Stats
	OrderCount   int     `json:"orderCount,omitempty"`
	TotalSpent   float64 `json:"totalSpent,omitempty"`
	LastOrderAt  string  `json:"lastOrderAt,omitempty"`

	// Metadata
	Metadata map[string]interface{} `json:"metadata,omitempty"`
}

// Validate validates the customer event
func (e *CustomerEvent) Validate() error {
	if err := e.BaseEvent.Validate(); err != nil {
		return err
	}
	if e.CustomerEmail == "" {
		return ErrMissingCustomerEmail
	}
	if !emailRegex.MatchString(e.CustomerEmail) {
		return ErrInvalidEmail
	}
	return nil
}

// GetSubject returns the NATS subject for this event
func (e *CustomerEvent) GetSubject() string {
	return e.EventType
}

// GetStream returns the NATS stream name for this event
func (e *CustomerEvent) GetStream() string {
	return StreamCustomers
}

// AuthEvent represents an authentication-related event
type AuthEvent struct {
	BaseEvent

	// User identification
	UserID string `json:"userId"`
	Email  string `json:"email"`
	Phone  string `json:"phone,omitempty"`

	// Password reset
	ResetToken    string `json:"resetToken,omitempty"`
	ResetURL      string `json:"resetUrl,omitempty"`
	ResetExpiresAt string `json:"resetExpiresAt,omitempty"`

	// Verification
	VerificationCode    string `json:"verificationCode,omitempty"`
	VerificationChannel string `json:"verificationChannel,omitempty"` // email, sms
	VerificationExpiresAt string `json:"verificationExpiresAt,omitempty"`

	// Login info
	IPAddress   string `json:"ipAddress,omitempty"`
	UserAgent   string `json:"userAgent,omitempty"`
	DeviceID    string `json:"deviceId,omitempty"`
	DeviceType  string `json:"deviceType,omitempty"` // web, mobile, tablet
	Location    string `json:"location,omitempty"`
	LoginMethod string `json:"loginMethod,omitempty"` // password, oauth, magic_link

	// Security
	FailedAttempts int    `json:"failedAttempts,omitempty"`
	LockedUntil    string `json:"lockedUntil,omitempty"`
	LockReason     string `json:"lockReason,omitempty"`

	// Metadata
	Metadata map[string]interface{} `json:"metadata,omitempty"`
}

// Validate validates the auth event
func (e *AuthEvent) Validate() error {
	if err := e.BaseEvent.Validate(); err != nil {
		return err
	}
	if e.UserID == "" && e.Email == "" {
		return ErrMissingUserID
	}
	if e.Email != "" && !emailRegex.MatchString(e.Email) {
		return ErrInvalidEmail
	}
	return nil
}

// GetSubject returns the NATS subject for this event
func (e *AuthEvent) GetSubject() string {
	return e.EventType
}

// GetStream returns the NATS stream name for this event
func (e *AuthEvent) GetStream() string {
	return StreamAuth
}

// InventoryItem represents a product with stock info
type InventoryItem struct {
	ProductID    string `json:"productId"`
	VariantID    string `json:"variantId,omitempty"`
	SKU          string `json:"sku"`
	Name         string `json:"name"`
	ImageURL     string `json:"imageUrl,omitempty"`
	CurrentStock int    `json:"currentStock"`
	PreviousStock int   `json:"previousStock,omitempty"`
	ReorderPoint int    `json:"reorderPoint,omitempty"`
	ReorderQty   int    `json:"reorderQty,omitempty"`
	VendorID     string `json:"vendorId,omitempty"`
	VendorName   string `json:"vendorName,omitempty"`
	WarehouseID  string `json:"warehouseId,omitempty"`
	WarehouseName string `json:"warehouseName,omitempty"`
	Location     string `json:"location,omitempty"` // Bin/shelf location
}

// IsLowStock checks if the item is below reorder point
func (i *InventoryItem) IsLowStock() bool {
	return i.CurrentStock <= i.ReorderPoint && i.CurrentStock > 0
}

// IsOutOfStock checks if the item is out of stock
func (i *InventoryItem) IsOutOfStock() bool {
	return i.CurrentStock <= 0
}

// InventoryEvent represents an inventory-related event
type InventoryEvent struct {
	BaseEvent

	// Inventory items
	Items []InventoryItem `json:"items"`

	// Summary
	TotalLowStock   int `json:"totalLowStock"`
	TotalOutOfStock int `json:"totalOutOfStock"`
	TotalAffected   int `json:"totalAffected"`

	// Alert info
	AlertLevel    string `json:"alertLevel,omitempty"` // info, warning, critical
	AlertMessage  string `json:"alertMessage,omitempty"`
	InventoryURL  string `json:"inventoryUrl,omitempty"`

	// Adjustment info (for adjusted events)
	AdjustmentType   string `json:"adjustmentType,omitempty"` // add, remove, set
	AdjustmentReason string `json:"adjustmentReason,omitempty"`
	AdjustedBy       string `json:"adjustedBy,omitempty"`

	// Metadata
	Metadata map[string]interface{} `json:"metadata,omitempty"`
}

// Validate validates the inventory event
func (e *InventoryEvent) Validate() error {
	if err := e.BaseEvent.Validate(); err != nil {
		return err
	}
	if len(e.Items) == 0 {
		return ErrMissingItems
	}
	return nil
}

// CalculateSummary calculates summary fields from items
func (e *InventoryEvent) CalculateSummary() {
	e.TotalLowStock = 0
	e.TotalOutOfStock = 0
	for _, item := range e.Items {
		if item.IsOutOfStock() {
			e.TotalOutOfStock++
		} else if item.IsLowStock() {
			e.TotalLowStock++
		}
	}
	e.TotalAffected = len(e.Items)

	// Set alert level based on severity
	if e.TotalOutOfStock > 0 {
		e.AlertLevel = "critical"
	} else if e.TotalLowStock > 0 {
		e.AlertLevel = "warning"
	} else {
		e.AlertLevel = "info"
	}
}

// GetSubject returns the NATS subject for this event
func (e *InventoryEvent) GetSubject() string {
	return e.EventType
}

// GetStream returns the NATS stream name for this event
func (e *InventoryEvent) GetStream() string {
	return StreamInventory
}

// ReturnEvent represents a return/refund request event
type ReturnEvent struct {
	BaseEvent

	// Return identification
	ReturnID    string `json:"returnId"`
	RMANumber   string `json:"rmaNumber"`

	// Order info
	OrderID     string `json:"orderId"`
	OrderNumber string `json:"orderNumber"`

	// Customer info
	CustomerID    string `json:"customerId,omitempty"`
	CustomerEmail string `json:"customerEmail"`
	CustomerName  string `json:"customerName"`

	// Return details
	Status        string      `json:"status"`
	Reason        string      `json:"reason"`
	Items         []OrderItem `json:"items,omitempty"`
	RefundAmount  float64     `json:"refundAmount"`
	RefundMethod  string      `json:"refundMethod,omitempty"` // original, store_credit
	Currency      string      `json:"currency"`

	// Processing
	ProcessedBy   string `json:"processedBy,omitempty"`
	ProcessedAt   string `json:"processedAt,omitempty"`
	Notes         string `json:"notes,omitempty"`

	// Metadata
	Metadata map[string]interface{} `json:"metadata,omitempty"`
}

// Validate validates the return event
func (e *ReturnEvent) Validate() error {
	if err := e.BaseEvent.Validate(); err != nil {
		return err
	}
	if e.ReturnID == "" && e.RMANumber == "" {
		return fmt.Errorf("return ID or RMA number is required")
	}
	if e.CustomerEmail == "" {
		return ErrMissingCustomerEmail
	}
	return nil
}

// GetSubject returns the NATS subject for this event
func (e *ReturnEvent) GetSubject() string {
	return e.EventType
}

// GetStream returns the NATS stream name for this event
func (e *ReturnEvent) GetStream() string {
	return StreamReturns
}

// ReviewEvent represents a product review event
type ReviewEvent struct {
	BaseEvent

	// Review identification
	ReviewID  string `json:"reviewId"`
	ProductID string `json:"productId"`

	// Customer info
	CustomerID   string `json:"customerId,omitempty"`
	CustomerName string `json:"customerName"`
	CustomerEmail string `json:"customerEmail,omitempty"`

	// Review details
	Rating    int    `json:"rating"` // 1-5
	Title     string `json:"title,omitempty"`
	Content   string `json:"content"`
	Status    string `json:"status"` // pending, approved, rejected
	Verified  bool   `json:"verified,omitempty"` // Verified purchase

	// Moderation
	ModeratedBy string `json:"moderatedBy,omitempty"`
	ModeratedAt string `json:"moderatedAt,omitempty"`
	RejectReason string `json:"rejectReason,omitempty"`

	// Product info (for notification context)
	ProductName  string `json:"productName,omitempty"`
	ProductSKU   string `json:"productSku,omitempty"`
	ProductImage string `json:"productImage,omitempty"`

	// Metadata
	Metadata map[string]interface{} `json:"metadata,omitempty"`
}

// Validate validates the review event
func (e *ReviewEvent) Validate() error {
	if err := e.BaseEvent.Validate(); err != nil {
		return err
	}
	if e.ReviewID == "" {
		return fmt.Errorf("review ID is required")
	}
	if e.Rating < 1 || e.Rating > 5 {
		return fmt.Errorf("rating must be between 1 and 5")
	}
	return nil
}

// GetSubject returns the NATS subject for this event
func (e *ReviewEvent) GetSubject() string {
	return e.EventType
}

// GetStream returns the NATS stream name for this event
func (e *ReviewEvent) GetStream() string {
	return StreamReviews
}

// Factory functions for creating events

// NewOrderEvent creates a new order event with base fields populated
func NewOrderEvent(eventType, tenantID string) *OrderEvent {
	return &OrderEvent{
		BaseEvent: BaseEvent{
			EventType: eventType,
			TenantID:  tenantID,
			Timestamp: time.Now().UTC(),
		},
		Currency: "USD", // Default currency
	}
}

// NewPaymentEvent creates a new payment event with base fields populated
func NewPaymentEvent(eventType, tenantID string) *PaymentEvent {
	return &PaymentEvent{
		BaseEvent: BaseEvent{
			EventType: eventType,
			TenantID:  tenantID,
			Timestamp: time.Now().UTC(),
		},
		Currency: "USD",
	}
}

// NewCustomerEvent creates a new customer event with base fields populated
func NewCustomerEvent(eventType, tenantID string) *CustomerEvent {
	return &CustomerEvent{
		BaseEvent: BaseEvent{
			EventType: eventType,
			TenantID:  tenantID,
			Timestamp: time.Now().UTC(),
		},
	}
}

// NewAuthEvent creates a new auth event with base fields populated
func NewAuthEvent(eventType, tenantID string) *AuthEvent {
	return &AuthEvent{
		BaseEvent: BaseEvent{
			EventType: eventType,
			TenantID:  tenantID,
			Timestamp: time.Now().UTC(),
		},
	}
}

// NewInventoryEvent creates a new inventory event with base fields populated
func NewInventoryEvent(eventType, tenantID string) *InventoryEvent {
	return &InventoryEvent{
		BaseEvent: BaseEvent{
			EventType: eventType,
			TenantID:  tenantID,
			Timestamp: time.Now().UTC(),
		},
		Items: make([]InventoryItem, 0),
	}
}

// NewReturnEvent creates a new return event with base fields populated
func NewReturnEvent(eventType, tenantID string) *ReturnEvent {
	return &ReturnEvent{
		BaseEvent: BaseEvent{
			EventType: eventType,
			TenantID:  tenantID,
			Timestamp: time.Now().UTC(),
		},
		Currency: "USD",
	}
}

// NewReviewEvent creates a new review event with base fields populated
func NewReviewEvent(eventType, tenantID string) *ReviewEvent {
	return &ReviewEvent{
		BaseEvent: BaseEvent{
			EventType: eventType,
			TenantID:  tenantID,
			Timestamp: time.Now().UTC(),
		},
	}
}

// GetStreamForSubject returns the appropriate stream for a subject pattern
func GetStreamForSubject(subject string) string {
	if strings.HasPrefix(subject, "order.") {
		return StreamOrders
	}
	if strings.HasPrefix(subject, "payment.") {
		return StreamPayments
	}
	if strings.HasPrefix(subject, "customer.") {
		return StreamCustomers
	}
	if strings.HasPrefix(subject, "auth.") {
		return StreamAuth
	}
	if strings.HasPrefix(subject, "inventory.") {
		return StreamInventory
	}
	if strings.HasPrefix(subject, "product.") {
		return StreamProducts
	}
	if strings.HasPrefix(subject, "return.") {
		return StreamReturns
	}
	if strings.HasPrefix(subject, "review.") {
		return StreamReviews
	}
	if strings.HasPrefix(subject, "coupon.") {
		return StreamCoupons
	}
	if strings.HasPrefix(subject, "vendor.") {
		return StreamVendors
	}
	if strings.HasPrefix(subject, "gift_card.") {
		return StreamGiftCards
	}
	if strings.HasPrefix(subject, "ticket.") {
		return StreamTickets
	}
	if strings.HasPrefix(subject, "staff.") {
		return StreamStaff
	}
	if strings.HasPrefix(subject, "tenant.") {
		return StreamTenants
	}
	if strings.HasPrefix(subject, "approval.") {
		return StreamApprovals
	}
	if strings.HasPrefix(subject, "category.") {
		return StreamCategories
	}
	if strings.HasPrefix(subject, "shipping.") {
		return StreamShipping
	}
	if strings.HasPrefix(subject, "tax.") {
		return StreamTax
	}
	if strings.HasPrefix(subject, "settings.") {
		return StreamSettings
	}
	if strings.HasPrefix(subject, "verification.") {
		return StreamVerification
	}
	if strings.HasPrefix(subject, "document.") {
		return StreamDocuments
	}
	if strings.HasPrefix(subject, "location.") {
		return StreamLocation
	}
	if strings.HasPrefix(subject, "qr.") {
		return StreamQR
	}
	if strings.HasPrefix(subject, "analytics.") {
		return StreamAnalytics
	}
	if strings.HasPrefix(subject, "domain.") {
		return StreamDomains
	}
	return ""
}

// CouponEvent represents a coupon-related event
type CouponEvent struct {
	BaseEvent

	// Coupon identification
	CouponID   string `json:"couponId"`
	CouponCode string `json:"couponCode"`

	// Customer info (for coupon applied events)
	CustomerID    string `json:"customerId,omitempty"`
	CustomerEmail string `json:"customerEmail,omitempty"`
	CustomerName  string `json:"customerName,omitempty"`

	// Order info (for coupon applied events)
	OrderID     string `json:"orderId,omitempty"`
	OrderNumber string `json:"orderNumber,omitempty"`

	// Coupon details
	DiscountType   string  `json:"discountType"`           // PERCENTAGE, FIXED, FREE_SHIPPING
	DiscountValue  float64 `json:"discountValue"`
	DiscountAmount float64 `json:"discountAmount,omitempty"` // Actual discount applied
	MaxDiscount    float64 `json:"maxDiscount,omitempty"`
	MinOrderValue  float64 `json:"minOrderValue,omitempty"`
	OrderValue     float64 `json:"orderValue,omitempty"`
	Currency       string  `json:"currency,omitempty"`

	// Usage info
	CurrentUsage int `json:"currentUsage,omitempty"`
	MaxUsage     int `json:"maxUsage,omitempty"`

	// Validity
	ValidFrom  string `json:"validFrom,omitempty"`
	ValidUntil string `json:"validUntil,omitempty"`
	Status     string `json:"status,omitempty"` // ACTIVE, INACTIVE, EXPIRED, FULLY_REDEEMED

	// Additional info
	Description string `json:"description,omitempty"`
	Scope       string `json:"scope,omitempty"` // APPLICATION, TENANT, VENDOR

	// Metadata
	Metadata map[string]interface{} `json:"metadata,omitempty"`
}

// Validate validates the coupon event
func (e *CouponEvent) Validate() error {
	if err := e.BaseEvent.Validate(); err != nil {
		return err
	}
	if e.CouponID == "" && e.CouponCode == "" {
		return fmt.Errorf("coupon ID or code is required")
	}
	return nil
}

// GetSubject returns the NATS subject for this event
func (e *CouponEvent) GetSubject() string {
	return e.EventType
}

// GetStream returns the NATS stream name for this event
func (e *CouponEvent) GetStream() string {
	return StreamCoupons
}

// VendorEvent represents a vendor-related event
type VendorEvent struct {
	BaseEvent

	// Vendor identification
	VendorID    string `json:"vendorId"`
	VendorName  string `json:"vendorName"`
	VendorEmail string `json:"vendorEmail,omitempty"`
	VendorPhone string `json:"vendorPhone,omitempty"`

	// Business info
	BusinessName    string `json:"businessName,omitempty"`
	BusinessType    string `json:"businessType,omitempty"`
	TaxID           string `json:"taxId,omitempty"`
	RegistrationNum string `json:"registrationNum,omitempty"`

	// Status
	Status         string `json:"status"`                   // PENDING, APPROVED, REJECTED, SUSPENDED, ACTIVE
	PreviousStatus string `json:"previousStatus,omitempty"`
	StatusReason   string `json:"statusReason,omitempty"`

	// Approval/Review
	ReviewedBy   string `json:"reviewedBy,omitempty"`
	ReviewedAt   string `json:"reviewedAt,omitempty"`
	RejectReason string `json:"rejectReason,omitempty"`

	// Commission
	CommissionRate float64 `json:"commissionRate,omitempty"`

	// Contact info
	PrimaryContact string `json:"primaryContact,omitempty"`
	Address        string `json:"address,omitempty"`
	City           string `json:"city,omitempty"`
	State          string `json:"state,omitempty"`
	Country        string `json:"country,omitempty"`
	PostalCode     string `json:"postalCode,omitempty"`

	// Stats
	ProductCount   int     `json:"productCount,omitempty"`
	OrderCount     int     `json:"orderCount,omitempty"`
	TotalRevenue   float64 `json:"totalRevenue,omitempty"`
	AverageRating  float64 `json:"averageRating,omitempty"`

	// Metadata
	Metadata map[string]interface{} `json:"metadata,omitempty"`
}

// Validate validates the vendor event
func (e *VendorEvent) Validate() error {
	if err := e.BaseEvent.Validate(); err != nil {
		return err
	}
	if e.VendorID == "" {
		return fmt.Errorf("vendor ID is required")
	}
	return nil
}

// GetSubject returns the NATS subject for this event
func (e *VendorEvent) GetSubject() string {
	return e.EventType
}

// GetStream returns the NATS stream name for this event
func (e *VendorEvent) GetStream() string {
	return StreamVendors
}

// GiftCardEvent represents a gift card-related event
type GiftCardEvent struct {
	BaseEvent

	// Gift card identification
	GiftCardID   string `json:"giftCardId"`
	GiftCardCode string `json:"giftCardCode"`

	// Customer info
	PurchaserID    string `json:"purchaserId,omitempty"`
	PurchaserEmail string `json:"purchaserEmail,omitempty"`
	PurchaserName  string `json:"purchaserName,omitempty"`
	RecipientEmail string `json:"recipientEmail,omitempty"`
	RecipientName  string `json:"recipientName,omitempty"`

	// Order info (for gift card applied events)
	OrderID     string `json:"orderId,omitempty"`
	OrderNumber string `json:"orderNumber,omitempty"`

	// Amount info
	InitialBalance  float64 `json:"initialBalance"`
	CurrentBalance  float64 `json:"currentBalance"`
	AmountUsed      float64 `json:"amountUsed,omitempty"`
	RefundAmount    float64 `json:"refundAmount,omitempty"`
	Currency        string  `json:"currency"`

	// Status
	Status     string `json:"status"` // PENDING, ACTIVE, USED, EXPIRED, CANCELLED
	ActivatedAt string `json:"activatedAt,omitempty"`
	ExpiresAt   string `json:"expiresAt,omitempty"`

	// Personalization
	Message   string `json:"message,omitempty"`
	DesignID  string `json:"designId,omitempty"`
	DesignURL string `json:"designUrl,omitempty"`

	// Delivery
	DeliveryMethod string `json:"deliveryMethod,omitempty"` // EMAIL, PHYSICAL, DIGITAL
	DeliveryDate   string `json:"deliveryDate,omitempty"`

	// Metadata
	Metadata map[string]interface{} `json:"metadata,omitempty"`
}

// Validate validates the gift card event
func (e *GiftCardEvent) Validate() error {
	if err := e.BaseEvent.Validate(); err != nil {
		return err
	}
	if e.GiftCardID == "" && e.GiftCardCode == "" {
		return fmt.Errorf("gift card ID or code is required")
	}
	return nil
}

// GetSubject returns the NATS subject for this event
func (e *GiftCardEvent) GetSubject() string {
	return e.EventType
}

// GetStream returns the NATS stream name for this event
func (e *GiftCardEvent) GetStream() string {
	return StreamGiftCards
}

// TicketEvent represents a support ticket event
type TicketEvent struct {
	BaseEvent

	// Ticket identification
	TicketID     string `json:"ticketId"`
	TicketNumber string `json:"ticketNumber"`

	// Customer info
	CustomerID    string `json:"customerId,omitempty"`
	CustomerEmail string `json:"customerEmail"`
	CustomerName  string `json:"customerName,omitempty"`
	CustomerPhone string `json:"customerPhone,omitempty"`

	// Ticket details
	Subject     string   `json:"subject"`
	Description string   `json:"description,omitempty"`
	Category    string   `json:"category,omitempty"`   // ORDER, PAYMENT, PRODUCT, SHIPPING, OTHER
	Priority    string   `json:"priority,omitempty"`   // LOW, MEDIUM, HIGH, URGENT
	Status      string   `json:"status"`               // OPEN, IN_PROGRESS, WAITING, RESOLVED, CLOSED
	Type        string   `json:"type,omitempty"`       // QUESTION, PROBLEM, FEATURE_REQUEST, COMPLAINT
	Tags        []string `json:"tags,omitempty"`

	// Assignment
	AssignedTo     string `json:"assignedTo,omitempty"`
	AssignedToName string `json:"assignedToName,omitempty"`
	AssignedAt     string `json:"assignedAt,omitempty"`
	Team           string `json:"team,omitempty"`

	// Related entities
	OrderID   string `json:"orderId,omitempty"`
	ProductID string `json:"productId,omitempty"`

	// Comments
	CommentID      string `json:"commentId,omitempty"`
	CommentContent string `json:"commentContent,omitempty"`
	CommentBy      string `json:"commentBy,omitempty"`
	CommentByName  string `json:"commentByName,omitempty"`
	IsInternal     bool   `json:"isInternal,omitempty"`

	// Resolution
	Resolution   string `json:"resolution,omitempty"`
	ResolvedBy   string `json:"resolvedBy,omitempty"`
	ResolvedAt   string `json:"resolvedAt,omitempty"`
	ClosedBy     string `json:"closedBy,omitempty"`
	ClosedAt     string `json:"closedAt,omitempty"`
	ReopenReason string `json:"reopenReason,omitempty"`

	// SLA
	FirstResponseAt string `json:"firstResponseAt,omitempty"`
	SLADueAt        string `json:"slaDueAt,omitempty"`
	SLABreached     bool   `json:"slaBreached,omitempty"`

	// Metadata
	Metadata map[string]interface{} `json:"metadata,omitempty"`
}

// Validate validates the ticket event
func (e *TicketEvent) Validate() error {
	if err := e.BaseEvent.Validate(); err != nil {
		return err
	}
	if e.TicketID == "" && e.TicketNumber == "" {
		return fmt.Errorf("ticket ID or number is required")
	}
	if e.Subject == "" {
		return fmt.Errorf("ticket subject is required")
	}
	return nil
}

// GetSubject returns the NATS subject for this event
func (e *TicketEvent) GetSubject() string {
	return e.EventType
}

// GetStream returns the NATS stream name for this event
func (e *TicketEvent) GetStream() string {
	return StreamTickets
}

// StaffEvent represents a staff member event
type StaffEvent struct {
	BaseEvent

	// Staff identification
	StaffID    string `json:"staffId"`
	StaffEmail string `json:"staffEmail"`
	StaffName  string `json:"staffName"`
	StaffPhone string `json:"staffPhone,omitempty"`

	// Employee info
	EmployeeID   string `json:"employeeId,omitempty"`
	Department   string `json:"department,omitempty"`
	Position     string `json:"position,omitempty"`
	ReportsTo    string `json:"reportsTo,omitempty"`
	ReportsToName string `json:"reportsToName,omitempty"`

	// Status
	Status         string `json:"status"`                   // ACTIVE, INACTIVE, PENDING, SUSPENDED
	PreviousStatus string `json:"previousStatus,omitempty"`
	StatusReason   string `json:"statusReason,omitempty"`

	// Role changes
	OldRole     string   `json:"oldRole,omitempty"`
	NewRole     string   `json:"newRole,omitempty"`
	Roles       []string `json:"roles,omitempty"`
	Permissions []string `json:"permissions,omitempty"`

	// Dates
	HireDate      string `json:"hireDate,omitempty"`
	StartDate     string `json:"startDate,omitempty"`
	TerminationDate string `json:"terminationDate,omitempty"`

	// Change info
	ChangedBy     string `json:"changedBy,omitempty"`
	ChangedByName string `json:"changedByName,omitempty"`

	// Location
	Location   string `json:"location,omitempty"`
	Timezone   string `json:"timezone,omitempty"`

	// Metadata
	Metadata map[string]interface{} `json:"metadata,omitempty"`
}

// Validate validates the staff event
func (e *StaffEvent) Validate() error {
	if err := e.BaseEvent.Validate(); err != nil {
		return err
	}
	if e.StaffID == "" {
		return fmt.Errorf("staff ID is required")
	}
	if e.StaffEmail == "" {
		return ErrMissingCustomerEmail
	}
	return nil
}

// GetSubject returns the NATS subject for this event
func (e *StaffEvent) GetSubject() string {
	return e.EventType
}

// GetStream returns the NATS stream name for this event
func (e *StaffEvent) GetStream() string {
	return StreamStaff
}

// TenantEvent represents a tenant-related event
type TenantEvent struct {
	BaseEvent

	// Tenant identification
	TenantName  string `json:"tenantName"`
	TenantSlug  string `json:"tenantSlug,omitempty"`
	Domain      string `json:"domain,omitempty"`

	// Owner info
	OwnerID    string `json:"ownerId,omitempty"`
	OwnerEmail string `json:"ownerEmail,omitempty"`
	OwnerName  string `json:"ownerName,omitempty"`

	// Business info (for welcome pack)
	BusinessName  string `json:"businessName,omitempty"`
	AdminURL      string `json:"adminUrl,omitempty"`
	StorefrontURL string `json:"storefrontUrl,omitempty"`

	// Email verification (for onboarding flow)
	SessionID          string `json:"sessionId,omitempty"`          // Onboarding session ID
	VerificationToken  string `json:"verificationToken,omitempty"`  // Token for email verification link
	VerificationLink   string `json:"verificationLink,omitempty"`   // Full verification URL
	VerificationExpiry string `json:"verificationExpiry,omitempty"` // Token expiry timestamp (RFC3339)

	// Status
	Status         string `json:"status"`                   // PENDING, ACTIVE, SUSPENDED, CANCELLED
	PreviousStatus string `json:"previousStatus,omitempty"`
	StatusReason   string `json:"statusReason,omitempty"`

	// Subscription
	SubscriptionPlan     string  `json:"subscriptionPlan,omitempty"`
	PreviousPlan         string  `json:"previousPlan,omitempty"`
	SubscriptionStatus   string  `json:"subscriptionStatus,omitempty"`
	BillingCycle         string  `json:"billingCycle,omitempty"` // MONTHLY, YEARLY
	MonthlyPrice         float64 `json:"monthlyPrice,omitempty"`
	Currency             string  `json:"currency,omitempty"`

	// Settings changes
	SettingKey      string `json:"settingKey,omitempty"`
	SettingOldValue string `json:"settingOldValue,omitempty"`
	SettingNewValue string `json:"settingNewValue,omitempty"`

	// Features
	EnabledFeatures  []string `json:"enabledFeatures,omitempty"`
	DisabledFeatures []string `json:"disabledFeatures,omitempty"`

	// Limits
	UserLimit     int `json:"userLimit,omitempty"`
	StorageLimit  int `json:"storageLimit,omitempty"` // in MB
	ProductLimit  int `json:"productLimit,omitempty"`

	// Dates
	TrialEndsAt       string `json:"trialEndsAt,omitempty"`
	SubscriptionEndsAt string `json:"subscriptionEndsAt,omitempty"`
	CancelledAt       string `json:"cancelledAt,omitempty"`

	// Change info
	ChangedBy     string `json:"changedBy,omitempty"`
	ChangedByName string `json:"changedByName,omitempty"`

	// Metadata
	Metadata map[string]interface{} `json:"metadata,omitempty"`
}

// Validate validates the tenant event
func (e *TenantEvent) Validate() error {
	if err := e.BaseEvent.Validate(); err != nil {
		return err
	}
	if e.TenantName == "" && e.TenantID == "" {
		return fmt.Errorf("tenant name or ID is required")
	}
	return nil
}

// GetSubject returns the NATS subject for this event
func (e *TenantEvent) GetSubject() string {
	return e.EventType
}

// GetStream returns the NATS stream name for this event
func (e *TenantEvent) GetStream() string {
	return StreamTenants
}

// NewCouponEvent creates a new coupon event with base fields populated
func NewCouponEvent(eventType, tenantID string) *CouponEvent {
	return &CouponEvent{
		BaseEvent: BaseEvent{
			EventType: eventType,
			TenantID:  tenantID,
			Timestamp: time.Now().UTC(),
		},
		Currency: "USD",
	}
}

// NewVendorEvent creates a new vendor event with base fields populated
func NewVendorEvent(eventType, tenantID string) *VendorEvent {
	return &VendorEvent{
		BaseEvent: BaseEvent{
			EventType: eventType,
			TenantID:  tenantID,
			Timestamp: time.Now().UTC(),
		},
	}
}

// NewGiftCardEvent creates a new gift card event with base fields populated
func NewGiftCardEvent(eventType, tenantID string) *GiftCardEvent {
	return &GiftCardEvent{
		BaseEvent: BaseEvent{
			EventType: eventType,
			TenantID:  tenantID,
			Timestamp: time.Now().UTC(),
		},
		Currency: "USD",
	}
}

// NewTicketEvent creates a new ticket event with base fields populated
func NewTicketEvent(eventType, tenantID string) *TicketEvent {
	return &TicketEvent{
		BaseEvent: BaseEvent{
			EventType: eventType,
			TenantID:  tenantID,
			Timestamp: time.Now().UTC(),
		},
	}
}

// NewStaffEvent creates a new staff event with base fields populated
func NewStaffEvent(eventType, tenantID string) *StaffEvent {
	return &StaffEvent{
		BaseEvent: BaseEvent{
			EventType: eventType,
			TenantID:  tenantID,
			Timestamp: time.Now().UTC(),
		},
	}
}

// NewTenantEvent creates a new tenant event with base fields populated
func NewTenantEvent(eventType, tenantID string) *TenantEvent {
	return &TenantEvent{
		BaseEvent: BaseEvent{
			EventType: eventType,
			TenantID:  tenantID,
			Timestamp: time.Now().UTC(),
		},
	}
}

// ApprovalEvent represents an approval workflow event
type ApprovalEvent struct {
	BaseEvent

	// Approval identification
	ApprovalRequestID string `json:"approvalRequestId"`
	WorkflowID        string `json:"workflowId,omitempty"`
	WorkflowName      string `json:"workflowName,omitempty"`

	// Requester info
	RequesterID    string `json:"requesterId"`
	RequesterEmail string `json:"requesterEmail,omitempty"`
	RequesterName  string `json:"requesterName,omitempty"`

	// Approver info (for granted/rejected events)
	ApproverID    string `json:"approverId,omitempty"`
	ApproverEmail string `json:"approverEmail,omitempty"`
	ApproverName  string `json:"approverName,omitempty"`
	ApproverRole  string `json:"approverRole,omitempty"`

	// Action details
	ActionType   string                 `json:"actionType"`   // refund, cancel_order, discount, etc.
	ActionData   map[string]interface{} `json:"actionData"`   // Context-specific data
	ResourceType string                 `json:"resourceType,omitempty"` // order, product, payment, etc.
	ResourceID   string                 `json:"resourceId,omitempty"`

	// Status
	Status         string `json:"status"`                   // pending, approved, rejected, cancelled, expired
	PreviousStatus string `json:"previousStatus,omitempty"`
	Decision       string `json:"decision,omitempty"`       // approve, reject

	// Decision details
	DecisionReason string `json:"decisionReason,omitempty"`
	DecisionNotes  string `json:"decisionNotes,omitempty"`
	DecisionAt     string `json:"decisionAt,omitempty"`

	// Escalation info
	EscalatedFrom     string `json:"escalatedFrom,omitempty"`     // Previous approver role
	EscalatedTo       string `json:"escalatedTo,omitempty"`       // New approver role
	EscalationReason  string `json:"escalationReason,omitempty"`  // timeout, manual
	EscalationLevel   int    `json:"escalationLevel,omitempty"`

	// Timing
	ExpiresAt   string `json:"expiresAt,omitempty"`
	RequestedAt string `json:"requestedAt,omitempty"`

	// Priority
	Priority string `json:"priority,omitempty"` // low, normal, high, urgent

	// Callback info (for domain services to resume processing)
	CallbackURL string `json:"callbackUrl,omitempty"`
	ExecutionID string `json:"executionId,omitempty"` // For idempotency

	// Metadata
	Metadata map[string]interface{} `json:"metadata,omitempty"`
}

// Validate validates the approval event
func (e *ApprovalEvent) Validate() error {
	if err := e.BaseEvent.Validate(); err != nil {
		return err
	}
	if e.ApprovalRequestID == "" {
		return fmt.Errorf("approval request ID is required")
	}
	if e.RequesterID == "" {
		return fmt.Errorf("requester ID is required")
	}
	if e.ActionType == "" {
		return fmt.Errorf("action type is required")
	}
	return nil
}

// GetSubject returns the NATS subject for this event
func (e *ApprovalEvent) GetSubject() string {
	return e.EventType
}

// GetStream returns the NATS stream name for this event
func (e *ApprovalEvent) GetStream() string {
	return StreamApprovals
}

// NewApprovalEvent creates a new approval event with base fields populated
func NewApprovalEvent(eventType, tenantID string) *ApprovalEvent {
	return &ApprovalEvent{
		BaseEvent: BaseEvent{
			EventType: eventType,
			TenantID:  tenantID,
			Timestamp: time.Now().UTC(),
		},
		ActionData: make(map[string]interface{}),
		Metadata:   make(map[string]interface{}),
	}
}

// ProductEvent represents a product-related event
type ProductEvent struct {
	BaseEvent

	// Product identification
	ProductID string `json:"productId"`
	SKU       string `json:"sku,omitempty"`

	// Product details
	ProductName string  `json:"productName"`
	Category    string  `json:"category,omitempty"`
	CategoryID  string  `json:"categoryId,omitempty"`
	Price       float64 `json:"price,omitempty"`
	Status      string  `json:"status,omitempty"` // active, draft, archived

	// Actor information
	ActorID    string `json:"actorId,omitempty"`
	ActorName  string `json:"actorName,omitempty"`
	ActorEmail string `json:"actorEmail,omitempty"`

	// Request context for audit trail
	ClientIP  string `json:"clientIp,omitempty"`
	UserAgent string `json:"userAgent,omitempty"`

	// Change details
	ChangeType  string                 `json:"changeType,omitempty"` // created, updated, deleted, published, archived
	OldValue    map[string]interface{} `json:"oldValue,omitempty"`
	NewValue    map[string]interface{} `json:"newValue,omitempty"`
	ChangedFields []string             `json:"changedFields,omitempty"`

	// Vendor info (for multi-vendor scenarios)
	VendorID   string `json:"vendorId,omitempty"`
	VendorName string `json:"vendorName,omitempty"`

	// Metadata
	Metadata map[string]interface{} `json:"metadata,omitempty"`
}

// Validate validates the product event
func (e *ProductEvent) Validate() error {
	if err := e.BaseEvent.Validate(); err != nil {
		return err
	}
	if e.ProductID == "" {
		return fmt.Errorf("product ID is required")
	}
	if e.ProductName == "" {
		return fmt.Errorf("product name is required")
	}
	return nil
}

// GetSubject returns the NATS subject for this event
func (e *ProductEvent) GetSubject() string {
	return e.EventType
}

// GetStream returns the NATS stream name for this event
func (e *ProductEvent) GetStream() string {
	return StreamProducts
}

// NewProductEvent creates a new product event with base fields populated
func NewProductEvent(eventType, tenantID string) *ProductEvent {
	return &ProductEvent{
		BaseEvent: BaseEvent{
			EventType: eventType,
			TenantID:  tenantID,
			Timestamp: time.Now().UTC(),
		},
		Metadata: make(map[string]interface{}),
	}
}

// TaxEvent represents a tax-related event
type TaxEvent struct {
	BaseEvent

	// Tax calculation info
	CalculationID  string  `json:"calculationId,omitempty"`
	OrderID        string  `json:"orderId,omitempty"`
	CustomerID     string  `json:"customerId,omitempty"`

	// Jurisdiction info
	JurisdictionID   string `json:"jurisdictionId,omitempty"`
	JurisdictionName string `json:"jurisdictionName,omitempty"`
	JurisdictionType string `json:"jurisdictionType,omitempty"` // STATE, COUNTY, CITY, SPECIAL

	// Tax rate info
	TaxRateID   string  `json:"taxRateId,omitempty"`
	TaxRate     float64 `json:"taxRate,omitempty"`
	TaxAmount   float64 `json:"taxAmount,omitempty"`
	TaxableAmount float64 `json:"taxableAmount,omitempty"`
	Currency    string  `json:"currency,omitempty"`

	// Exemption info
	ExemptionID     string `json:"exemptionId,omitempty"`
	ExemptionType   string `json:"exemptionType,omitempty"`
	ExemptionNumber string `json:"exemptionNumber,omitempty"`
	IsExempt        bool   `json:"isExempt,omitempty"`

	// Address info
	Address     string `json:"address,omitempty"`
	City        string `json:"city,omitempty"`
	State       string `json:"state,omitempty"`
	PostalCode  string `json:"postalCode,omitempty"`
	Country     string `json:"country,omitempty"`

	// Actor info
	ActorID   string `json:"actorId,omitempty"`
	ActorName string `json:"actorName,omitempty"`

	// Metadata
	Metadata map[string]interface{} `json:"metadata,omitempty"`
}

// Validate validates the tax event
func (e *TaxEvent) Validate() error {
	return e.BaseEvent.Validate()
}

// GetSubject returns the NATS subject for this event
func (e *TaxEvent) GetSubject() string {
	return e.EventType
}

// GetStream returns the NATS stream name for this event
func (e *TaxEvent) GetStream() string {
	return StreamTax
}

// NewTaxEvent creates a new tax event with base fields populated
func NewTaxEvent(eventType, tenantID string) *TaxEvent {
	return &TaxEvent{
		BaseEvent: BaseEvent{
			EventType: eventType,
			TenantID:  tenantID,
			Timestamp: time.Now().UTC(),
		},
		Currency: "USD",
		Metadata: make(map[string]interface{}),
	}
}

// SettingsEvent represents a settings-related event
type SettingsEvent struct {
	BaseEvent

	// Settings identification
	SettingKey     string `json:"settingKey"`
	SettingScope   string `json:"settingScope,omitempty"`   // GLOBAL, TENANT, USER
	SettingCategory string `json:"settingCategory,omitempty"` // general, payment, shipping, etc.

	// Values
	OldValue interface{} `json:"oldValue,omitempty"`
	NewValue interface{} `json:"newValue,omitempty"`

	// Bulk update info
	ChangedSettings []string `json:"changedSettings,omitempty"`
	SettingsCount   int      `json:"settingsCount,omitempty"`

	// Actor info
	ChangedBy     string `json:"changedBy,omitempty"`
	ChangedByName string `json:"changedByName,omitempty"`
	ChangedByIP   string `json:"changedByIP,omitempty"`

	// Metadata
	Metadata map[string]interface{} `json:"metadata,omitempty"`
}

// Validate validates the settings event
func (e *SettingsEvent) Validate() error {
	if err := e.BaseEvent.Validate(); err != nil {
		return err
	}
	if e.SettingKey == "" && len(e.ChangedSettings) == 0 {
		return fmt.Errorf("setting key or changed settings list is required")
	}
	return nil
}

// GetSubject returns the NATS subject for this event
func (e *SettingsEvent) GetSubject() string {
	return e.EventType
}

// GetStream returns the NATS stream name for this event
func (e *SettingsEvent) GetStream() string {
	return StreamSettings
}

// NewSettingsEvent creates a new settings event with base fields populated
func NewSettingsEvent(eventType, tenantID string) *SettingsEvent {
	return &SettingsEvent{
		BaseEvent: BaseEvent{
			EventType: eventType,
			TenantID:  tenantID,
			Timestamp: time.Now().UTC(),
		},
		Metadata: make(map[string]interface{}),
	}
}

// VerificationEvent represents a verification-related event
type VerificationEvent struct {
	BaseEvent

	// Verification identification
	VerificationID string `json:"verificationId"`
	VerificationType string `json:"verificationType"` // EMAIL, SMS, PHONE

	// Target info
	UserID    string `json:"userId,omitempty"`
	Email     string `json:"email,omitempty"`
	Phone     string `json:"phone,omitempty"`

	// Verification details
	Code         string `json:"code,omitempty"` // Only include in internal events
	ExpiresAt    string `json:"expiresAt,omitempty"`
	AttemptCount int    `json:"attemptCount,omitempty"`
	MaxAttempts  int    `json:"maxAttempts,omitempty"`

	// Status
	Status       string `json:"status"` // PENDING, VERIFIED, FAILED, EXPIRED
	FailureReason string `json:"failureReason,omitempty"`

	// Context
	Purpose   string `json:"purpose,omitempty"`   // login, registration, password_reset
	IPAddress string `json:"ipAddress,omitempty"`
	UserAgent string `json:"userAgent,omitempty"`

	// Metadata
	Metadata map[string]interface{} `json:"metadata,omitempty"`
}

// Validate validates the verification event
func (e *VerificationEvent) Validate() error {
	if err := e.BaseEvent.Validate(); err != nil {
		return err
	}
	if e.VerificationID == "" {
		return fmt.Errorf("verification ID is required")
	}
	return nil
}

// GetSubject returns the NATS subject for this event
func (e *VerificationEvent) GetSubject() string {
	return e.EventType
}

// GetStream returns the NATS stream name for this event
func (e *VerificationEvent) GetStream() string {
	return StreamVerification
}

// NewVerificationEvent creates a new verification event with base fields populated
func NewVerificationEvent(eventType, tenantID string) *VerificationEvent {
	return &VerificationEvent{
		BaseEvent: BaseEvent{
			EventType: eventType,
			TenantID:  tenantID,
			Timestamp: time.Now().UTC(),
		},
		Metadata: make(map[string]interface{}),
	}
}

// DocumentEvent represents a document-related event
type DocumentEvent struct {
	BaseEvent

	// Document identification
	DocumentID   string `json:"documentId"`
	DocumentType string `json:"documentType"` // ID, CONTRACT, INVOICE, etc.
	FileName     string `json:"fileName,omitempty"`
	FileSize     int64  `json:"fileSize,omitempty"`
	MimeType     string `json:"mimeType,omitempty"`

	// Storage info
	BucketName string `json:"bucketName,omitempty"`
	ObjectPath string `json:"objectPath,omitempty"`
	StorageURL string `json:"storageUrl,omitempty"`

	// Multi-product support
	ProductID     string `json:"productId,omitempty"`     // Product that owns this document (marketplace, bookkeeping, etc.)
	SourceService string `json:"sourceService,omitempty"` // Service that published the event

	// Owner info
	OwnerID   string `json:"ownerId,omitempty"`
	OwnerType string `json:"ownerType,omitempty"` // STAFF, CUSTOMER, VENDOR
	OwnerName string `json:"ownerName,omitempty"`

	// Processing status
	Status         string `json:"status"` // UPLOADED, PROCESSING, PROCESSED, FAILED, VERIFIED
	ProcessingType string `json:"processingType,omitempty"` // OCR, VIRUS_SCAN, THUMBNAIL
	ErrorMessage   string `json:"errorMessage,omitempty"`

	// Verification info
	VerifiedBy   string `json:"verifiedBy,omitempty"`
	VerifiedAt   string `json:"verifiedAt,omitempty"`
	ExpiresAt    string `json:"expiresAt,omitempty"`

	// Actor info
	UploadedBy     string `json:"uploadedBy,omitempty"`
	UploadedByName string `json:"uploadedByName,omitempty"`

	// Metadata
	Metadata map[string]interface{} `json:"metadata,omitempty"`
}

// Validate validates the document event
func (e *DocumentEvent) Validate() error {
	if err := e.BaseEvent.Validate(); err != nil {
		return err
	}
	if e.DocumentID == "" {
		return fmt.Errorf("document ID is required")
	}
	return nil
}

// GetSubject returns the NATS subject for this event
func (e *DocumentEvent) GetSubject() string {
	return e.EventType
}

// GetStream returns the NATS stream name for this event
func (e *DocumentEvent) GetStream() string {
	return StreamDocuments
}

// NewDocumentEvent creates a new document event with base fields populated
func NewDocumentEvent(eventType, tenantID string) *DocumentEvent {
	return &DocumentEvent{
		BaseEvent: BaseEvent{
			EventType: eventType,
			TenantID:  tenantID,
			Timestamp: time.Now().UTC(),
		},
		Metadata: make(map[string]interface{}),
	}
}

// LocationEvent represents a location/geocoding event
type LocationEvent struct {
	BaseEvent

	// Location identification
	LocationID string `json:"locationId,omitempty"`
	QueryID    string `json:"queryId,omitempty"`

	// Input data
	QueryAddress string  `json:"queryAddress,omitempty"`
	Latitude     float64 `json:"latitude,omitempty"`
	Longitude    float64 `json:"longitude,omitempty"`

	// Result data
	FormattedAddress string `json:"formattedAddress,omitempty"`
	StreetNumber     string `json:"streetNumber,omitempty"`
	Street           string `json:"street,omitempty"`
	City             string `json:"city,omitempty"`
	State            string `json:"state,omitempty"`
	PostalCode       string `json:"postalCode,omitempty"`
	Country          string `json:"country,omitempty"`
	CountryCode      string `json:"countryCode,omitempty"`
	PlaceID          string `json:"placeId,omitempty"`

	// Cache info
	CacheHit     bool   `json:"cacheHit,omitempty"`
	CacheKey     string `json:"cacheKey,omitempty"`
	CacheTTL     int    `json:"cacheTTL,omitempty"`

	// Provider info
	Provider      string `json:"provider,omitempty"` // google, mapbox, here
	ResponseTime  int64  `json:"responseTime,omitempty"` // in milliseconds
	Confidence    float64 `json:"confidence,omitempty"`

	// Metadata
	Metadata map[string]interface{} `json:"metadata,omitempty"`
}

// Validate validates the location event
func (e *LocationEvent) Validate() error {
	return e.BaseEvent.Validate()
}

// GetSubject returns the NATS subject for this event
func (e *LocationEvent) GetSubject() string {
	return e.EventType
}

// GetStream returns the NATS stream name for this event
func (e *LocationEvent) GetStream() string {
	return StreamLocation
}

// NewLocationEvent creates a new location event with base fields populated
func NewLocationEvent(eventType, tenantID string) *LocationEvent {
	return &LocationEvent{
		BaseEvent: BaseEvent{
			EventType: eventType,
			TenantID:  tenantID,
			Timestamp: time.Now().UTC(),
		},
		Metadata: make(map[string]interface{}),
	}
}

// QREvent represents a QR code event
type QREvent struct {
	BaseEvent

	// QR identification
	QRID     string `json:"qrId"`
	QRCode   string `json:"qrCode,omitempty"` // The encoded content
	QRType   string `json:"qrType"`           // URL, TEXT, VCARD, WIFI, etc.

	// Content info
	Content     string `json:"content"`
	ContentType string `json:"contentType,omitempty"` // What the QR encodes

	// Generation info
	Format     string `json:"format,omitempty"`     // PNG, SVG
	Size       int    `json:"size,omitempty"`       // Pixel dimensions
	ErrorLevel string `json:"errorLevel,omitempty"` // L, M, Q, H

	// Associated entity
	EntityType string `json:"entityType,omitempty"` // ORDER, PRODUCT, TICKET, etc.
	EntityID   string `json:"entityId,omitempty"`

	// Scan info (for scanned events)
	ScannedAt   string `json:"scannedAt,omitempty"`
	ScannedBy   string `json:"scannedBy,omitempty"`
	ScannerIP   string `json:"scannerIP,omitempty"`
	ScannerType string `json:"scannerType,omitempty"` // MOBILE, SCANNER, POS

	// Expiry
	ExpiresAt string `json:"expiresAt,omitempty"`
	IsExpired bool   `json:"isExpired,omitempty"`

	// Metadata
	Metadata map[string]interface{} `json:"metadata,omitempty"`
}

// Validate validates the QR event
func (e *QREvent) Validate() error {
	if err := e.BaseEvent.Validate(); err != nil {
		return err
	}
	if e.QRID == "" {
		return fmt.Errorf("QR ID is required")
	}
	return nil
}

// GetSubject returns the NATS subject for this event
func (e *QREvent) GetSubject() string {
	return e.EventType
}

// GetStream returns the NATS stream name for this event
func (e *QREvent) GetStream() string {
	return StreamQR
}

// NewQREvent creates a new QR event with base fields populated
func NewQREvent(eventType, tenantID string) *QREvent {
	return &QREvent{
		BaseEvent: BaseEvent{
			EventType: eventType,
			TenantID:  tenantID,
			Timestamp: time.Now().UTC(),
		},
		Metadata: make(map[string]interface{}),
	}
}

// AnalyticsEvent represents an analytics event
type AnalyticsEvent struct {
	BaseEvent

	// Event identification
	AnalyticsID string `json:"analyticsId"`
	EventName   string `json:"eventName"`
	EventCategory string `json:"eventCategory,omitempty"` // pageview, click, conversion, etc.

	// User info
	UserID      string `json:"userId,omitempty"`
	SessionID   string `json:"sessionId,omitempty"`
	AnonymousID string `json:"anonymousId,omitempty"`

	// Page info
	PageURL     string `json:"pageUrl,omitempty"`
	PageTitle   string `json:"pageTitle,omitempty"`
	PagePath    string `json:"pagePath,omitempty"`
	Referrer    string `json:"referrer,omitempty"`

	// Device info
	DeviceType   string `json:"deviceType,omitempty"`   // desktop, mobile, tablet
	Browser      string `json:"browser,omitempty"`
	OS           string `json:"os,omitempty"`
	ScreenWidth  int    `json:"screenWidth,omitempty"`
	ScreenHeight int    `json:"screenHeight,omitempty"`

	// Location info
	Country   string `json:"country,omitempty"`
	Region    string `json:"region,omitempty"`
	City      string `json:"city,omitempty"`
	IPAddress string `json:"ipAddress,omitempty"`

	// Goal/Conversion info
	GoalID      string  `json:"goalId,omitempty"`
	GoalName    string  `json:"goalName,omitempty"`
	GoalValue   float64 `json:"goalValue,omitempty"`

	// Custom properties
	Properties map[string]interface{} `json:"properties,omitempty"`

	// Metadata
	Metadata map[string]interface{} `json:"metadata,omitempty"`
}

// Validate validates the analytics event
func (e *AnalyticsEvent) Validate() error {
	if err := e.BaseEvent.Validate(); err != nil {
		return err
	}
	if e.EventName == "" {
		return fmt.Errorf("event name is required")
	}
	return nil
}

// GetSubject returns the NATS subject for this event
func (e *AnalyticsEvent) GetSubject() string {
	return e.EventType
}

// GetStream returns the NATS stream name for this event
func (e *AnalyticsEvent) GetStream() string {
	return StreamAnalytics
}

// NewAnalyticsEvent creates a new analytics event with base fields populated
func NewAnalyticsEvent(eventType, tenantID string) *AnalyticsEvent {
	return &AnalyticsEvent{
		BaseEvent: BaseEvent{
			EventType: eventType,
			TenantID:  tenantID,
			Timestamp: time.Now().UTC(),
		},
		Properties: make(map[string]interface{}),
		Metadata:   make(map[string]interface{}),
	}
}

// DomainEvent represents a custom domain event
type DomainEvent struct {
	BaseEvent

	// Domain identification
	DomainID   string `json:"domainId"`
	Domain     string `json:"domain"`
	DomainType string `json:"domainType,omitempty"` // apex, subdomain

	// Tenant info
	TenantSlug string `json:"tenantSlug,omitempty"`

	// Owner info (admin who added the domain)
	OwnerID    string `json:"ownerId,omitempty"`
	OwnerEmail string `json:"ownerEmail,omitempty"`
	OwnerName  string `json:"ownerName,omitempty"`

	// Domain status
	Status         string `json:"status"`                   // pending, verifying, provisioning, active, failed, deleting
	PreviousStatus string `json:"previousStatus,omitempty"`
	StatusMessage  string `json:"statusMessage,omitempty"`

	// DNS verification
	DNSVerified       bool   `json:"dnsVerified,omitempty"`
	DNSVerifiedAt     string `json:"dnsVerifiedAt,omitempty"`
	VerificationToken string `json:"verificationToken,omitempty"` // Token for DNS TXT verification
	DNSRecordType     string `json:"dnsRecordType,omitempty"`     // CNAME, A, TXT
	DNSRecordName     string `json:"dnsRecordName,omitempty"`     // Record name to add
	DNSRecordValue    string `json:"dnsRecordValue,omitempty"`    // Record value to add

	// SSL info
	SSLStatus     string `json:"sslStatus,omitempty"`     // pending, provisioning, active, failed, expired
	SSLExpiresAt  string `json:"sslExpiresAt,omitempty"`
	SSLProvider   string `json:"sslProvider,omitempty"`   // letsencrypt

	// Routing info
	RoutingStatus string `json:"routingStatus,omitempty"` // pending, active, failed
	IsPrimary     bool   `json:"isPrimary,omitempty"`
	RoutingTarget string `json:"routingTarget,omitempty"` // Target service/endpoint for routing
	RoutingPath   string `json:"routingPath,omitempty"`   // Path prefix if any

	// Target info
	TargetType    string `json:"targetType,omitempty"` // storefront, admin
	TargetURL     string `json:"targetUrl,omitempty"`

	// Migration info (for domain.migrated events)
	MigratedFrom    string `json:"migratedFrom,omitempty"`    // Previous subdomain (e.g., slug.tesserix.app)
	MigratedTo      string `json:"migratedTo,omitempty"`      // New infrastructure/target
	MigratedAt      string `json:"migratedAt,omitempty"`
	MigrationReason string `json:"migrationReason,omitempty"` // Reason for migration

	// Failure info
	FailureReason string `json:"failureReason,omitempty"`
	FailureCode   string `json:"failureCode,omitempty"`   // Error code for troubleshooting
	FailureStage  string `json:"failureStage,omitempty"` // dns_verification, ssl_provisioning, routing

	// Health check info (for health_check_failed events)
	LastHealthCheck string `json:"lastHealthCheck,omitempty"`
	ResponseTime    int    `json:"responseTime,omitempty"` // in ms
	HTTPStatusCode  int    `json:"httpStatusCode,omitempty"`

	// URLs for customer
	DomainURL string `json:"domainUrl,omitempty"` // Full URL (https://custom.domain.com)
	AdminURL  string `json:"adminUrl,omitempty"`  // Admin dashboard URL

	// Metadata
	Metadata map[string]interface{} `json:"metadata,omitempty"`
}

// Validate validates the domain event
func (e *DomainEvent) Validate() error {
	if err := e.BaseEvent.Validate(); err != nil {
		return err
	}
	if e.DomainID == "" && e.Domain == "" {
		return fmt.Errorf("domain ID or domain name is required")
	}
	return nil
}

// GetSubject returns the NATS subject for this event
func (e *DomainEvent) GetSubject() string {
	return e.EventType
}

// GetStream returns the NATS stream name for this event
func (e *DomainEvent) GetStream() string {
	return StreamDomains
}

// NewDomainEvent creates a new domain event with base fields populated
func NewDomainEvent(eventType, tenantID string) *DomainEvent {
	return &DomainEvent{
		BaseEvent: BaseEvent{
			EventType: eventType,
			TenantID:  tenantID,
			Timestamp: time.Now().UTC(),
		},
		Metadata: make(map[string]interface{}),
	}
}
