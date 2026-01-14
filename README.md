# Go Shared Libraries

Production-grade shared Go packages for Tesseract multi-tenant SaaS platform microservices.

## Architecture Overview

This library provides core infrastructure for building scalable, multi-tenant microservices with:
- **Multi-Tenancy**: Tenant isolation, sharding, and scoped data access
- **Authentication**: Keycloak/OIDC with legacy JWT support
- **Authorization**: Role-based access control with permission hierarchy
- **Event-Driven**: NATS streaming with 70+ domain event types
- **Observability**: Structured logging, Prometheus metrics, OpenTelemetry tracing

## Installation

```bash
go get github.com/Tesseract-Nexus/go-shared
```

## Packages

### Authentication & Authorization

| Package | Description |
|---------|-------------|
| `auth` | Keycloak/OIDC JWT validation with RS256, JWKS caching, legacy HS256 support |
| `rbac` | Role-based access control with staff-service integration, permission hierarchy, 2FA enforcement |

**Auth Features:**
- Keycloak claims parsing with role helpers (`HasRole`, `IsSuperAdmin`, `IsTenantAdmin`)
- JWKS cache pre-warming for performance
- Backward compatibility with legacy token formats
- Token statistics tracking (success rate, token types)

**RBAC Role Priority:**
| Priority | Role | Access Level |
|----------|------|--------------|
| 10 | Viewer | Read-only |
| 50 | Customer Support | Order/customer support |
| 60 | Specialist | Inventory/order management |
| 70 | Store Manager | Operations |
| 90 | Store Admin | Full admin (except finance) |
| 100 | Store Owner | Unrestricted |

### Database

| Package | Description |
|---------|-------------|
| `database` | PostgreSQL/GORM with connection pooling, sharding, read replicas |
| `repository` | Generic repository pattern with CRUD, pagination, search, soft delete |

**Database Features:**
- **Connection Pool Profiles**: Default, HighThroughput, LowLatency, Background
- **Sharding**: Tenant-based consistent hashing (SHA256)
- **Read Replicas**: Round-robin selection with lag monitoring
- **Health Checks**: Per-shard with configurable timeout

**Repository Features:**
- Generic CRUD with Go 1.18+ generics
- Batch operations (CreateBatch, UpdateBatch, DeleteBatch)
- Full-text search across multiple fields
- Tenant-scoped queries
- Soft delete support
- Transaction management

### HTTP & Middleware

| Package | Description |
|---------|-------------|
| `middleware` | Gin middleware collection for auth, CORS, rate limiting, metrics |
| `http` | HTTP utilities and helpers |
| `httpclient` | HTTP client with retry and circuit breaker |

**Middleware Components:**
- `keycloak_auth` - Keycloak JWT authentication with role requirements
- `auth` - Legacy JWT authentication
- `cors` - CORS handling
- `tenant` - Multi-tenant isolation
- `ratelimit` - In-memory rate limiting
- `ratelimit_redis` - Redis-backed distributed rate limiting
- `metrics` - Prometheus HTTP metrics
- `compression` - Gzip response compression
- `security_headers` - HSTS, CSP, X-Frame-Options
- `request_id` - Request ID tracking/propagation
- `error_handler` - Centralized error handling
- `response` - Standardized JSON responses
- `coalesce` - Request coalescing/deduplication
- `istio_headers` - Service mesh header handling

### Events

| Package | Description |
|---------|-------------|
| `events` | NATS event definitions with 70+ domain event types |

**Event Categories:**
- **Order**: created, confirmed, paid, shipped, delivered, cancelled, refunded
- **Payment**: pending, captured, succeeded, failed, refunded
- **Customer**: registered, created, updated, deleted
- **Auth**: password_reset, login_success, login_failed, account_locked
- **Inventory**: low_stock, out_of_stock, restocked, adjusted
- **Product**: created, updated, deleted, published, archived
- **Approval**: requested, granted, rejected, cancelled, escalated
- **Tenant**: created, activated, deactivated, subscription_changed
- **Staff**: created, updated, role_changed
- **Support**: ticket_created, assigned, resolved, closed
- **Tax**: calculated, jurisdiction_updated, exemption_created
- **Document**: uploaded, processed, verified, deleted
- **Analytics**: event_tracked, page_viewed, goal_completed

**Event Features:**
- `BaseEvent` with traceID, correlationID for distributed tracing
- Validation methods on all event types
- Factory functions (`NewOrderEvent`, `NewPaymentEvent`, etc.)

### Observability

| Package | Description |
|---------|-------------|
| `logger` | Structured logging (slog) with PII protection |
| `metrics` | Prometheus metrics collection |
| `tracing` | OpenTelemetry distributed tracing |

**Logger Features:**
- JSON or text format output
- Context-aware (request_id, user_id, tenant_id)
- Specialized loggers: `LogRequest`, `LogQuery`, `LogAudit`, `LogSecurityEvent`
- Automatic PII sanitization

**Metrics Tracked:**
- `http_requests_total` - Request count by method/path/status
- `http_request_duration_seconds` - Latency histogram
- `http_request_size_bytes` / `http_response_size_bytes`

### Infrastructure

| Package | Description |
|---------|-------------|
| `config` | Environment-based configuration with GCP Secret Manager |
| `cache` | Redis caching abstraction |
| `secrets` | GCP Secret Manager integration |
| `errors` | Standardized error types with HTTP status mapping |
| `security` | Encryption utilities and PII masking |
| `validation` | Input validation utilities |
| `clients` | Service clients (approval-service) |

**Error Types:**
- Authentication: `ErrMissingToken`, `ErrInvalidToken`, `ErrExpiredToken`
- Authorization: `ErrUnauthorized`, `ErrForbidden`, `ErrInsufficientPermissions`
- Validation: `ErrBadRequest`, `ErrValidationFailed`
- Data: `ErrNotFound`, `ErrConflict`, `ErrAlreadyExists`
- Database: `ErrDatabase`
- External: `ErrExternalService`

### Testing

| Package | Description |
|---------|-------------|
| `testutil` | Testing utilities, mocks, and integration test helpers |

## Usage Examples

### Authentication Middleware

```go
import (
    "github.com/Tesseract-Nexus/go-shared/middleware"
)

// Initialize Keycloak auth
authMiddleware := middleware.NewKeycloakAuthMiddleware(config)

router := gin.Default()

// Protected routes
api := router.Group("/api")
api.Use(authMiddleware.Handler())

// Role-based access
admin := api.Group("/admin")
admin.Use(authMiddleware.RequireRole("admin"))
```

### Repository Pattern

```go
import (
    "github.com/Tesseract-Nexus/go-shared/repository"
)

type Product struct {
    ID        string `gorm:"primaryKey"`
    TenantID  string
    Name      string
    Price     float64
    DeletedAt *time.Time
}

func (p *Product) GetID() string { return p.ID }
func (p *Product) SetID(id string) { p.ID = id }

// Create repository
repo := repository.NewBaseRepository[Product](db)

// CRUD operations
product, err := repo.Create(ctx, &Product{Name: "Widget", Price: 9.99})
products, err := repo.FindAll(ctx, repository.QueryOptions{
    TenantID: "tenant-123",
    Search:   "widget",
    Page:     1,
    PageSize: 20,
})
```

### Event Publishing

```go
import (
    "github.com/Tesseract-Nexus/go-shared/events"
)

event := events.NewOrderEvent(events.OrderCreated, tenantID, orderData)
event.TraceID = traceID
event.CorrelationID = correlationID

if err := event.Validate(); err != nil {
    return err
}

publisher.Publish("order.created", event)
```

### Database with Sharding

```go
import (
    "github.com/Tesseract-Nexus/go-shared/database"
)

// Create shard router
router := database.NewShardRouter(shardConfigs)

// Get shard for tenant
db := router.GetShardForTenant(tenantID)

// Or use read replica
readDB := router.GetReadReplica(tenantID)
```

## Dependencies

| Dependency | Purpose |
|------------|---------|
| `gin-gonic/gin` | HTTP framework |
| `gorm.io/gorm` | ORM |
| `lib/pq` | PostgreSQL driver |
| `nats-io/nats.go` | Message streaming |
| `golang-jwt/jwt` | JWT handling |
| `redis/go-redis` | Redis client |
| `prometheus/client_golang` | Metrics |
| `opentelemetry.io/otel` | Distributed tracing |
| `sirupsen/logrus` | Logging |
| `cloud.google.com/go/secretmanager` | GCP secrets |

## Requirements

- Go 1.25+
- PostgreSQL 14+
- Redis 7+ (for caching and rate limiting)
- NATS 2.9+ (for event streaming)
- Keycloak 22+ (for authentication)
- GCP credentials (for Secret Manager)

## License

Proprietary - Tesseract Nexus
