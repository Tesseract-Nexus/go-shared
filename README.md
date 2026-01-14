# Go Shared Libraries

Shared Go packages for Tesseract platform microservices.

## Packages

| Package | Description |
|---------|-------------|
| `auth` | JWT authentication and authorization utilities |
| `cache` | Redis caching abstraction |
| `clients` | HTTP and service clients |
| `config` | Configuration management |
| `database` | Database connection and utilities (PostgreSQL/GORM) |
| `errors` | Custom error types and handling |
| `events` | NATS event publishing and subscription |
| `http` | HTTP utilities and helpers |
| `httpclient` | HTTP client with retry and circuit breaker |
| `logger` | Structured logging with Logrus |
| `metrics` | Prometheus metrics collection |
| `middleware` | Gin middleware (auth, logging, rate limiting, etc.) |
| `rbac` | Role-based access control |
| `repository` | Generic repository patterns |
| `secrets` | GCP Secret Manager integration |
| `security` | Security utilities (hashing, encryption) |
| `testutil` | Testing utilities and mocks |
| `tracing` | OpenTelemetry distributed tracing |
| `validation` | Input validation utilities |

## Installation

```bash
go get github.com/Tesseract-Nexus/go-shared
```

## Usage

Import individual packages as needed:

```go
import (
    "github.com/Tesseract-Nexus/go-shared/auth"
    "github.com/Tesseract-Nexus/go-shared/logger"
    "github.com/Tesseract-Nexus/go-shared/middleware"
)
```

## Requirements

- Go 1.25+
- PostgreSQL (for database package)
- Redis (for cache package)
- NATS (for events package)
- GCP credentials (for secrets package)

## License

Proprietary - Tesseract Nexus
