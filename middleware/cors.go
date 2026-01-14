package middleware

import (
	"net/http"
	"os"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
)

// CORSConfig holds CORS configuration options
type CORSConfig struct {
	AllowedOrigins   []string
	AllowedMethods   []string
	AllowedHeaders   []string
	ExposedHeaders   []string
	AllowCredentials bool
	MaxAge           int
}

// DefaultCORSConfig returns a default CORS configuration
func DefaultCORSConfig() CORSConfig {
	return CORSConfig{
		AllowedOrigins: []string{"*"},
		AllowedMethods: []string{"GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"},
		AllowedHeaders: []string{
			"Content-Type",
			"Authorization",
			"X-Tenant-ID",
			"X-User-ID",
			"X-Request-ID",
			"x-user-id",
			"x-tenant-id",
			"Accept",
			"Accept-Language",
			"Content-Language",
			"Origin",
		},
		ExposedHeaders: []string{
			"Content-Length",
			"X-Request-ID",
			"X-Total-Count",
		},
		AllowCredentials: true,
		MaxAge:           86400, // 24 hours
	}
}

// ProductionCORSConfig returns a secure CORS configuration for production
func ProductionCORSConfig() CORSConfig {
	allowedOrigins := []string{
		"https://app.tesseract.com",
		"https://admin.tesseract.com",
		"https://api.tesseract.com",
	}

	// Allow environment-specific origins
	if envOrigins := os.Getenv("CORS_ALLOWED_ORIGINS"); envOrigins != "" {
		allowedOrigins = strings.Split(envOrigins, ",")
		for i, origin := range allowedOrigins {
			allowedOrigins[i] = strings.TrimSpace(origin)
		}
	}

	config := DefaultCORSConfig()
	config.AllowedOrigins = allowedOrigins
	return config
}

// CORS creates a CORS middleware with default configuration
func CORS() gin.HandlerFunc {
	return CORSWithConfig(DefaultCORSConfig())
}

// CORSWithConfig creates a CORS middleware with custom configuration
func CORSWithConfig(config CORSConfig) gin.HandlerFunc {
	return func(c *gin.Context) {
		origin := c.GetHeader("Origin")

		// Set Access-Control-Allow-Origin
		if len(config.AllowedOrigins) == 1 && config.AllowedOrigins[0] == "*" {
			c.Header("Access-Control-Allow-Origin", "*")
		} else if isOriginAllowed(origin, config.AllowedOrigins) {
			c.Header("Access-Control-Allow-Origin", origin)
		}

		// Set other CORS headers
		c.Header("Access-Control-Allow-Methods", strings.Join(config.AllowedMethods, ", "))
		c.Header("Access-Control-Allow-Headers", strings.Join(config.AllowedHeaders, ", "))

		if len(config.ExposedHeaders) > 0 {
			c.Header("Access-Control-Expose-Headers", strings.Join(config.ExposedHeaders, ", "))
		}

		if config.AllowCredentials {
			c.Header("Access-Control-Allow-Credentials", "true")
		}

		if config.MaxAge > 0 {
			c.Header("Access-Control-Max-Age", strconv.Itoa(config.MaxAge))
		}

		// Handle preflight OPTIONS request
		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(http.StatusNoContent)
			return
		}

		c.Next()
	}
}

// isOriginAllowed checks if the origin is in the allowed list
func isOriginAllowed(origin string, allowedOrigins []string) bool {
	for _, allowed := range allowedOrigins {
		if allowed == "*" || allowed == origin {
			return true
		}
	}
	return false
}

// DevelopmentCORS returns a permissive CORS middleware for development
func DevelopmentCORS() gin.HandlerFunc {
	return CORS()
}

// ProductionCORS returns a secure CORS middleware for production
func ProductionCORS() gin.HandlerFunc {
	return CORSWithConfig(ProductionCORSConfig())
}
