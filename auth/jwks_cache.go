package auth

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
)

// JWKS represents a JSON Web Key Set
type JWKS struct {
	Keys []JWK `json:"keys"`
}

// JWK represents a JSON Web Key
type JWK struct {
	Kty string `json:"kty"` // Key Type (RSA, EC, etc.)
	Use string `json:"use"` // Public Key Use (sig, enc)
	Kid string `json:"kid"` // Key ID
	Alg string `json:"alg"` // Algorithm (RS256, ES256, etc.)
	N   string `json:"n"`   // RSA modulus
	E   string `json:"e"`   // RSA exponent
	// EC keys (for future use)
	Crv string `json:"crv,omitempty"` // Curve (P-256, P-384, P-521)
	X   string `json:"x,omitempty"`   // X coordinate
	Y   string `json:"y,omitempty"`   // Y coordinate
}

// ToRSAPublicKey converts a JWK to an RSA public key
func (jwk *JWK) ToRSAPublicKey() (*rsa.PublicKey, error) {
	if jwk.Kty != "RSA" {
		return nil, fmt.Errorf("unsupported key type: %s", jwk.Kty)
	}

	// Decode modulus (N)
	nBytes, err := base64.RawURLEncoding.DecodeString(jwk.N)
	if err != nil {
		return nil, fmt.Errorf("failed to decode modulus: %w", err)
	}
	n := new(big.Int).SetBytes(nBytes)

	// Decode exponent (E)
	eBytes, err := base64.RawURLEncoding.DecodeString(jwk.E)
	if err != nil {
		return nil, fmt.Errorf("failed to decode exponent: %w", err)
	}

	// Convert exponent bytes to int
	var e int
	for _, b := range eBytes {
		e = e<<8 + int(b)
	}

	return &rsa.PublicKey{
		N: n,
		E: e,
	}, nil
}

// JWKSCacheEntry represents a cached JWKS with expiration
type JWKSCacheEntry struct {
	Keys       map[string]*rsa.PublicKey // kid -> public key
	RawKeys    JWKS                      // Original JWKS for debugging
	FetchedAt  time.Time
	ExpiresAt  time.Time
	FetchCount int64
	HitCount   int64
}

// IsExpired checks if the cache entry is expired
func (e *JWKSCacheEntry) IsExpired() bool {
	return time.Now().After(e.ExpiresAt)
}

// JWKSCache provides thread-safe caching of JWKS
type JWKSCache struct {
	mu          sync.RWMutex
	cache       map[string]*JWKSCacheEntry // issuer -> cache entry
	config      KeycloakConfig
	httpClient  *http.Client
	logger      *logrus.Entry
	refreshLock sync.Map // per-issuer refresh lock

	// Circuit breaker state
	failures    map[string]int       // issuer -> consecutive failures
	lastFailure map[string]time.Time // issuer -> last failure time
	circuitOpen map[string]bool      // issuer -> circuit open status

	// Metrics
	fetchTotal   int64
	fetchSuccess int64
	fetchFailure int64
	cacheHits    int64
	cacheMisses  int64
}

// NewJWKSCache creates a new JWKS cache
func NewJWKSCache(config KeycloakConfig, logger *logrus.Logger) *JWKSCache {
	return &JWKSCache{
		cache: make(map[string]*JWKSCacheEntry),
		config: config,
		httpClient: &http.Client{
			Timeout: config.JWKSRefreshTimeout,
			Transport: &http.Transport{
				MaxIdleConns:        10,
				MaxIdleConnsPerHost: 5,
				IdleConnTimeout:     90 * time.Second,
			},
		},
		logger:      logger.WithField("component", "jwks_cache"),
		failures:    make(map[string]int),
		lastFailure: make(map[string]time.Time),
		circuitOpen: make(map[string]bool),
	}
}

// GetKey retrieves a public key for the given issuer and key ID
func (c *JWKSCache) GetKey(ctx context.Context, issuer, kid string) (*rsa.PublicKey, error) {
	// Check cache first (read lock)
	c.mu.RLock()
	entry, exists := c.cache[issuer]
	if exists && !entry.IsExpired() {
		if key, ok := entry.Keys[kid]; ok {
			entry.HitCount++
			c.cacheHits++
			c.mu.RUnlock()
			return key, nil
		}
	}
	c.mu.RUnlock()

	// Cache miss - need to refresh
	c.cacheMisses++

	// Check circuit breaker
	if c.isCircuitOpen(issuer) {
		// Return cached key if available, even if expired
		c.mu.RLock()
		if entry, ok := c.cache[issuer]; ok {
			if key, ok := entry.Keys[kid]; ok {
				c.mu.RUnlock()
				c.logger.Warn("Circuit open, returning stale cached key")
				return key, nil
			}
		}
		c.mu.RUnlock()
		return nil, NewJWKSFetchError(issuer, fmt.Errorf("circuit breaker open"))
	}

	// Refresh JWKS (with per-issuer lock to prevent thundering herd)
	if err := c.refreshJWKS(ctx, issuer); err != nil {
		// Return cached key if available, even if refresh failed
		c.mu.RLock()
		if entry, ok := c.cache[issuer]; ok {
			if key, ok := entry.Keys[kid]; ok {
				c.mu.RUnlock()
				c.logger.WithError(err).Warn("JWKS refresh failed, returning stale cached key")
				return key, nil
			}
		}
		c.mu.RUnlock()
		return nil, err
	}

	// Try to get key from refreshed cache
	c.mu.RLock()
	defer c.mu.RUnlock()

	entry, exists = c.cache[issuer]
	if !exists {
		return nil, NewJWKSFetchError(issuer, fmt.Errorf("cache entry not found after refresh"))
	}

	key, ok := entry.Keys[kid]
	if !ok {
		return nil, NewJWKSKeyNotFoundError(kid)
	}

	return key, nil
}

// refreshJWKS fetches and caches JWKS from the issuer
func (c *JWKSCache) refreshJWKS(ctx context.Context, issuer string) error {
	// Per-issuer lock to prevent concurrent refreshes
	lockKey := "refresh:" + issuer
	if _, loaded := c.refreshLock.LoadOrStore(lockKey, true); loaded {
		// Another goroutine is already refreshing, wait for it
		time.Sleep(100 * time.Millisecond)
		return nil
	}
	defer c.refreshLock.Delete(lockKey)

	jwksURL := c.config.GetJWKSURL(issuer)
	if jwksURL == "" {
		return fmt.Errorf("no JWKS URL for issuer: %s", issuer)
	}

	c.fetchTotal++
	c.logger.WithField("url", jwksURL).Debug("Fetching JWKS")

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, jwksURL, nil)
	if err != nil {
		c.recordFailure(issuer)
		c.fetchFailure++
		return NewJWKSFetchError(issuer, err)
	}

	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "Tesseract-Hub/1.0")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		c.recordFailure(issuer)
		c.fetchFailure++
		return NewJWKSFetchError(issuer, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		c.recordFailure(issuer)
		c.fetchFailure++
		return NewJWKSFetchError(issuer, fmt.Errorf("unexpected status: %d", resp.StatusCode))
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		c.recordFailure(issuer)
		c.fetchFailure++
		return NewJWKSFetchError(issuer, err)
	}

	var jwks JWKS
	if err := json.Unmarshal(body, &jwks); err != nil {
		c.recordFailure(issuer)
		c.fetchFailure++
		return &TokenValidationError{
			Code:    "JWKS_PARSE_ERROR",
			Message: "Failed to parse JWKS response",
			Issuer:  issuer,
			Cause:   err,
		}
	}

	// Convert JWKs to RSA public keys
	keys := make(map[string]*rsa.PublicKey)
	for _, jwk := range jwks.Keys {
		if jwk.Kty != "RSA" || jwk.Use != "sig" {
			continue // Skip non-RSA and non-signing keys
		}

		pubKey, err := jwk.ToRSAPublicKey()
		if err != nil {
			c.logger.WithError(err).WithField("kid", jwk.Kid).Warn("Failed to parse JWK")
			continue
		}
		keys[jwk.Kid] = pubKey
	}

	if len(keys) == 0 {
		c.recordFailure(issuer)
		c.fetchFailure++
		return NewJWKSFetchError(issuer, fmt.Errorf("no valid RSA signing keys found"))
	}

	// Update cache
	c.mu.Lock()
	existingEntry := c.cache[issuer]
	var fetchCount int64
	if existingEntry != nil {
		fetchCount = existingEntry.FetchCount
	}

	c.cache[issuer] = &JWKSCacheEntry{
		Keys:       keys,
		RawKeys:    jwks,
		FetchedAt:  time.Now(),
		ExpiresAt:  time.Now().Add(c.config.JWKSCacheTTL),
		FetchCount: fetchCount + 1,
	}
	c.mu.Unlock()

	// Reset failure count on success
	c.resetFailure(issuer)
	c.fetchSuccess++

	c.logger.WithFields(logrus.Fields{
		"issuer":   issuer,
		"keyCount": len(keys),
	}).Debug("JWKS cache refreshed")

	return nil
}

// Circuit breaker methods

func (c *JWKSCache) isCircuitOpen(issuer string) bool {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if !c.circuitOpen[issuer] {
		return false
	}

	// Check if enough time has passed to try again (half-open state)
	lastFail := c.lastFailure[issuer]
	if time.Since(lastFail) > 30*time.Second {
		return false
	}

	return true
}

func (c *JWKSCache) recordFailure(issuer string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.failures[issuer]++
	c.lastFailure[issuer] = time.Now()

	// Open circuit after 3 consecutive failures
	if c.failures[issuer] >= 3 {
		c.circuitOpen[issuer] = true
		c.logger.WithField("issuer", issuer).Warn("Circuit breaker opened for issuer")
	}
}

func (c *JWKSCache) resetFailure(issuer string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.failures[issuer] = 0
	c.circuitOpen[issuer] = false
}

// PreWarm fetches JWKS for all configured issuers
func (c *JWKSCache) PreWarm(ctx context.Context) error {
	issuers := []string{}
	if c.config.CustomerIssuer != "" {
		issuers = append(issuers, c.config.CustomerIssuer)
	}
	if c.config.InternalIssuer != "" {
		issuers = append(issuers, c.config.InternalIssuer)
	}

	var lastErr error
	for _, issuer := range issuers {
		if err := c.refreshJWKS(ctx, issuer); err != nil {
			c.logger.WithError(err).WithField("issuer", issuer).Error("Failed to pre-warm JWKS cache")
			lastErr = err
		} else {
			c.logger.WithField("issuer", issuer).Info("Pre-warmed JWKS cache")
		}
	}

	return lastErr
}

// Stats returns cache statistics
func (c *JWKSCache) Stats() map[string]interface{} {
	c.mu.RLock()
	defer c.mu.RUnlock()

	entries := make(map[string]interface{})
	for issuer, entry := range c.cache {
		entries[issuer] = map[string]interface{}{
			"key_count":   len(entry.Keys),
			"fetched_at":  entry.FetchedAt,
			"expires_at":  entry.ExpiresAt,
			"expired":     entry.IsExpired(),
			"fetch_count": entry.FetchCount,
			"hit_count":   entry.HitCount,
		}
	}

	return map[string]interface{}{
		"entries":       entries,
		"fetch_total":   c.fetchTotal,
		"fetch_success": c.fetchSuccess,
		"fetch_failure": c.fetchFailure,
		"cache_hits":    c.cacheHits,
		"cache_misses":  c.cacheMisses,
	}
}

// Clear clears the cache (for testing)
func (c *JWKSCache) Clear() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.cache = make(map[string]*JWKSCacheEntry)
}
