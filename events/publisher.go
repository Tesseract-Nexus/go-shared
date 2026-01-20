// Package events provides shared event types and publishing utilities for NATS messaging.
package events

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
	"github.com/sirupsen/logrus"
)

// Publisher configuration
type PublisherConfig struct {
	// NATS connection URL
	NATSURL string

	// Connection options
	Name           string        // Client name for identification
	ConnectTimeout time.Duration // Connection timeout (default: 10s)
	MaxReconnects  int           // Max reconnection attempts (default: -1, unlimited)
	ReconnectWait  time.Duration // Wait between reconnects (default: 2s)

	// JetStream options
	PublishTimeout time.Duration // Publish ack timeout (default: 5s)
	RetryAttempts  int           // Retry attempts on publish failure (default: 3)
	RetryDelay     time.Duration // Delay between retries (default: 100ms)
}

// DefaultPublisherConfig returns configuration with sensible defaults
func DefaultPublisherConfig(natsURL string) *PublisherConfig {
	return &PublisherConfig{
		NATSURL:        natsURL,
		Name:           "event-publisher",
		ConnectTimeout: 10 * time.Second,
		MaxReconnects:  -1, // Unlimited
		ReconnectWait:  2 * time.Second,
		PublishTimeout: 5 * time.Second,
		RetryAttempts:  3,
		RetryDelay:     100 * time.Millisecond,
	}
}

// Publisher provides a high-level interface for publishing events to NATS JetStream
type Publisher struct {
	nc     *nats.Conn
	js     jetstream.JetStream
	config *PublisherConfig
	logger *logrus.Entry
	mu     sync.RWMutex
}

// NewPublisher creates a new event publisher with startup retry logic
// This handles cases where the Istio sidecar isn't ready yet during pod startup
func NewPublisher(config *PublisherConfig, logger *logrus.Logger) (*Publisher, error) {
	if config == nil {
		return nil, fmt.Errorf("config is required")
	}
	if config.NATSURL == "" {
		return nil, fmt.Errorf("NATS URL is required")
	}

	log := logger
	if log == nil {
		log = logrus.StandardLogger()
	}

	p := &Publisher{
		config: config,
		logger: log.WithField("component", "events.publisher"),
	}

	// Retry connection with exponential backoff (handles Istio sidecar startup race)
	maxRetries := 5
	retryDelay := 2 * time.Second

	var lastErr error
	for i := 0; i < maxRetries; i++ {
		if err := p.connect(); err != nil {
			lastErr = err
			p.logger.WithFields(logrus.Fields{
				"attempt": i + 1,
				"max":     maxRetries,
				"delay":   retryDelay,
			}).WithError(err).Warn("Failed to connect to NATS, retrying...")
			time.Sleep(retryDelay)
			retryDelay = retryDelay * 2 // Exponential backoff
			if retryDelay > 30*time.Second {
				retryDelay = 30 * time.Second
			}
			continue
		}
		return p, nil
	}

	return nil, fmt.Errorf("failed to connect to NATS after %d attempts: %w", maxRetries, lastErr)
}

// connect establishes connection to NATS and JetStream with production-ready settings
func (p *Publisher) connect() error {
	// Ensure unlimited reconnects for production resilience
	maxReconnects := p.config.MaxReconnects
	if maxReconnects == 0 {
		maxReconnects = -1 // Default to unlimited
	}

	opts := []nats.Option{
		nats.Name(p.config.Name),
		nats.Timeout(p.config.ConnectTimeout),
		nats.RetryOnFailedConnect(true),
		nats.MaxReconnects(maxReconnects),
		nats.ReconnectWait(p.config.ReconnectWait),
		nats.ReconnectBufSize(8 * 1024 * 1024), // 8MB buffer for messages during reconnect
		nats.DisconnectErrHandler(func(nc *nats.Conn, err error) {
			if err != nil {
				p.logger.WithError(err).Warn("[NATS] Disconnected")
			}
		}),
		nats.ReconnectHandler(func(nc *nats.Conn) {
			p.logger.WithField("url", nc.ConnectedUrl()).Info("[NATS] Reconnected")
		}),
		nats.ClosedHandler(func(nc *nats.Conn) {
			p.logger.Info("[NATS] Connection closed")
		}),
		nats.ErrorHandler(func(nc *nats.Conn, sub *nats.Subscription, err error) {
			p.logger.WithError(err).Error("[NATS] Error")
		}),
	}

	nc, err := nats.Connect(p.config.NATSURL, opts...)
	if err != nil {
		return fmt.Errorf("failed to connect to NATS: %w", err)
	}

	js, err := jetstream.New(nc)
	if err != nil {
		nc.Close()
		return fmt.Errorf("failed to create JetStream context: %w", err)
	}

	p.mu.Lock()
	p.nc = nc
	p.js = js
	p.mu.Unlock()

	p.logger.WithField("url", p.config.NATSURL).Info("Connected to NATS JetStream")
	return nil
}

// PublishableEvent interface for events that can be published
type PublishableEvent interface {
	Validatable
	GetSubject() string
	GetStream() string
}

// Publish publishes an event to NATS JetStream
func (p *Publisher) Publish(ctx context.Context, event PublishableEvent) error {
	// Validate the event first
	if err := event.Validate(); err != nil {
		return fmt.Errorf("event validation failed: %w", err)
	}

	subject := event.GetSubject()
	if subject == "" {
		return fmt.Errorf("event subject is empty")
	}

	// Serialize to JSON
	data, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("failed to marshal event: %w", err)
	}

	// Publish with retries
	var lastErr error
	for attempt := 0; attempt <= p.config.RetryAttempts; attempt++ {
		if attempt > 0 {
			time.Sleep(p.config.RetryDelay * time.Duration(attempt))
			p.logger.WithFields(logrus.Fields{
				"attempt": attempt,
				"subject": subject,
			}).Debug("Retrying publish")
		}

		pubCtx, cancel := context.WithTimeout(ctx, p.config.PublishTimeout)
		ack, err := p.js.Publish(pubCtx, subject, data)
		cancel()

		if err == nil {
			p.logger.WithFields(logrus.Fields{
				"subject":  subject,
				"stream":   ack.Stream,
				"sequence": ack.Sequence,
			}).Info("Event published to JetStream")
			return nil
		}
		lastErr = err
	}

	return fmt.Errorf("failed to publish after %d attempts: %w", p.config.RetryAttempts+1, lastErr)
}

// PublishAsync publishes an event asynchronously and returns a channel for the result
func (p *Publisher) PublishAsync(ctx context.Context, event PublishableEvent) <-chan error {
	result := make(chan error, 1)
	go func() {
		result <- p.Publish(ctx, event)
		close(result)
	}()
	return result
}

// PublishBatch publishes multiple events, stopping on first error
func (p *Publisher) PublishBatch(ctx context.Context, events []PublishableEvent) error {
	for i, event := range events {
		if err := p.Publish(ctx, event); err != nil {
			return fmt.Errorf("failed to publish event %d: %w", i, err)
		}
	}
	return nil
}

// PublishOrder is a convenience method for publishing order events
func (p *Publisher) PublishOrder(ctx context.Context, event *OrderEvent) error {
	return p.Publish(ctx, event)
}

// PublishPayment is a convenience method for publishing payment events
func (p *Publisher) PublishPayment(ctx context.Context, event *PaymentEvent) error {
	return p.Publish(ctx, event)
}

// PublishCustomer is a convenience method for publishing customer events
func (p *Publisher) PublishCustomer(ctx context.Context, event *CustomerEvent) error {
	return p.Publish(ctx, event)
}

// PublishAuth is a convenience method for publishing auth events
func (p *Publisher) PublishAuth(ctx context.Context, event *AuthEvent) error {
	return p.Publish(ctx, event)
}

// PublishInventory is a convenience method for publishing inventory events
func (p *Publisher) PublishInventory(ctx context.Context, event *InventoryEvent) error {
	return p.Publish(ctx, event)
}

// PublishReturn is a convenience method for publishing return events
func (p *Publisher) PublishReturn(ctx context.Context, event *ReturnEvent) error {
	return p.Publish(ctx, event)
}

// PublishReview is a convenience method for publishing review events
func (p *Publisher) PublishReview(ctx context.Context, event *ReviewEvent) error {
	return p.Publish(ctx, event)
}

// PublishApproval is a convenience method for publishing approval events
func (p *Publisher) PublishApproval(ctx context.Context, event *ApprovalEvent) error {
	return p.Publish(ctx, event)
}

// PublishProduct is a convenience method for publishing product events
func (p *Publisher) PublishProduct(ctx context.Context, event *ProductEvent) error {
	return p.Publish(ctx, event)
}

// PublishDomain is a convenience method for publishing domain events
func (p *Publisher) PublishDomain(ctx context.Context, event *DomainEvent) error {
	return p.Publish(ctx, event)
}

// IsConnected returns true if connected to NATS
func (p *Publisher) IsConnected() bool {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.nc != nil && p.nc.IsConnected()
}

// Close closes the NATS connection
func (p *Publisher) Close() {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.nc != nil {
		p.nc.Drain()
		p.nc.Close()
		p.nc = nil
		p.js = nil
	}
	p.logger.Info("Publisher closed")
}

// EnsureStream creates a stream if it doesn't exist
func (p *Publisher) EnsureStream(ctx context.Context, streamName string, subjects []string) error {
	p.mu.RLock()
	js := p.js
	p.mu.RUnlock()

	if js == nil {
		return fmt.Errorf("not connected to JetStream")
	}

	// Check if stream exists
	_, err := js.Stream(ctx, streamName)
	if err == nil {
		p.logger.WithField("stream", streamName).Debug("Stream already exists")
		return nil
	}

	// Create the stream
	_, err = js.CreateStream(ctx, jetstream.StreamConfig{
		Name:        streamName,
		Description: fmt.Sprintf("Events for %s", streamName),
		Subjects:    subjects,
		Retention:   jetstream.LimitsPolicy,
		MaxAge:      7 * 24 * time.Hour,  // 7 days retention
		MaxBytes:    50 * 1024 * 1024,    // 50MB max per stream (fits within NATS storage limits)
		Discard:     jetstream.DiscardOld,
		Duplicates:  5 * time.Minute,
		Storage:     jetstream.FileStorage,
		Replicas:    1,
	})

	if err != nil {
		return fmt.Errorf("failed to create stream %s: %w", streamName, err)
	}

	p.logger.WithFields(logrus.Fields{
		"stream":   streamName,
		"subjects": subjects,
	}).Info("Stream created")

	return nil
}

// EnsureAllStreams creates all event streams if they don't exist
func (p *Publisher) EnsureAllStreams(ctx context.Context) error {
	streams := map[string][]string{
		StreamOrders:     {"order.>"},
		StreamPayments:   {"payment.>"},
		StreamCustomers:  {"customer.>"},
		StreamAuth:       {"auth.>"},
		StreamInventory:  {"inventory.>"},
		StreamReturns:    {"return.>"},
		StreamReviews:    {"review.>"},
		StreamCoupons:    {"coupon.>"},
		StreamVendors:    {"vendor.>"},
		StreamGiftCards:  {"gift_card.>"},
		StreamTickets:    {"ticket.>"},
		StreamStaff:      {"staff.>"},
		StreamTenants:    {"tenant.>"},
		StreamApprovals:  {"approval.>"},
		StreamCategories: {"category.>"},
		StreamShipping:   {"shipping.>"},
		StreamDomains:    {"domain.>"},
	}

	for name, subjects := range streams {
		if err := p.EnsureStream(ctx, name, subjects); err != nil {
			return err
		}
	}

	return nil
}
