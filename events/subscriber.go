// Package events provides shared event types and subscription utilities for NATS messaging.
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

// SubscriberConfig holds subscriber configuration
type SubscriberConfig struct {
	// NATS connection URL
	NATSURL string

	// Connection options
	Name           string        // Client name for identification
	ConnectTimeout time.Duration // Connection timeout (default: 10s)
	MaxReconnects  int           // Max reconnection attempts (default: -1, unlimited)
	ReconnectWait  time.Duration // Wait between reconnects (default: 2s)

	// Consumer options
	ConsumerName   string        // Durable consumer name
	AckWait        time.Duration // Time to wait for acknowledgment (default: 30s)
	MaxDeliver     int           // Max delivery attempts (default: 5)
	DeliverPolicy  string        // "all", "last", "new", "by_start_time" (default: "new")
	FilterSubjects []string      // Subjects to filter on
}

// DefaultSubscriberConfig returns configuration with sensible defaults
func DefaultSubscriberConfig(natsURL, consumerName string) *SubscriberConfig {
	return &SubscriberConfig{
		NATSURL:        natsURL,
		Name:           "event-subscriber",
		ConnectTimeout: 10 * time.Second,
		MaxReconnects:  -1, // Unlimited
		ReconnectWait:  2 * time.Second,
		ConsumerName:   consumerName,
		AckWait:        30 * time.Second,
		MaxDeliver:     5,
		DeliverPolicy:  "new",
	}
}

// Subscriber provides a high-level interface for subscribing to NATS JetStream events
type Subscriber struct {
	nc          *nats.Conn
	js          jetstream.JetStream
	config      *SubscriberConfig
	logger      *logrus.Entry
	mu          sync.RWMutex
	consumers   map[string]jetstream.Consumer
	stopChan    chan struct{}
	doneChan    chan struct{}
}

// NewSubscriber creates a new event subscriber with startup retry logic
func NewSubscriber(config *SubscriberConfig, logger *logrus.Logger) (*Subscriber, error) {
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

	s := &Subscriber{
		config:    config,
		logger:    log.WithField("component", "events.subscriber"),
		consumers: make(map[string]jetstream.Consumer),
		stopChan:  make(chan struct{}),
		doneChan:  make(chan struct{}),
	}

	// Retry connection with exponential backoff
	maxRetries := 5
	retryDelay := 2 * time.Second

	var lastErr error
	for i := 0; i < maxRetries; i++ {
		if err := s.connect(); err != nil {
			lastErr = err
			s.logger.WithFields(logrus.Fields{
				"attempt": i + 1,
				"max":     maxRetries,
				"delay":   retryDelay,
			}).WithError(err).Warn("Failed to connect to NATS, retrying...")
			time.Sleep(retryDelay)
			retryDelay = retryDelay * 2
			if retryDelay > 30*time.Second {
				retryDelay = 30 * time.Second
			}
			continue
		}
		return s, nil
	}

	return nil, fmt.Errorf("failed to connect to NATS after %d attempts: %w", maxRetries, lastErr)
}

// connect establishes connection to NATS and JetStream with production-ready settings
func (s *Subscriber) connect() error {
	// Ensure unlimited reconnects for production resilience
	maxReconnects := s.config.MaxReconnects
	if maxReconnects == 0 {
		maxReconnects = -1 // Default to unlimited
	}

	opts := []nats.Option{
		nats.Name(s.config.Name),
		nats.Timeout(s.config.ConnectTimeout),
		nats.RetryOnFailedConnect(true),
		nats.MaxReconnects(maxReconnects),
		nats.ReconnectWait(s.config.ReconnectWait),
		nats.ReconnectBufSize(8 * 1024 * 1024), // 8MB buffer for messages during reconnect
		nats.DisconnectErrHandler(func(nc *nats.Conn, err error) {
			if err != nil {
				s.logger.WithError(err).Warn("[NATS] Disconnected")
			}
		}),
		nats.ReconnectHandler(func(nc *nats.Conn) {
			s.logger.WithField("url", nc.ConnectedUrl()).Info("[NATS] Reconnected")
		}),
		nats.ClosedHandler(func(nc *nats.Conn) {
			s.logger.Info("[NATS] Connection closed")
		}),
		nats.ErrorHandler(func(nc *nats.Conn, sub *nats.Subscription, err error) {
			s.logger.WithError(err).Error("[NATS] Error")
		}),
	}

	nc, err := nats.Connect(s.config.NATSURL, opts...)
	if err != nil {
		return fmt.Errorf("failed to connect to NATS: %w", err)
	}

	js, err := jetstream.New(nc)
	if err != nil {
		nc.Close()
		return fmt.Errorf("failed to create JetStream context: %w", err)
	}

	s.mu.Lock()
	s.nc = nc
	s.js = js
	s.mu.Unlock()

	s.logger.WithField("url", s.config.NATSURL).Info("Connected to NATS JetStream")
	return nil
}

// MessageHandler is a function type for handling messages
type MessageHandler func(ctx context.Context, msg *Message) error

// Message represents a received message
type Message struct {
	Subject   string
	Data      []byte
	Headers   map[string][]string
	Timestamp time.Time
	Sequence  uint64
	msg       jetstream.Msg
}

// Ack acknowledges the message
func (m *Message) Ack() error {
	return m.msg.Ack()
}

// Nak negatively acknowledges the message (will be redelivered)
func (m *Message) Nak() error {
	return m.msg.Nak()
}

// NakWithDelay negatively acknowledges with a delay before redelivery
func (m *Message) NakWithDelay(delay time.Duration) error {
	return m.msg.NakWithDelay(delay)
}

// Term terminates the message (will not be redelivered)
func (m *Message) Term() error {
	return m.msg.Term()
}

// Subscribe creates a durable consumer and starts consuming messages
func (s *Subscriber) Subscribe(ctx context.Context, streamName string, subjects []string, handler MessageHandler) error {
	s.mu.RLock()
	js := s.js
	s.mu.RUnlock()

	if js == nil {
		return fmt.Errorf("not connected to JetStream")
	}

	// Build consumer config
	consumerConfig := jetstream.ConsumerConfig{
		Name:          s.config.ConsumerName,
		Durable:       s.config.ConsumerName,
		AckWait:       s.config.AckWait,
		MaxDeliver:    s.config.MaxDeliver,
		FilterSubjects: subjects,
	}

	// Set delivery policy
	switch s.config.DeliverPolicy {
	case "all":
		consumerConfig.DeliverPolicy = jetstream.DeliverAllPolicy
	case "last":
		consumerConfig.DeliverPolicy = jetstream.DeliverLastPolicy
	case "new":
		consumerConfig.DeliverPolicy = jetstream.DeliverNewPolicy
	default:
		consumerConfig.DeliverPolicy = jetstream.DeliverNewPolicy
	}

	// Get or create the stream
	stream, err := js.Stream(ctx, streamName)
	if err != nil {
		return fmt.Errorf("failed to get stream %s: %w", streamName, err)
	}

	// Create or update consumer
	consumer, err := stream.CreateOrUpdateConsumer(ctx, consumerConfig)
	if err != nil {
		return fmt.Errorf("failed to create consumer: %w", err)
	}

	s.mu.Lock()
	s.consumers[streamName] = consumer
	s.mu.Unlock()

	s.logger.WithFields(logrus.Fields{
		"stream":   streamName,
		"consumer": s.config.ConsumerName,
		"subjects": subjects,
	}).Info("Consumer created, starting message consumption")

	// Start consuming messages
	go s.consume(ctx, consumer, handler)

	return nil
}

// consume handles message consumption loop
func (s *Subscriber) consume(ctx context.Context, consumer jetstream.Consumer, handler MessageHandler) {
	for {
		select {
		case <-ctx.Done():
			s.logger.Info("Context cancelled, stopping consumer")
			return
		case <-s.stopChan:
			s.logger.Info("Stop signal received, stopping consumer")
			close(s.doneChan)
			return
		default:
			// Fetch messages in batches
			msgs, err := consumer.Fetch(10, jetstream.FetchMaxWait(5*time.Second))
			if err != nil {
				if err != context.DeadlineExceeded && err != nats.ErrTimeout {
					s.logger.WithError(err).Error("Failed to fetch messages")
				}
				continue
			}

			for msg := range msgs.Messages() {
				m := &Message{
					Subject:   msg.Subject(),
					Data:      msg.Data(),
					Headers:   make(map[string][]string),
					Timestamp: time.Now(),
					msg:       msg,
				}

				// Get metadata for sequence
				meta, err := msg.Metadata()
				if err == nil {
					m.Sequence = meta.Sequence.Stream
					m.Timestamp = meta.Timestamp
				}

				// Copy headers
				if msg.Headers() != nil {
					for k, v := range msg.Headers() {
						m.Headers[k] = v
					}
				}

				// Process message
				if err := handler(ctx, m); err != nil {
					s.logger.WithFields(logrus.Fields{
						"subject":  m.Subject,
						"sequence": m.Sequence,
					}).WithError(err).Error("Handler returned error, message will be redelivered")
					m.Nak()
				} else {
					m.Ack()
				}
			}
		}
	}
}

// SubscribeApprovalEvents is a convenience method for subscribing to approval events
func (s *Subscriber) SubscribeApprovalEvents(ctx context.Context, subjects []string, handler func(ctx context.Context, event *ApprovalEvent) error) error {
	msgHandler := func(ctx context.Context, msg *Message) error {
		var event ApprovalEvent
		if err := json.Unmarshal(msg.Data, &event); err != nil {
			s.logger.WithError(err).Error("Failed to unmarshal approval event")
			return nil // Don't redeliver malformed messages
		}
		return handler(ctx, &event)
	}

	return s.Subscribe(ctx, StreamApprovals, subjects, msgHandler)
}

// IsConnected returns true if connected to NATS
func (s *Subscriber) IsConnected() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.nc != nil && s.nc.IsConnected()
}

// Close closes the NATS connection and stops all consumers
func (s *Subscriber) Close() {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Signal consumers to stop
	close(s.stopChan)

	// Wait for consumers to stop (with timeout)
	select {
	case <-s.doneChan:
	case <-time.After(5 * time.Second):
		s.logger.Warn("Timeout waiting for consumers to stop")
	}

	if s.nc != nil {
		s.nc.Drain()
		s.nc.Close()
		s.nc = nil
		s.js = nil
	}
	s.logger.Info("Subscriber closed")
}
