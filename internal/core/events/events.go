// Package events provides an event bus for inter-module communication
package events

import (
	"context"
	"sync"
	"time"
)

// Event represents a system event
type Event struct {
	// Type is the event type identifier
	Type string

	// Source is the name of the module that emitted the event
	Source string

	// Timestamp is when the event occurred
	Timestamp time.Time

	// Data contains event-specific payload
	Data interface{}

	// Metadata contains additional key-value pairs
	Metadata map[string]interface{}
}

// EventHandler is a function that handles events
type EventHandler func(event Event)

// EventBus provides publish/subscribe functionality for events
type EventBus interface {
	// Publish publishes an event to all subscribers
	Publish(event Event) error

	// PublishAsync publishes an event asynchronously
	PublishAsync(event Event)

	// Subscribe subscribes to events of a given type
	Subscribe(eventType string) <-chan Event

	// SubscribeFunc subscribes a handler function to events
	SubscribeFunc(eventType string, handler EventHandler) (unsubscribe func())

	// SubscribeAll subscribes to all events
	SubscribeAll() <-chan Event

	// Unsubscribe removes a subscription channel
	Unsubscribe(eventType string, ch <-chan Event)

	// Close closes the event bus
	Close()
}

// subscription represents a single subscription
type subscription struct {
	ch      chan Event
	handler EventHandler
}

// eventBus is the default implementation of EventBus
type eventBus struct {
	mu          sync.RWMutex
	subscribers map[string][]subscription
	allSubs     []subscription
	bufferSize  int
	closed      bool
	wg          sync.WaitGroup
}

// NewEventBus creates a new event bus with the given buffer size
func NewEventBus(bufferSize int) EventBus {
	if bufferSize < 1 {
		bufferSize = 100
	}
	return &eventBus{
		subscribers: make(map[string][]subscription),
		allSubs:     make([]subscription, 0),
		bufferSize:  bufferSize,
	}
}

// Publish publishes an event synchronously
func (eb *eventBus) Publish(event Event) error {
	eb.mu.RLock()
	defer eb.mu.RUnlock()

	if eb.closed {
		return ErrEventBusClosed
	}

	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now()
	}

	// Send to type-specific subscribers
	if subs, ok := eb.subscribers[event.Type]; ok {
		for _, sub := range subs {
			if sub.handler != nil {
				sub.handler(event)
			} else {
				select {
				case sub.ch <- event:
				default:
					// Channel full, skip
				}
			}
		}
	}

	// Send to all-event subscribers
	for _, sub := range eb.allSubs {
		if sub.handler != nil {
			sub.handler(event)
		} else {
			select {
			case sub.ch <- event:
			default:
				// Channel full, skip
			}
		}
	}

	return nil
}

// PublishAsync publishes an event asynchronously
func (eb *eventBus) PublishAsync(event Event) {
	eb.wg.Add(1)
	go func() {
		defer eb.wg.Done()
		_ = eb.Publish(event)
	}()
}

// Subscribe creates a subscription for a specific event type
func (eb *eventBus) Subscribe(eventType string) <-chan Event {
	eb.mu.Lock()
	defer eb.mu.Unlock()

	ch := make(chan Event, eb.bufferSize)
	sub := subscription{ch: ch}
	eb.subscribers[eventType] = append(eb.subscribers[eventType], sub)
	return ch
}

// SubscribeFunc subscribes a handler function to events
func (eb *eventBus) SubscribeFunc(eventType string, handler EventHandler) func() {
	eb.mu.Lock()
	defer eb.mu.Unlock()

	sub := subscription{handler: handler}
	eb.subscribers[eventType] = append(eb.subscribers[eventType], sub)

	// Return unsubscribe function
	return func() {
		eb.mu.Lock()
		defer eb.mu.Unlock()

		subs := eb.subscribers[eventType]
		for i, s := range subs {
			if s.handler != nil && &s.handler == &handler {
				eb.subscribers[eventType] = append(subs[:i], subs[i+1:]...)
				break
			}
		}
	}
}

// SubscribeAll subscribes to all events
func (eb *eventBus) SubscribeAll() <-chan Event {
	eb.mu.Lock()
	defer eb.mu.Unlock()

	ch := make(chan Event, eb.bufferSize)
	sub := subscription{ch: ch}
	eb.allSubs = append(eb.allSubs, sub)
	return ch
}

// Unsubscribe removes a subscription channel
func (eb *eventBus) Unsubscribe(eventType string, ch <-chan Event) {
	eb.mu.Lock()
	defer eb.mu.Unlock()

	subs := eb.subscribers[eventType]
	for i, sub := range subs {
		if sub.ch == ch {
			close(sub.ch)
			eb.subscribers[eventType] = append(subs[:i], subs[i+1:]...)
			return
		}
	}

	// Check all-event subscribers
	for i, sub := range eb.allSubs {
		if sub.ch == ch {
			close(sub.ch)
			eb.allSubs = append(eb.allSubs[:i], eb.allSubs[i+1:]...)
			return
		}
	}
}

// Close closes the event bus and all subscription channels
func (eb *eventBus) Close() {
	eb.mu.Lock()
	defer eb.mu.Unlock()

	if eb.closed {
		return
	}
	eb.closed = true

	// Wait for async publishes to complete
	eb.wg.Wait()

	// Close all channels
	for _, subs := range eb.subscribers {
		for _, sub := range subs {
			if sub.ch != nil {
				close(sub.ch)
			}
		}
	}
	for _, sub := range eb.allSubs {
		if sub.ch != nil {
			close(sub.ch)
		}
	}
}

// Standard event types
const (
	EventTypeSessionCreated = "session.created"
	EventTypeSessionUpdated = "session.updated"
	EventTypeSessionRemoved = "session.removed"
	EventTypeSessionExpired = "session.expired"
	EventTypeSessionRekeyed = "session.rekeyed"

	EventTypePacketReceived = "packet.received"
	EventTypePacketSent     = "packet.sent"
	EventTypePacketDropped  = "packet.dropped"

	EventTypeHandshakeStarted   = "handshake.started"
	EventTypeHandshakeCompleted = "handshake.completed"
	EventTypeHandshakeFailed    = "handshake.failed"

	EventTypeConfigReloaded = "config.reloaded"
	EventTypeModuleStarted  = "module.started"
	EventTypeModuleStopped  = "module.stopped"
	EventTypeModuleError    = "module.error"

	EventTypeHealthChanged = "health.changed"
)

// Error types
var (
	ErrEventBusClosed = &EventBusError{Message: "event bus is closed"}
)

// EventBusError represents an event bus error
type EventBusError struct {
	Message string
}

func (e *EventBusError) Error() string {
	return e.Message
}

// NewEvent creates a new event with default timestamp
func NewEvent(eventType, source string, data interface{}) Event {
	return Event{
		Type:      eventType,
		Source:    source,
		Timestamp: time.Now(),
		Data:      data,
		Metadata:  make(map[string]interface{}),
	}
}

// WithMetadata adds metadata to an event
func (e Event) WithMetadata(key string, value interface{}) Event {
	if e.Metadata == nil {
		e.Metadata = make(map[string]interface{})
	}
	e.Metadata[key] = value
	return e
}

// TopicMatcher provides pattern matching for event topics
type TopicMatcher struct {
	pattern string
}

// NewTopicMatcher creates a new topic matcher
func NewTopicMatcher(pattern string) *TopicMatcher {
	return &TopicMatcher{pattern: pattern}
}

// Matches checks if an event type matches the pattern
func (tm *TopicMatcher) Matches(eventType string) bool {
	if tm.pattern == "*" {
		return true
	}
	if tm.pattern == eventType {
		return true
	}
	// Support prefix matching with wildcard (e.g., "session.*")
	if len(tm.pattern) > 0 && tm.pattern[len(tm.pattern)-1] == '*' {
		prefix := tm.pattern[:len(tm.pattern)-1]
		return len(eventType) >= len(prefix) && eventType[:len(prefix)] == prefix
	}
	return false
}

// EventAggregator aggregates events over a time window
type EventAggregator struct {
	mu       sync.Mutex
	events   []Event
	window   time.Duration
	callback func(events []Event)
	timer    *time.Timer
}

// NewEventAggregator creates a new event aggregator
func NewEventAggregator(window time.Duration, callback func(events []Event)) *EventAggregator {
	return &EventAggregator{
		events:   make([]Event, 0),
		window:   window,
		callback: callback,
	}
}

// Add adds an event to the aggregator
func (ea *EventAggregator) Add(event Event) {
	ea.mu.Lock()
	defer ea.mu.Unlock()

	ea.events = append(ea.events, event)

	// Start timer on first event
	if ea.timer == nil {
		ea.timer = time.AfterFunc(ea.window, ea.flush)
	}
}

// flush sends aggregated events to callback
func (ea *EventAggregator) flush() {
	ea.mu.Lock()
	events := ea.events
	ea.events = make([]Event, 0)
	ea.timer = nil
	ea.mu.Unlock()

	if len(events) > 0 && ea.callback != nil {
		ea.callback(events)
	}
}

// Flush immediately flushes all events
func (ea *EventAggregator) Flush() {
	ea.mu.Lock()
	if ea.timer != nil {
		ea.timer.Stop()
	}
	ea.mu.Unlock()
	ea.flush()
}

// EventFilter provides event filtering
type EventFilter struct {
	types   map[string]bool
	sources map[string]bool
}

// NewEventFilter creates a new event filter
func NewEventFilter() *EventFilter {
	return &EventFilter{
		types:   make(map[string]bool),
		sources: make(map[string]bool),
	}
}

// AllowType allows events of a specific type
func (ef *EventFilter) AllowType(eventType string) *EventFilter {
	ef.types[eventType] = true
	return ef
}

// AllowSource allows events from a specific source
func (ef *EventFilter) AllowSource(source string) *EventFilter {
	ef.sources[source] = true
	return ef
}

// Matches checks if an event passes the filter
func (ef *EventFilter) Matches(event Event) bool {
	if len(ef.types) > 0 && !ef.types[event.Type] {
		return false
	}
	if len(ef.sources) > 0 && !ef.sources[event.Source] {
		return false
	}
	return true
}

// FilteredSubscriber wraps a channel with event filtering
type FilteredSubscriber struct {
	input  <-chan Event
	output chan Event
	filter *EventFilter
	ctx    context.Context
	cancel context.CancelFunc
}

// NewFilteredSubscriber creates a filtered subscriber
func NewFilteredSubscriber(input <-chan Event, filter *EventFilter, bufferSize int) *FilteredSubscriber {
	ctx, cancel := context.WithCancel(context.Background())
	fs := &FilteredSubscriber{
		input:  input,
		output: make(chan Event, bufferSize),
		filter: filter,
		ctx:    ctx,
		cancel: cancel,
	}
	go fs.run()
	return fs
}

// Channel returns the filtered output channel
func (fs *FilteredSubscriber) Channel() <-chan Event {
	return fs.output
}

// Close stops the filtered subscriber
func (fs *FilteredSubscriber) Close() {
	fs.cancel()
}

func (fs *FilteredSubscriber) run() {
	defer close(fs.output)
	for {
		select {
		case <-fs.ctx.Done():
			return
		case event, ok := <-fs.input:
			if !ok {
				return
			}
			if fs.filter.Matches(event) {
				select {
				case fs.output <- event:
				case <-fs.ctx.Done():
					return
				}
			}
		}
	}
}
