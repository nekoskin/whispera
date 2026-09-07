package events

import (
	"sync"
	"sync/atomic"
	"time"
)

type Event struct {
	Type string

	Source string

	Timestamp time.Time

	Data any

	Metadata map[string]any
}

type subscription struct {
	id      int64
	ch      chan Event
	handler EventHandler
}

type eventBus struct {
	mu          sync.RWMutex
	subscribers map[string][]subscription
	allSubs     []subscription
	bufferSize  int
	closed      bool
	wg          sync.WaitGroup
	subIDSeq    atomic.Int64
}

type EventBusError struct {
	Message string
}

var (
	ErrEventBusClosed = &EventBusError{Message: "event bus is closed"}
)

const (
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
)

type EventHandler func(event Event)

type EventBus interface {
	Publish(event Event) error

	PublishAsync(event Event)

	Subscribe(eventType string) <-chan Event

	SubscribeFunc(eventType string, handler EventHandler) (unsubscribe func())

	SubscribeAll() <-chan Event

	Unsubscribe(eventType string, ch <-chan Event)

	Close()
}

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

func (eb *eventBus) Publish(event Event) error {
	eb.mu.RLock()
	defer eb.mu.RUnlock()

	if eb.closed {
		return ErrEventBusClosed
	}

	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now()
	}

	if subs, ok := eb.subscribers[event.Type]; ok {
		for _, sub := range subs {
			if sub.handler != nil {
				sub.handler(event)
				continue
			}
			select {
			case sub.ch <- event:
			default:
			}
		}
	}

	for _, sub := range eb.allSubs {
		if sub.handler != nil {
			sub.handler(event)
			continue
		}
		select {
		case sub.ch <- event:
		default:
		}
	}

	return nil
}

func (eb *eventBus) PublishAsync(event Event) {
	eb.wg.Add(1)
	go func() {
		defer eb.wg.Done()
		_ = eb.Publish(event)
	}()
}

func (eb *eventBus) Subscribe(eventType string) <-chan Event {
	eb.mu.Lock()
	defer eb.mu.Unlock()

	ch := make(chan Event, eb.bufferSize)
	sub := subscription{ch: ch}
	eb.subscribers[eventType] = append(eb.subscribers[eventType], sub)
	return ch
}

func (eb *eventBus) SubscribeFunc(eventType string, handler EventHandler) func() {
	eb.mu.Lock()
	defer eb.mu.Unlock()

	id := eb.subIDSeq.Add(1)
	sub := subscription{id: id, handler: handler}
	eb.subscribers[eventType] = append(eb.subscribers[eventType], sub)

	return func() {
		eb.mu.Lock()
		defer eb.mu.Unlock()

		subs := eb.subscribers[eventType]
		for i, s := range subs {
			if s.id == id {
				eb.subscribers[eventType] = append(subs[:i], subs[i+1:]...)
				break
			}
		}
	}
}

func (eb *eventBus) SubscribeAll() <-chan Event {
	eb.mu.Lock()
	defer eb.mu.Unlock()

	ch := make(chan Event, eb.bufferSize)
	sub := subscription{ch: ch}
	eb.allSubs = append(eb.allSubs, sub)
	return ch
}

func (eb *eventBus) Unsubscribe(eventType string, ch <-chan Event) {
	eb.mu.Lock()
	defer eb.mu.Unlock()

	subs := eb.subscribers[eventType]
	for i, sub := range subs {
		if sub.ch == ch {
			eb.subscribers[eventType] = append(subs[:i], subs[i+1:]...)
			close(sub.ch)
			return
		}
	}

	for i, sub := range eb.allSubs {
		if sub.ch == ch {
			eb.allSubs = append(eb.allSubs[:i], eb.allSubs[i+1:]...)
			close(sub.ch)
			return
		}
	}
}

func (eb *eventBus) Close() {
	eb.mu.Lock()
	if eb.closed {
		eb.mu.Unlock()
		return
	}
	eb.closed = true
	eb.mu.Unlock()

	eb.wg.Wait()

	eb.mu.Lock()
	defer eb.mu.Unlock()

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

func (e *EventBusError) Error() string {
	return e.Message
}

func NewEvent(eventType, source string, data any) Event {
	return Event{
		Type:      eventType,
		Source:    source,
		Timestamp: time.Now(),
		Data:      data,
		Metadata:  make(map[string]any),
	}
}

func (e Event) WithMetadata(key string, value any) Event {
	if e.Metadata == nil {
		e.Metadata = make(map[string]any)
	}
	e.Metadata[key] = value
	return e
}
