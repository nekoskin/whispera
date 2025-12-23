package xhttp

import (
	"fmt"
	"sync"
	"time"
)

// ErrorType represents type of XHTTP error
type ErrorType int

const (
	ErrorTypeUnknown ErrorType = iota
	ErrorTypeSessionNotFound
	ErrorTypeBufferFull
	ErrorTypePacketTooLarge
	ErrorTypeTimeout
	ErrorTypeConnectionClosed
	ErrorTypeInvalidFrame
	ErrorTypeStreamClosed
	ErrorTypeFlowControl
	ErrorTypeObfuscation
	ErrorTypeInternalServer
)

// XHTTPError represents an XHTTP protocol error
type XHTTPError struct {
	Type      ErrorType
	Message   string
	Timestamp time.Time
	Retryable bool

	// For nested errors
	Cause error
}

// Error implements error interface
func (e *XHTTPError) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("XHTTP error (%v): %s (caused by: %v)", e.Type, e.Message, e.Cause)
	}
	return fmt.Sprintf("XHTTP error (%v): %s", e.Type, e.Message)
}

// Unwrap returns wrapped error for error chains
func (e *XHTTPError) Unwrap() error {
	return e.Cause
}

// IsRetryable returns whether error is retryable
func (e *XHTTPError) IsRetryable() bool {
	return e.Retryable
}

// NewXHTTPError creates new XHTTP error
func NewXHTTPError(errorType ErrorType, message string, retryable bool) *XHTTPError {
	return &XHTTPError{
		Type:      errorType,
		Message:   message,
		Timestamp: time.Now(),
		Retryable: retryable,
	}
}

// NewXHTTPErrorWithCause creates XHTTP error with wrapped cause
func NewXHTTPErrorWithCause(errorType ErrorType, message string, retryable bool, cause error) *XHTTPError {
	err := NewXHTTPError(errorType, message, retryable)
	err.Cause = cause
	return err
}

// RetryPolicy defines retry behavior for failed operations
type RetryPolicy struct {
	MaxRetries        int
	InitialBackoff    time.Duration
	MaxBackoff        time.Duration
	BackoffMultiplier float64
}

// DefaultRetryPolicy returns default retry policy
func DefaultRetryPolicy() *RetryPolicy {
	return &RetryPolicy{
		MaxRetries:        3,
		InitialBackoff:    100 * time.Millisecond,
		MaxBackoff:        5 * time.Second,
		BackoffMultiplier: 2.0,
	}
}

// RetryConfig contains retry configuration
type RetryConfig struct {
	Policy  *RetryPolicy
	OnRetry func(attempt int, err error)
}

// Retry executes function with retry logic
func (rc *RetryConfig) Retry(fn func() error) error {
	if rc.Policy == nil {
		rc.Policy = DefaultRetryPolicy()
	}

	backoff := rc.Policy.InitialBackoff

	for attempt := 0; attempt <= rc.Policy.MaxRetries; attempt++ {
		err := fn()
		if err == nil {
			return nil
		}

		// Check if error is retryable
		xhttpErr, ok := err.(*XHTTPError)
		if ok && !xhttpErr.IsRetryable() {
			return err
		}

		if attempt < rc.Policy.MaxRetries {
			if rc.OnRetry != nil {
				rc.OnRetry(attempt+1, err)
			}

			// Sleep before retry
			time.Sleep(backoff)

			// Update backoff for next attempt
			backoff = time.Duration(float64(backoff) * rc.Policy.BackoffMultiplier)
			if backoff > rc.Policy.MaxBackoff {
				backoff = rc.Policy.MaxBackoff
			}
		}
	}

	return NewXHTTPError(ErrorTypeInternalServer,
		fmt.Sprintf("operation failed after %d retries", rc.Policy.MaxRetries),
		false)
}

// ErrorHandler handles XHTTP errors with recovery strategies
type ErrorHandler struct {
	policy     *RetryPolicy
	errorLog   []ErrorRecord
	errorLogMu sync.RWMutex
	maxLogSize int
}

// ErrorRecord represents logged error
type ErrorRecord struct {
	Timestamp time.Time
	Error     *XHTTPError
	Context   map[string]interface{}
}

// NewErrorHandler creates new error handler
func NewErrorHandler() *ErrorHandler {
	return &ErrorHandler{
		policy:     DefaultRetryPolicy(),
		errorLog:   make([]ErrorRecord, 0, 100),
		maxLogSize: 100,
	}
}

// Handle handles error with retry logic
func (eh *ErrorHandler) Handle(err error, fn func() error) error {
	if err == nil {
		return nil
	}

	rc := &RetryConfig{
		Policy: eh.policy,
		OnRetry: func(attempt int, retryErr error) {
			eh.logError(retryErr, map[string]interface{}{
				"attempt": attempt,
			})
		},
	}

	return rc.Retry(fn)
}

// logError logs error to internal buffer
func (eh *ErrorHandler) logError(err error, context map[string]interface{}) {
	eh.errorLogMu.Lock()
	defer eh.errorLogMu.Unlock()

	xhttpErr, ok := err.(*XHTTPError)
	if !ok {
		xhttpErr = NewXHTTPErrorWithCause(ErrorTypeUnknown, err.Error(), true, err)
	}

	record := ErrorRecord{
		Timestamp: time.Now(),
		Error:     xhttpErr,
		Context:   context,
	}

	eh.errorLog = append(eh.errorLog, record)

	// Keep log size bounded
	if len(eh.errorLog) > eh.maxLogSize {
		eh.errorLog = eh.errorLog[1:]
	}
}

// GetErrorLog returns recent errors
func (eh *ErrorHandler) GetErrorLog(limit int) []ErrorRecord {
	eh.errorLogMu.RLock()
	defer eh.errorLogMu.RUnlock()

	if limit == 0 || limit > len(eh.errorLog) {
		limit = len(eh.errorLog)
	}

	result := make([]ErrorRecord, limit)
	copy(result, eh.errorLog[len(eh.errorLog)-limit:])
	return result
}

// ClearErrorLog clears error log
func (eh *ErrorHandler) ClearErrorLog() {
	eh.errorLogMu.Lock()
	defer eh.errorLogMu.Unlock()
	eh.errorLog = make([]ErrorRecord, 0, 100)
}

// GetErrorStats returns error statistics
func (eh *ErrorHandler) GetErrorStats() map[string]interface{} {
	eh.errorLogMu.RLock()
	defer eh.errorLogMu.RUnlock()

	stats := make(map[string]int)
	for _, record := range eh.errorLog {
		typeName := fmt.Sprintf("error_type_%d", record.Error.Type)
		stats[typeName]++
	}

	return map[string]interface{}{
		"total_errors": len(eh.errorLog),
		"by_type":      stats,
	}
}

// RecordError records an error without retry logic
func (eh *ErrorHandler) RecordError(err *XHTTPError) {
	eh.logError(err, nil)
}

// ConnState represents connection state
type ConnState int

const (
	ConnStateOpen ConnState = iota
	ConnStateData
	ConnStateClosed
	ConnStateReset
)
