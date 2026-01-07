// Package registry provides dependency injection and module management
package registry

import (
	"context"
	"fmt"
	"log"
	"sort"
	"sync"
	"time"

	"whispera/internal/core/events"
	"whispera/internal/core/interfaces"
)

// Registry manages module registration, lifecycle, and dependency injection
type Registry interface {
	// Register registers a module
	Register(module interfaces.Module) error

	// Get gets a module by name
	Get(name string) (interfaces.Module, bool)

	// GetTyped gets a module and casts it to the expected type
	GetTyped(name string, target interface{}) error

	// GetAll returns all registered modules
	GetAll() []interfaces.Module

	// StartAll starts all modules in dependency order
	StartAll(ctx context.Context) error

	// StopAll stops all modules in reverse dependency order
	StopAll(ctx context.Context) error

	// Reload reloads configuration for all modules
	Reload(ctx context.Context, cfg interface{}) error

	// HealthCheck returns health status of all modules
	HealthCheck() map[string]interfaces.HealthStatus

	// SetEventBus sets the event bus for the registry
	SetEventBus(bus events.EventBus)

	// Events returns the event bus
	Events() events.EventBus
}

// ModuleState represents the current state of a module
type ModuleState int

const (
	ModuleStateUninitialized ModuleState = iota
	ModuleStateInitialized
	ModuleStateStarting
	ModuleStateRunning
	ModuleStateStopping
	ModuleStateStopped
	ModuleStateError
)

func (s ModuleState) String() string {
	switch s {
	case ModuleStateUninitialized:
		return "uninitialized"
	case ModuleStateInitialized:
		return "initialized"
	case ModuleStateStarting:
		return "starting"
	case ModuleStateRunning:
		return "running"
	case ModuleStateStopping:
		return "stopping"
	case ModuleStateStopped:
		return "stopped"
	case ModuleStateError:
		return "error"
	default:
		return "unknown"
	}
}

// moduleEntry holds module and its state
type moduleEntry struct {
	module interfaces.Module
	state  ModuleState
	err    error
}

// registry is the default implementation of Registry
type registry struct {
	mu       sync.RWMutex
	modules  map[string]*moduleEntry
	order    []string // Topologically sorted start order
	eventBus events.EventBus
}

// NewRegistry creates a new module registry
func NewRegistry() Registry {
	return &registry{
		modules:  make(map[string]*moduleEntry),
		order:    make([]string, 0),
		eventBus: events.NewEventBus(100),
	}
}

// Register registers a module with the registry
func (r *registry) Register(module interfaces.Module) error {
	if module == nil {
		return fmt.Errorf("cannot register nil module")
	}

	name := module.Name()
	if name == "" {
		return fmt.Errorf("module name cannot be empty")
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	if _, exists := r.modules[name]; exists {
		return fmt.Errorf("module %q already registered", name)
	}

	r.modules[name] = &moduleEntry{
		module: module,
		state:  ModuleStateUninitialized,
	}

	log.Printf("[Registry] Registered module: %s (v%s)", name, module.Version())
	return nil
}

// Get retrieves a module by name
func (r *registry) Get(name string) (interfaces.Module, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	entry, exists := r.modules[name]
	if !exists {
		return nil, false
	}
	return entry.module, true
}

// GetTyped gets a module and assigns it to the target pointer
func (r *registry) GetTyped(name string, target interface{}) error {
	module, exists := r.Get(name)
	if !exists {
		return fmt.Errorf("module %q not found", name)
	}

	// Use type assertion at the call site
	// This is a simplified version; a more robust implementation
	// would use reflection
	switch t := target.(type) {
	case *interfaces.Transport:
		if m, ok := module.(interfaces.Transport); ok {
			*t = m
			return nil
		}
	case *interfaces.SessionManager:
		if m, ok := module.(interfaces.SessionManager); ok {
			*t = m
			return nil
		}
	case *interfaces.Router:
		if m, ok := module.(interfaces.Router); ok {
			*t = m
			return nil
		}
	case *interfaces.Obfuscator:
		if m, ok := module.(interfaces.Obfuscator); ok {
			*t = m
			return nil
		}
	}

	return fmt.Errorf("module %q is not of the expected type", name)
}

// GetAll returns all registered modules
func (r *registry) GetAll() []interfaces.Module {
	r.mu.RLock()
	defer r.mu.RUnlock()

	modules := make([]interfaces.Module, 0, len(r.modules))
	for _, entry := range r.modules {
		modules = append(modules, entry.module)
	}
	return modules
}

// StartAll starts all modules in dependency order
func (r *registry) StartAll(ctx context.Context) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	// Compute start order based on dependencies
	order, err := r.computeStartOrder()
	if err != nil {
		return fmt.Errorf("failed to compute start order: %w", err)
	}
	r.order = order

	log.Printf("[Registry] Starting %d modules in order: %v", len(order), order)

	// Start modules in order
	for _, name := range order {
		entry := r.modules[name]
		if entry.state == ModuleStateRunning {
			continue
		}

		log.Printf("[Registry] Starting module: %s", name)

		if entry.state == ModuleStateUninitialized {
			if err := entry.module.Init(ctx, nil); err != nil {
				return fmt.Errorf("failed to init module %q: %w", name, err)
			}
			entry.state = ModuleStateInitialized
		}

		entry.state = ModuleStateStarting

		if err := entry.module.Start(); err != nil {
			entry.state = ModuleStateError
			entry.err = err
			r.publishEvent(events.EventTypeModuleError, name, map[string]interface{}{
				"error": err.Error(),
			})
			return fmt.Errorf("failed to start module %q: %w", name, err)
		}

		entry.state = ModuleStateRunning
		r.publishEvent(events.EventTypeModuleStarted, name, nil)
		log.Printf("[Registry] Module started: %s", name)
	}

	log.Printf("[Registry] All %d modules started successfully", len(order))
	return nil
}

// StopAll stops all modules in reverse dependency order
func (r *registry) StopAll(ctx context.Context) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	// Stop in reverse order
	stopOrder := make([]string, len(r.order))
	for i, name := range r.order {
		stopOrder[len(r.order)-1-i] = name
	}

	log.Printf("[Registry] Stopping %d modules in order: %v", len(stopOrder), stopOrder)

	var lastErr error
	for _, name := range stopOrder {
		entry := r.modules[name]
		if entry.state != ModuleStateRunning {
			continue
		}

		entry.state = ModuleStateStopping
		log.Printf("[Registry] Stopping module: %s", name)

		if err := entry.module.Stop(); err != nil {
			entry.state = ModuleStateError
			entry.err = err
			lastErr = err
			log.Printf("[Registry] Error stopping module %s: %v", name, err)
			continue
		}

		entry.state = ModuleStateStopped
		r.publishEvent(events.EventTypeModuleStopped, name, nil)
		log.Printf("[Registry] Module stopped: %s", name)
	}

	if lastErr != nil {
		return fmt.Errorf("errors occurred while stopping modules: %w", lastErr)
	}

	log.Printf("[Registry] All modules stopped")
	return nil
}

// Reload reloads configuration for all modules
func (r *registry) Reload(ctx context.Context, cfg interface{}) error {
	r.mu.RLock()
	defer r.mu.RUnlock()

	// This is a simplified version - real implementation would
	// pass specific config to each module that supports hot reload
	log.Printf("[Registry] Reloading configuration for %d modules", len(r.modules))

	r.publishEvent(events.EventTypeConfigReloaded, "registry", cfg)
	return nil
}

// HealthCheck returns health status of all modules
func (r *registry) HealthCheck() map[string]interfaces.HealthStatus {
	r.mu.RLock()
	defer r.mu.RUnlock()

	status := make(map[string]interfaces.HealthStatus, len(r.modules))
	for name, entry := range r.modules {
		if entry.state == ModuleStateRunning {
			status[name] = entry.module.HealthCheck()
		} else {
			status[name] = interfaces.HealthStatus{
				Healthy:     false,
				Message:     fmt.Sprintf("module is in state: %s", entry.state),
				LastChecked: time.Now(),
			}
		}
	}
	return status
}

// SetEventBus sets the event bus
func (r *registry) SetEventBus(bus events.EventBus) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.eventBus = bus
}

// Events returns the event bus
func (r *registry) Events() events.EventBus {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.eventBus
}

// computeStartOrder computes topological order for module startup
func (r *registry) computeStartOrder() ([]string, error) {
	// Build dependency graph
	inDegree := make(map[string]int)
	deps := make(map[string][]string)

	for name := range r.modules {
		inDegree[name] = 0
		deps[name] = make([]string, 0)
	}

	for name, entry := range r.modules {
		for _, dep := range entry.module.Dependencies() {
			if _, exists := r.modules[dep]; !exists {
				return nil, fmt.Errorf("module %q depends on unregistered module %q", name, dep)
			}
			deps[dep] = append(deps[dep], name)
			inDegree[name]++
		}
	}

	// Kahn's algorithm for topological sort
	queue := make([]string, 0)
	for name, degree := range inDegree {
		if degree == 0 {
			queue = append(queue, name)
		}
	}

	// Sort for deterministic order
	sort.Strings(queue)

	order := make([]string, 0, len(r.modules))
	for len(queue) > 0 {
		// Pop first element
		name := queue[0]
		queue = queue[1:]
		order = append(order, name)

		// Process dependents
		dependents := deps[name]
		sort.Strings(dependents)
		for _, dependent := range dependents {
			inDegree[dependent]--
			if inDegree[dependent] == 0 {
				queue = append(queue, dependent)
			}
		}
	}

	if len(order) != len(r.modules) {
		return nil, fmt.Errorf("circular dependency detected in modules")
	}

	return order, nil
}

// publishEvent publishes an event through the event bus
func (r *registry) publishEvent(eventType, source string, data interface{}) {
	if r.eventBus != nil {
		r.eventBus.PublishAsync(events.NewEvent(eventType, source, data))
	}
}

// ModuleFactory is a function that creates a module
type ModuleFactory func(cfg interface{}) (interfaces.Module, error)

// FactoryRegistry allows registering module factories for dynamic creation
type FactoryRegistry struct {
	mu        sync.RWMutex
	factories map[string]ModuleFactory
}

// NewFactoryRegistry creates a new factory registry
func NewFactoryRegistry() *FactoryRegistry {
	return &FactoryRegistry{
		factories: make(map[string]ModuleFactory),
	}
}

// RegisterFactory registers a module factory
func (fr *FactoryRegistry) RegisterFactory(moduleType string, factory ModuleFactory) {
	fr.mu.Lock()
	defer fr.mu.Unlock()
	fr.factories[moduleType] = factory
}

// CreateModule creates a module using a registered factory
func (fr *FactoryRegistry) CreateModule(moduleType string, cfg interface{}) (interfaces.Module, error) {
	fr.mu.RLock()
	factory, exists := fr.factories[moduleType]
	fr.mu.RUnlock()

	if !exists {
		return nil, fmt.Errorf("no factory registered for module type %q", moduleType)
	}

	return factory(cfg)
}

// GetRegisteredTypes returns all registered module types
func (fr *FactoryRegistry) GetRegisteredTypes() []string {
	fr.mu.RLock()
	defer fr.mu.RUnlock()

	types := make([]string, 0, len(fr.factories))
	for t := range fr.factories {
		types = append(types, t)
	}
	sort.Strings(types)
	return types
}

// GlobalRegistry is the default global registry instance
var GlobalRegistry = NewRegistry()

// GlobalFactoryRegistry is the default factory registry
var GlobalFactoryRegistry = NewFactoryRegistry()

// Register is a convenience function to register with the global registry
func Register(module interfaces.Module) error {
	return GlobalRegistry.Register(module)
}

// Get is a convenience function to get from the global registry
func Get(name string) (interfaces.Module, bool) {
	return GlobalRegistry.Get(name)
}

// MustGet gets a module or panics if not found
func MustGet(name string) interfaces.Module {
	module, ok := Get(name)
	if !ok {
		panic(fmt.Sprintf("module %q not found in registry", name))
	}
	return module
}
