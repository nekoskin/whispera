package obfuscation

import (
	mariomethods "whispera/internal/obfuscation/marionette"
	mlpkg "whispera/internal/obfuscation/ml"
)

// MarionetteAdapter is a re-export for backward compatibility
type MarionetteAdapter = mariomethods.MarionetteAdapter

// NewMarionetteAdapter creates a new MarionetteAdapter
func NewMarionetteAdapter() *MarionetteAdapter {
	return mariomethods.NewMarionetteAdapter()
}

// Marionette structure alias for compatibility
type Marionette = mariomethods.Marionette

// UnifiedMLSystem alias for compatibility
type UnifiedMLSystem = mlpkg.UnifiedMLSystem

// NewUnifiedMLSystem alias
func NewUnifiedMLSystem() *UnifiedMLSystem {
	return mlpkg.NewUnifiedMLSystem()
}
