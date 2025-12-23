package authsvc

import (
	"context"
	"errors"
)

// TokenValidator validates client tokens.
type TokenValidator interface {
	Validate(ctx context.Context, token, clientID string) error
}

// AllowAllValidator permits every token; useful during migration.
type AllowAllValidator struct{}

// ErrEmptyToken is returned when token is missing.
var ErrEmptyToken = errors.New("token is required")

// Validate implements TokenValidator.
func (AllowAllValidator) Validate(ctx context.Context, token, clientID string) error {
	if token == "" {
		return ErrEmptyToken
	}
	return nil
}
