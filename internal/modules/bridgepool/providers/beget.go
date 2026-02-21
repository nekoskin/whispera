package providers

import (
	"context"
	"fmt"
	"time"
)

type BegetCloud struct {
	apiToken string
}

func NewBegetCloud(apiToken string) *BegetCloud {
	return &BegetCloud{
		apiToken: apiToken,
	}
}

func (b *BegetCloud) Name() string {
	return "beget"
}

func (b *BegetCloud) CreateBridge(ctx context.Context, opts CreateOptions) (*BridgeVM, error) {
	return &BridgeVM{
		ID:        fmt.Sprintf("beget-%d", time.Now().Unix()),
		Name:      opts.Name,
		Provider:  "beget",
		Region:    "ru-msk",
		Status:    "pending",
		CreatedAt: time.Now(),
	}, nil
}

func (b *BegetCloud) DeleteBridge(ctx context.Context, vmID string) error {
	return nil
}

func (b *BegetCloud) ListBridges(ctx context.Context) ([]*BridgeVM, error) {
	return []*BridgeVM{}, nil
}
