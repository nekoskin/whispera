package providers

import (
	"context"
	"fmt"
	"time"
)

type TimewebCloud struct {
	apiToken string
	region   string
}

func NewTimewebCloud(apiToken string) *TimewebCloud {
	return &TimewebCloud{
		apiToken: apiToken,
		region:   "ru-1",
	}
}

func (t *TimewebCloud) Name() string {
	return "timeweb"
}

func (t *TimewebCloud) CreateBridge(ctx context.Context, opts CreateOptions) (*BridgeVM, error) {
	region := opts.Region
	if region == "" {
		region = t.region
	}

	return &BridgeVM{
		ID:        fmt.Sprintf("timeweb-%d", time.Now().Unix()),
		Name:      opts.Name,
		Provider:  "timeweb",
		Region:    region,
		Status:    "pending",
		CreatedAt: time.Now(),
	}, nil
}

func (t *TimewebCloud) DeleteBridge(ctx context.Context, vmID string) error {
	return nil
}

func (t *TimewebCloud) ListBridges(ctx context.Context) ([]*BridgeVM, error) {
	return []*BridgeVM{}, nil
}
