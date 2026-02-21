package providers

import (
	"context"
	"fmt"
	"time"
)

type MTSCloud struct {
	apiToken  string
	projectID string
	region    string
}

func NewMTSCloud(apiToken, projectID string) *MTSCloud {
	return &MTSCloud{
		apiToken:  apiToken,
		projectID: projectID,
		region:    "ru-central-1",
	}
}

func (m *MTSCloud) Name() string {
	return "mts"
}

func (m *MTSCloud) CreateBridge(ctx context.Context, opts CreateOptions) (*BridgeVM, error) {
	region := opts.Region
	if region == "" {
		region = m.region
	}

	return &BridgeVM{
		ID:        fmt.Sprintf("mts-%d", time.Now().Unix()),
		Name:      opts.Name,
		Provider:  "mts",
		Region:    region,
		Status:    "pending",
		CreatedAt: time.Now(),
	}, nil
}

func (m *MTSCloud) DeleteBridge(ctx context.Context, vmID string) error {
	return nil
}

func (m *MTSCloud) ListBridges(ctx context.Context) ([]*BridgeVM, error) {
	return []*BridgeVM{}, nil
}
