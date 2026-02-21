package providers

import (
	"context"
	"fmt"
	"time"
)
type SelectelCloud struct {
	apiToken  string
	projectID string
	region    string
}

func NewSelectelCloud(apiToken, projectID string) *SelectelCloud {
	return &SelectelCloud{
		apiToken:  apiToken,
		projectID: projectID,
		region:    "ru-1",
	}
}

func (s *SelectelCloud) Name() string {
	return "selectel"
}

func (s *SelectelCloud) CreateBridge(ctx context.Context, opts CreateOptions) (*BridgeVM, error) {
	if s.apiToken == "" {
		return nil, fmt.Errorf("selectel: API token not configured — set it in config.yaml under bridge.selectel_api_token")
	}
	if s.projectID == "" {
		return nil, fmt.Errorf("selectel: project ID not configured — set it in config.yaml under bridge.selectel_project_id")
	}

	region := opts.Region
	if region == "" {
		region = s.region
	}

	return &BridgeVM{
		ID:        fmt.Sprintf("selectel-%d", time.Now().Unix()),
		Name:      opts.Name,
		Provider:  "selectel",
		Region:    region,
		Status:    "pending_implementation",
		CreatedAt: time.Now(),
	}, nil
}

func (s *SelectelCloud) DeleteBridge(ctx context.Context, vmID string) error {
	if s.apiToken == "" {
		return fmt.Errorf("selectel: API token not configured")
	}
	return fmt.Errorf("selectel: DeleteBridge not yet implemented for VM %s", vmID)
}

func (s *SelectelCloud) ListBridges(ctx context.Context) ([]*BridgeVM, error) {
	if s.apiToken == "" {
		return nil, fmt.Errorf("selectel: API token not configured")
	}
	return []*BridgeVM{}, fmt.Errorf("selectel: ListBridges not yet implemented")
}
