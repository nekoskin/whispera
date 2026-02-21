package providers

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"
)

type VKCloudProvider struct {
	APIKey    string
	ProjectID string
	baseURL   string
	client    *http.Client
}

func NewVKCloudProvider(apiKey, projectID string) *VKCloudProvider {
	return &VKCloudProvider{
		APIKey:    apiKey,
		ProjectID: projectID,
		baseURL:   "https://infra.mail.ru:8774/v2.1",
		client:    &http.Client{Timeout: 60 * time.Second},
	}
}

func (p *VKCloudProvider) Name() string {
	return "vk"
}

func (p *VKCloudProvider) CreateBridge(ctx context.Context, opts CreateOptions) (*BridgeVM, error) {
	if p.APIKey == "" {
		return nil, errors.New("VK Cloud API key not configured")
	}

	region := opts.Region
	if region == "" {
		region = "ru-msk"
	}

	userData := opts.UserData
	if userData == "" {
		userData = DefaultBridgeCloudInit()
	}

	reqBody := map[string]interface{}{
		"server": map[string]interface{}{
			"name":              opts.Name,
			"flavorRef":         "Basic-1-2-20",
			"imageRef":          "ubuntu-22-04",
			"availability_zone": region,
			"user_data":         userData,
			"networks": []map[string]interface{}{
				{"uuid": "external-network"},
			},
		},
	}

	body, _ := json.Marshal(reqBody)
	req, err := http.NewRequestWithContext(ctx, "POST", fmt.Sprintf("%s/%s/servers", p.baseURL, p.ProjectID), bytes.NewReader(body))
	if err != nil {
		return nil, err
	}

	req.Header.Set("X-Auth-Token", p.APIKey)
	req.Header.Set("Content-Type", "application/json")

	resp, err := p.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to create VM: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusAccepted {
		respBody, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("VK Cloud API error %d: %s", resp.StatusCode, string(respBody))
	}

	var result struct {
		Server struct {
			ID string `json:"id"`
		} `json:"server"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	vm, err := p.waitForVM(ctx, result.Server.ID)
	if err != nil {
		return nil, err
	}

	return vm, nil
}

func (p *VKCloudProvider) waitForVM(ctx context.Context, vmID string) (*BridgeVM, error) {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	timeout := time.After(5 * time.Minute)

	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-timeout:
			return nil, errors.New("timeout waiting for VM")
		case <-ticker.C:
			req, _ := http.NewRequestWithContext(ctx, "GET", fmt.Sprintf("%s/%s/servers/%s", p.baseURL, p.ProjectID, vmID), nil)
			req.Header.Set("X-Auth-Token", p.APIKey)

			resp, err := p.client.Do(req)
			if err != nil {
				continue
			}

			var server struct {
				Server struct {
					Status    string `json:"status"`
					Addresses map[string][]struct {
						Addr    string `json:"addr"`
						Version int    `json:"version"`
						Type    string `json:"OS-EXT-IPS:type"`
					} `json:"addresses"`
				} `json:"server"`
			}

			json.NewDecoder(resp.Body).Decode(&server)
			resp.Body.Close()

			if server.Server.Status == "ACTIVE" {
				for _, addrs := range server.Server.Addresses {
					for _, addr := range addrs {
						if addr.Type == "floating" || addr.Version == 4 {
							return &BridgeVM{
								ID:        vmID,
								PublicIP:  addr.Addr,
								Status:    "running",
								Provider:  "vk",
								CreatedAt: time.Now(),
							}, nil
						}
					}
				}
			}
		}
	}
}

func (p *VKCloudProvider) DeleteBridge(ctx context.Context, vmID string) error {
	req, err := http.NewRequestWithContext(ctx, "DELETE", fmt.Sprintf("%s/%s/servers/%s", p.baseURL, p.ProjectID, vmID), nil)
	if err != nil {
		return err
	}

	req.Header.Set("X-Auth-Token", p.APIKey)

	resp, err := p.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusAccepted {
		return fmt.Errorf("failed to delete VM: %d", resp.StatusCode)
	}

	return nil
}

func (p *VKCloudProvider) ListBridges(ctx context.Context) ([]*BridgeVM, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", fmt.Sprintf("%s/%s/servers/detail", p.baseURL, p.ProjectID), nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("X-Auth-Token", p.APIKey)

	resp, err := p.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var result struct {
		Servers []struct {
			ID        string `json:"id"`
			Name      string `json:"name"`
			Status    string `json:"status"`
			Addresses map[string][]struct {
				Addr string `json:"addr"`
				Type string `json:"OS-EXT-IPS:type"`
			} `json:"addresses"`
		} `json:"servers"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	vms := make([]*BridgeVM, 0)
	for _, srv := range result.Servers {
		ip := ""
		for _, addrs := range srv.Addresses {
			for _, addr := range addrs {
				if addr.Type == "floating" || ip == "" {
					ip = addr.Addr
				}
			}
		}
		vms = append(vms, &BridgeVM{
			ID:       srv.ID,
			Name:     srv.Name,
			PublicIP: ip,
			Status:   srv.Status,
			Provider: "vk",
		})
	}

	return vms, nil
}
