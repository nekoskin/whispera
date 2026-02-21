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

type YandexCloudProvider struct {
	APIKey   string
	FolderID string
	baseURL  string
	client   *http.Client
}

func NewYandexCloudProvider(apiKey, folderID string) *YandexCloudProvider {
	return &YandexCloudProvider{
		APIKey:   apiKey,
		FolderID: folderID,
		baseURL:  "https://compute.api.cloud.yandex.net/compute/v1",
		client:   &http.Client{Timeout: 60 * time.Second},
	}
}

func (p *YandexCloudProvider) Name() string {
	return "yandex"
}

func (p *YandexCloudProvider) CreateBridge(ctx context.Context, opts CreateOptions) (*BridgeVM, error) {
	if p.APIKey == "" {
		return nil, errors.New("Yandex Cloud API key not configured")
	}

	region := opts.Region
	if region == "" {
		region = "ru-central1-a"
	}

	userData := opts.UserData
	if userData == "" {
		userData = DefaultBridgeCloudInit()
	}

	reqBody := map[string]interface{}{
		"folderId":   p.FolderID,
		"name":       opts.Name,
		"zoneId":     region,
		"platformId": "standard-v3",
		"resourcesSpec": map[string]interface{}{
			"memory":       2147483648,
			"cores":        2,
			"coreFraction": 20,
		},
		"metadata": map[string]string{
			"user-data": userData,
		},
		"bootDiskSpec": map[string]interface{}{
			"autoDelete": true,
			"diskSpec": map[string]interface{}{
				"size":    10737418240,
				"typeId":  "network-ssd",
				"imageId": "fd8vmcue7aajpmeo39kk",
			},
		},
		"networkInterfaceSpecs": []map[string]interface{}{
			{
				"subnetId": "auto",
				"primaryV4AddressSpec": map[string]interface{}{
					"oneToOneNatSpec": map[string]interface{}{
						"ipVersion": "IPV4",
					},
				},
			},
		},
	}

	body, _ := json.Marshal(reqBody)
	req, err := http.NewRequestWithContext(ctx, "POST", p.baseURL+"/instances", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", "Bearer "+p.APIKey)
	req.Header.Set("Content-Type", "application/json")

	resp, err := p.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to create VM: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		respBody, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("Yandex API error %d: %s", resp.StatusCode, string(respBody))
	}

	var result struct {
		ID       string `json:"id"`
		Metadata struct {
			InstanceID string `json:"instanceId"`
		} `json:"metadata"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	vm, err := p.waitForVM(ctx, result.Metadata.InstanceID)
	if err != nil {
		return nil, err
	}

	return vm, nil
}

func (p *YandexCloudProvider) waitForVM(ctx context.Context, vmID string) (*BridgeVM, error) {
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
			req, _ := http.NewRequestWithContext(ctx, "GET", p.baseURL+"/instances/"+vmID, nil)
			req.Header.Set("Authorization", "Bearer "+p.APIKey)

			resp, err := p.client.Do(req)
			if err != nil {
				continue
			}

			var instance struct {
				Status            string `json:"status"`
				NetworkInterfaces []struct {
					PrimaryV4Address struct {
						OneToOneNat struct {
							Address string `json:"address"`
						} `json:"oneToOneNat"`
					} `json:"primaryV4Address"`
				} `json:"networkInterfaces"`
			}

			json.NewDecoder(resp.Body).Decode(&instance)
			resp.Body.Close()

			if instance.Status == "RUNNING" && len(instance.NetworkInterfaces) > 0 {
				ip := instance.NetworkInterfaces[0].PrimaryV4Address.OneToOneNat.Address
				if ip != "" {
					return &BridgeVM{
						ID:        vmID,
						PublicIP:  ip,
						Status:    "running",
						Provider:  "yandex",
						CreatedAt: time.Now(),
					}, nil
				}
			}
		}
	}
}

func (p *YandexCloudProvider) DeleteBridge(ctx context.Context, vmID string) error {
	req, err := http.NewRequestWithContext(ctx, "DELETE", p.baseURL+"/instances/"+vmID, nil)
	if err != nil {
		return err
	}

	req.Header.Set("Authorization", "Bearer "+p.APIKey)

	resp, err := p.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusAccepted {
		return fmt.Errorf("failed to delete VM: %d", resp.StatusCode)
	}

	return nil
}

func (p *YandexCloudProvider) ListBridges(ctx context.Context) ([]*BridgeVM, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", p.baseURL+"/instances?folderId="+p.FolderID, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", "Bearer "+p.APIKey)

	resp, err := p.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var result struct {
		Instances []struct {
			ID                string `json:"id"`
			Name              string `json:"name"`
			Status            string `json:"status"`
			NetworkInterfaces []struct {
				PrimaryV4Address struct {
					OneToOneNat struct {
						Address string `json:"address"`
					} `json:"oneToOneNat"`
				} `json:"primaryV4Address"`
			} `json:"networkInterfaces"`
		} `json:"instances"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	vms := make([]*BridgeVM, 0)
	for _, inst := range result.Instances {
		ip := ""
		if len(inst.NetworkInterfaces) > 0 {
			ip = inst.NetworkInterfaces[0].PrimaryV4Address.OneToOneNat.Address
		}
		vms = append(vms, &BridgeVM{
			ID:       inst.ID,
			Name:     inst.Name,
			PublicIP: ip,
			Status:   inst.Status,
			Provider: "yandex",
		})
	}

	return vms, nil
}
