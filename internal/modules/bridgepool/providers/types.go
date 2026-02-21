package providers

import (
	"context"
	"time"
)

type CloudProvider interface {
	Name() string
	CreateBridge(ctx context.Context, opts CreateOptions) (*BridgeVM, error)
	DeleteBridge(ctx context.Context, vmID string) error
	ListBridges(ctx context.Context) ([]*BridgeVM, error)
}
type CreateOptions struct {
	Name       string
	Region     string
	Size       string
	SSHKeyPath string
	UserData   string
}

type BridgeVM struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	PublicIP  string    `json:"public_ip"`
	Status    string    `json:"status"`
	Provider  string    `json:"provider"`
	Region    string    `json:"region"`
	CreatedAt time.Time `json:"created_at"`
}

func DefaultBridgeCloudInit() string {
	return `#!/bin/bash
set -e

apt-get update && apt-get upgrade -y
curl -fsSL https://github.com/your-repo/whispera/releases/latest/download/whispera-linux-amd64 -o /usr/local/bin/whispera-bridge
chmod +x /usr/local/bin/whispera-bridge

mkdir -p /etc/whispera
cat > /etc/whispera/bridge.yaml <<EOF
relay_mode: bridge
upstream_server: "MAIN_SERVER_ADDRESS:443"
bridge:
  auto_register: true
  type: user
phantom:
  enabled: true
  use_russian_service: true
  russian_service_name: vk
EOF

cat > /etc/systemd/system/whispera-bridge.service <<EOF
[Unit]
Description=Whispera Bridge
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/whispera-bridge -c /etc/whispera/bridge.yaml
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable whispera-bridge
systemctl start whispera-bridge
`
}
