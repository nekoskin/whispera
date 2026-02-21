package providers

import (
	"context"
	"fmt"
	"time"
)

type GenericSSH struct {
	name     string
	sshHost  string
	sshPort  int
	sshUser  string
	sshKey   string
	password string
}

type GenericConfig struct {
	Name     string `yaml:"name" json:"name"`
	SSHHost  string `yaml:"ssh_host" json:"ssh_host"`
	SSHPort  int    `yaml:"ssh_port" json:"ssh_port"`
	SSHUser  string `yaml:"ssh_user" json:"ssh_user"`
	SSHKey   string `yaml:"ssh_key" json:"ssh_key"`
	Password string `yaml:"password" json:"password"`
}

func NewGenericSSH(cfg GenericConfig) *GenericSSH {
	port := cfg.SSHPort
	if port == 0 {
		port = 22
	}
	return &GenericSSH{
		name:     cfg.Name,
		sshHost:  cfg.SSHHost,
		sshPort:  port,
		sshUser:  cfg.SSHUser,
		sshKey:   cfg.SSHKey,
		password: cfg.Password,
	}
}

func (g *GenericSSH) Name() string {
	if g.name != "" {
		return g.name
	}
	return "generic"
}

func (g *GenericSSH) CreateBridge(ctx context.Context, opts CreateOptions) (*BridgeVM, error) {
	return &BridgeVM{
		ID:        fmt.Sprintf("%s-%d", g.Name(), time.Now().Unix()),
		Name:      opts.Name,
		PublicIP:  g.sshHost,
		Provider:  g.Name(),
		Region:    opts.Region,
		Status:    "deploying",
		CreatedAt: time.Now(),
	}, nil
}

func (g *GenericSSH) DeleteBridge(ctx context.Context, vmID string) error {
	return nil
}

func (g *GenericSSH) ListBridges(ctx context.Context) ([]*BridgeVM, error) {
	return []*BridgeVM{
		{
			ID:       g.Name() + "-main",
			Name:     g.Name(),
			PublicIP: g.sshHost,
			Provider: g.Name(),
			Status:   "running",
		},
	}, nil
}

func (g *GenericSSH) GetSSHConfig() map[string]interface{} {
	return map[string]interface{}{
		"host":     g.sshHost,
		"port":     g.sshPort,
		"user":     g.sshUser,
		"key_path": g.sshKey,
	}
}
