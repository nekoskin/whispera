package tunnel

import (
	"context"
	"net"
)

type killSwitchController interface {
	SetVPNServer(ip net.IP, port int)
	Enable() error
	Disable() error
}

type tcpBypassDialer interface {
	DialTCPWithFragments(ctx context.Context, network, addr string, maxRecords int) (net.Conn, error)
	DialTCPWithShape(ctx context.Context, network, addr string, records, pauseMs int) (net.Conn, error)
	DialTCP(ctx context.Context, network, addr string) (net.Conn, error)
	Fragmenting() bool
}
