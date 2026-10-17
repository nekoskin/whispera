package tunnel

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net"
	"sync/atomic"
)

const (
	networkKeyBytes   = 4
	routePrefixBitsV4 = 24
	routePrefixBitsV6 = 64
	routeDescriptorAt = "route:"
)

var platformNetwork atomic.Pointer[string]

func SetNetwork(descriptor string) {
	if descriptor == "" {
		platformNetwork.Store(nil)
		return
	}
	key := hashNetwork(descriptor)
	platformNetwork.Store(&key)
}

func hashNetwork(descriptor string) string {
	if descriptor == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(descriptor))
	return hex.EncodeToString(sum[:networkKeyBytes])
}

func networkKey(ctx context.Context, serverAddr string) string {
	if key := platformNetwork.Load(); key != nil {
		return *key
	}
	return hashNetwork(routeDescriptor(ctx, serverAddr))
}

func routeDescriptor(ctx context.Context, serverAddr string) string {
	var d net.Dialer
	conn, err := d.DialContext(ctx, "udp", serverAddr)
	if err != nil {
		return ""
	}
	defer conn.Close()
	local, ok := conn.LocalAddr().(*net.UDPAddr)
	if !ok {
		return ""
	}
	return routeDescriptorAt + localPrefix(local.IP).String()
}

func localPrefix(ip net.IP) *net.IPNet {
	bits, size := routePrefixBitsV6, net.IPv6len*8
	if v4 := ip.To4(); v4 != nil {
		ip, bits, size = v4, routePrefixBitsV4, net.IPv4len*8
	}
	mask := net.CIDRMask(bits, size)
	return &net.IPNet{IP: ip.Mask(mask), Mask: mask}
}

func armContext(sni, network, kind string) string {
	if network == "" {
		return sni + "|" + kind
	}
	return sni + "|" + network + "|" + kind
}
