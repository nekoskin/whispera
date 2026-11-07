package tunnel

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	stdlog "log"
	"net"
	"sync/atomic"
)

const (
	networkKeyBytes   = 4
	routePrefixBitsV4 = 24
	routePrefixBitsV6 = 64
	routeDescriptorAt = "route:"
	routeHopAt        = " via "
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

var lastNetwork atomic.Pointer[string]

func networkKey(ctx context.Context, serverAddr string) string {
	if key := platformNetwork.Load(); key != nil {
		return *key
	}
	local, ok := routeSource(ctx, serverAddr)
	if !ok {
		return ""
	}
	descriptor := routeDescriptorAt + localPrefix(local).String()
	if hop, ok := sharedWire.nextHop(local); ok {
		descriptor += routeHopAt + hop.String()
	}
	key := hashNetwork(descriptor)
	if prev := lastNetwork.Swap(&key); prev == nil || *prev != key {
		stdlog.Printf("[DIAL] network %s: %s", key, descriptor)
	}
	return key
}

func routeSource(ctx context.Context, serverAddr string) (net.IP, bool) {
	var d net.Dialer
	conn, err := d.DialContext(ctx, "udp", serverAddr)
	if err != nil {
		return nil, false
	}
	defer conn.Close()
	local, ok := conn.LocalAddr().(*net.UDPAddr)
	if !ok {
		return nil, false
	}
	return local.IP, true
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
