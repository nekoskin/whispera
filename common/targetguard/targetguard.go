package targetguard

import (
	"errors"
	"fmt"
	"maps"
	"net"
	"net/netip"
	"slices"
	"strings"
	"syscall"
)

const (
	ClassLoopback    = "loopback"
	ClassUnspecified = "unspecified"
	ClassPrivate     = "private"
	ClassLinkLocal   = "link-local"
)

var classes = map[string]func(netip.Addr) bool{
	ClassLoopback:    netip.Addr.IsLoopback,
	ClassUnspecified: netip.Addr.IsUnspecified,
	ClassPrivate:     netip.Addr.IsPrivate,
	ClassLinkLocal: func(addr netip.Addr) bool {
		return addr.IsLinkLocalUnicast() || addr.IsLinkLocalMulticast()
	},
}

var ErrBlocked = errors.New("blocked by relay.blocked_targets")

type Guard struct {
	matchers []func(netip.Addr) bool
}

func New(entries []string) (*Guard, error) {
	guard := &Guard{}
	for _, entry := range entries {
		entry = strings.TrimSpace(entry)
		if match, ok := classes[entry]; ok {
			guard.matchers = append(guard.matchers, match)
			continue
		}
		prefix, err := netip.ParsePrefix(entry)
		if err != nil {
			return nil, fmt.Errorf("%q is neither a CIDR nor one of %s", entry, strings.Join(slices.Sorted(maps.Keys(classes)), ", "))
		}
		prefix = prefix.Masked()
		guard.matchers = append(guard.matchers, prefix.Contains)
	}
	return guard, nil
}

func (g *Guard) Blocks(addr netip.Addr) bool {
	if g == nil {
		return false
	}
	addr = addr.Unmap().WithZone("")
	return slices.ContainsFunc(g.matchers, func(match func(netip.Addr) bool) bool {
		return match(addr)
	})
}

func (g *Guard) Control(_, address string, _ syscall.RawConn) error {
	target, err := netip.ParseAddrPort(address)
	if err != nil {
		return err
	}
	if g.Blocks(target.Addr()) {
		return fmt.Errorf("%s %w", target.Addr(), ErrBlocked)
	}
	return nil
}

func (g *Guard) Dialer() *net.Dialer {
	if g == nil {
		return &net.Dialer{}
	}
	return &net.Dialer{Control: g.Control}
}
