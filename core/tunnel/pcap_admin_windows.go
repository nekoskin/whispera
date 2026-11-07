package tunnel

import (
	"fmt"
	"math"
	"unsafe"

	"golang.org/x/sys/windows"
)

func captureHint(err error) error {
	if windows.GetCurrentProcessToken().IsElevated() {
		return fmt.Errorf("%w; check that Npcap is installed", err)
	}
	return fmt.Errorf("%w; check that Npcap is installed, and run the client as administrator if Npcap was installed admin-only", err)
}

func defaultRouteInterface() (int, string) {
	const flags = windows.GAA_FLAG_INCLUDE_GATEWAYS | windows.GAA_FLAG_SKIP_ANYCAST | windows.GAA_FLAG_SKIP_MULTICAST | windows.GAA_FLAG_SKIP_DNS_SERVER
	size := uint32(16 << 10)
	for {
		buf := make([]byte, size)
		first := (*windows.IpAdapterAddresses)(unsafe.Pointer(&buf[0]))
		err := windows.GetAdaptersAddresses(windows.AF_INET, flags, 0, first, &size)
		if err == windows.ERROR_BUFFER_OVERFLOW {
			continue
		}
		if err != nil {
			return 0, ""
		}
		hardware, virtual := routeChoice{metric: math.MaxUint32}, routeChoice{metric: math.MaxUint32}
		for a := first; a != nil; a = a.Next {
			if a.OperStatus != windows.IfOperStatusUp || !hasGateway(a) {
				continue
			}
			pick := &virtual
			if isHardwareInterface(a.Luid) {
				pick = &hardware
			}
			if a.Ipv4Metric < pick.metric {
				*pick = routeChoice{index: int(a.IfIndex), name: windows.UTF16PtrToString(a.FriendlyName), metric: a.Ipv4Metric}
			}
		}
		if hardware.index == 0 {
			return virtual.index, virtual.name
		}
		return hardware.index, hardware.name
	}
}

type routeChoice struct {
	index  int
	name   string
	metric uint32
}

const ifHardwareInterface = 0x01

func isHardwareInterface(luid uint64) bool {
	row := windows.MibIfRow2{InterfaceLuid: luid}
	return windows.GetIfEntry2Ex(windows.MibIfEntryNormalWithoutStatistics, &row) == nil && row.InterfaceAndOperStatusFlags&ifHardwareInterface != 0
}

func hasGateway(a *windows.IpAdapterAddresses) bool {
	for g := a.FirstGatewayAddress; g != nil; g = g.Next {
		if ip := g.Address.IP(); ip != nil && !ip.IsUnspecified() {
			return true
		}
	}
	return false
}
