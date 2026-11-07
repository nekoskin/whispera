//go:build !windows

package tunnel

import (
	"fmt"
	"math"
	"net"
	"os"
	"runtime"
	"strconv"
	"strings"
)

func captureHint(err error) error {
	return fmt.Errorf("%w; capturing needs libpcap and the CAP_NET_RAW capability", err)
}

const (
	procRoutes = "/proc/net/route"
	anyIPv4Hex = "00000000"
)

func defaultRouteInterface() (int, string) {
	if runtime.GOOS != "linux" {
		return 0, ""
	}
	data, err := os.ReadFile(procRoutes)
	if err != nil {
		return 0, ""
	}
	name, metric := "", uint64(math.MaxUint64)
	for _, line := range strings.Split(string(data), "\n")[1:] {
		f := strings.Fields(line)
		if len(f) < 8 || f[1] != anyIPv4Hex || f[7] != anyIPv4Hex || f[2] == anyIPv4Hex {
			continue
		}
		if m, err := strconv.ParseUint(f[6], 10, 32); err == nil && m < metric {
			name, metric = f[0], m
		}
	}
	if name == "" {
		return 0, ""
	}
	iface, err := net.InterfaceByName(name)
	if err != nil {
		return 0, ""
	}
	return iface.Index, name
}
