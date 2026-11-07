package tunnel

import (
	"fmt"
	"net"
	"strings"
)

const captureEndpointsMax = 16

func endpointFilter(endpoints []string) string {
	if len(endpoints) == 0 {
		return "tcp"
	}
	parts := make([]string, 0, len(endpoints))
	for _, ep := range endpoints {
		host, port, err := net.SplitHostPort(ep)
		if err != nil {
			continue
		}
		parts = append(parts, fmt.Sprintf("(host %s and port %s)", host, port))
	}
	return "tcp and (" + strings.Join(parts, " or ") + ")"
}

func configuredFilter(server string) (string, []string) {
	host, port, err := net.SplitHostPort(server)
	if err != nil {
		return endpointFilter(nil), nil
	}
	if net.ParseIP(host) != nil {
		endpoints := []string{net.JoinHostPort(host, port)}
		return endpointFilter(endpoints), endpoints
	}
	return "tcp and port " + port, nil
}

func addEndpoint(endpoints []string, endpoint string) ([]string, bool) {
	for _, ep := range endpoints {
		if ep == endpoint {
			return endpoints, false
		}
	}
	endpoints = append(endpoints, endpoint)
	if len(endpoints) > captureEndpointsMax {
		endpoints = endpoints[len(endpoints)-captureEndpointsMax:]
	}
	return endpoints, true
}
