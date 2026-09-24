package router

import (
	"context"
	"fmt"
	"net"
	"testing"

	"github.com/nekoskin/whispera/common/runtime/interfaces"
)

func benchEngine(b *testing.B, rules int, cache bool) *Engine {
	cfg := DefaultConfig()
	cfg.EnableCache = cache
	e, err := New(cfg)
	if err != nil {
		b.Fatal(err)
	}
	for i := 0; i < rules; i++ {
		err := e.AddRule(interfaces.RoutingRule{
			ID:       fmt.Sprintf("rule-%d", i),
			Priority: i,
			Conditions: []interfaces.RuleCondition{{
				Field:    "dst_ip",
				Operator: "cidr",
				Value:    fmt.Sprintf("10.%d.%d.0/24", i/256, i%256),
			}},
			Destination: interfaces.Destination{Type: interfaces.DestinationDirect},
		})
		if err != nil {
			b.Fatal(err)
		}
	}
	return e
}

func BenchmarkRouteMiss(b *testing.B) {
	ctx := context.Background()
	for _, n := range []int{10, 100, 1000} {
		e := benchEngine(b, n, false)
		pkt := &interfaces.Packet{DstAddr: &net.TCPAddr{IP: net.ParseIP("203.0.113.7"), Port: 443}}
		b.Run(fmt.Sprintf("rules=%d", n), func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				if _, err := e.Route(ctx, pkt); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkRouteCached(b *testing.B) {
	ctx := context.Background()
	e := benchEngine(b, 1000, true)
	pkt := &interfaces.Packet{DstAddr: &net.TCPAddr{IP: net.ParseIP("203.0.113.7"), Port: 443}}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, err := e.Route(ctx, pkt); err != nil {
			b.Fatal(err)
		}
	}
}
