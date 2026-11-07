package tunnel

import (
	"net"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func TestHashNetworkIsShortAndStable(t *testing.T) {
	a, b := hashNetwork("wifi:gw=192.168.1.1"), hashNetwork("wifi:gw=192.168.1.1")
	if a != b {
		t.Fatalf("same network hashed differently: %q vs %q", a, b)
	}
	if len(a) != networkKeyBytes*2 {
		t.Fatalf("key %q should be %d hex chars", a, networkKeyBytes*2)
	}
	if hashNetwork("wifi:gw=192.168.0.1") == a {
		t.Fatal("different networks share a key")
	}
	if hashNetwork("") != "" {
		t.Fatal("an unknown network should have no key")
	}
}

func TestPlatformNetworkOverridesRoute(t *testing.T) {
	defer SetNetwork("")
	const server = "127.0.0.1:443"
	route := networkKey(t.Context(), server)
	if route == "" {
		t.Fatal("loopback route should give a key")
	}
	SetNetwork("mobile:25001")
	if got := networkKey(t.Context(), server); got != hashNetwork("mobile:25001") {
		t.Fatalf("platform network ignored: %q", got)
	}
	SetNetwork("")
	if got := networkKey(t.Context(), server); got != route {
		t.Fatalf("clearing the platform network should fall back to the route key, got %q", got)
	}
}

func TestSameSubnetBehindDifferentGatewaysIsTwoNetworks(t *testing.T) {
	w := newWireWatch()
	w.start(nil)
	local := net.IPv4(192, 168, 1, 23)
	server, neighbor := net.IPv4(203, 0, 113, 7), net.IPv4(192, 168, 1, 50)
	frame := func(to net.IP, hop net.HardwareAddr) gopacket.Packet {
		eth := &layers.Ethernet{SrcMAC: net.HardwareAddr{2, 0, 0, 0, 0, 1}, DstMAC: hop, EthernetType: layers.EthernetTypeIPv4}
		ip := &layers.IPv4{Version: 4, TTL: 64, Protocol: layers.IPProtocolTCP, SrcIP: local.To4(), DstIP: to.To4()}
		tcp := &layers.TCP{SrcPort: 50000, DstPort: 443, SYN: true, Window: 64240}
		if err := tcp.SetNetworkLayerForChecksum(ip); err != nil {
			t.Fatal(err)
		}
		buf := gopacket.NewSerializeBuffer()
		if err := gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, eth, ip, tcp); err != nil {
			t.Fatal(err)
		}
		pkt := gopacket.NewPacket(buf.Bytes(), layers.LayerTypeEthernet, gopacket.Default)
		pkt.Metadata().Timestamp = time.Now()
		return pkt
	}
	home, cafe := net.HardwareAddr{0xa0, 1, 2, 3, 4, 5}, net.HardwareAddr{0xb0, 6, 7, 8, 9, 10}
	w.see(frame(server, home))
	w.see(frame(neighbor, net.HardwareAddr{0xc0, 1, 1, 1, 1, 1}))
	if hop, ok := w.nextHop(local); !ok || hop.String() != home.String() {
		t.Fatalf("the gateway behind a fresh outbound SYN came out as %v, want %v; a host on the local subnet is not a gateway", hop, home)
	}
	w.see(frame(server, cafe))
	if hop, ok := w.nextHop(local); !ok || hop.String() != cafe.String() {
		t.Fatalf("after moving to another router with the same subnet the gateway is %v, want %v", hop, cafe)
	}
}
