//go:build pcap || (windows && (amd64 || 386))

package tunnel

import (
	"errors"
	"fmt"
	stdlog "log"
	"net"
	"strings"
	"sync"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

func LogCaptureDevices() {
	devs, err := pcap.FindAllDevs()
	if err != nil {
		stdlog.Printf("[PCAP] no capture devices (%s): %v", pcap.Version(), err)
		return
	}
	stdlog.Printf("[PCAP] %s", pcap.Version())
	for _, d := range devs {
		ips := make([]string, 0, len(d.Addresses))
		for _, a := range d.Addresses {
			ips = append(ips, a.IP.String())
		}
		stdlog.Printf("[PCAP] device %s %q %s", d.Name, d.Description, strings.Join(ips, ","))
	}
}

func routeDevice(server string) string {
	if server == "" {
		return ""
	}
	conn, err := (&net.Dialer{Control: bindDefaultRoute}).Dial("udp", server)
	if err != nil {
		return ""
	}
	defer conn.Close()
	local, ok := conn.LocalAddr().(*net.UDPAddr)
	if !ok {
		return ""
	}
	return deviceWithIP(local.IP)
}

func deviceWithIP(ip net.IP) string {
	devs, err := pcap.FindAllDevs()
	if err != nil {
		return ""
	}
	for _, d := range devs {
		for _, a := range d.Addresses {
			if a.IP.Equal(ip) {
				return d.Name
			}
		}
	}
	return ""
}

func deviceIPs(name string) []net.IP {
	devs, err := pcap.FindAllDevs()
	if err != nil {
		return nil
	}
	for _, d := range devs {
		if d.Name != name {
			continue
		}
		ips := make([]net.IP, 0, len(d.Addresses))
		for _, a := range d.Addresses {
			ips = append(ips, a.IP)
		}
		return ips
	}
	return nil
}

func firstDevice() (string, error) {
	devs, err := pcap.FindAllDevs()
	if err != nil {
		return "", err
	}
	for _, d := range devs {
		if len(d.Addresses) > 0 && !strings.Contains(strings.ToLower(d.Description), "loopback") {
			return d.Name, nil
		}
	}
	return "", errors.New("no capture interface found")
}

func openCapture(iface string) (*pcap.Handle, error) {
	inactive, err := pcap.NewInactiveHandle(iface)
	if err != nil {
		return nil, err
	}
	defer inactive.CleanUp()
	for _, set := range []func() error{
		func() error { return inactive.SetSnapLen(pcapSnapLen) },
		func() error { return inactive.SetPromisc(true) },
		func() error { return inactive.SetTimeout(pcap.BlockForever) },
		func() error { return inactive.SetImmediateMode(true) },
	} {
		if err := set(); err != nil {
			return nil, err
		}
	}
	return inactive.Activate()
}

type captureSession struct {
	mu          sync.Mutex
	handle      *pcap.Handle
	device      string
	ips         []net.IP
	filter      string
	fixedFilter bool
	endpoints   []string
	logPackets  bool
	unknown     map[string]bool
}

var sharedCapture = &captureSession{unknown: map[string]bool{}}

func CaptureBuilt() bool { return true }

func StartPcap(cfg PcapConfig) error {
	iface := cfg.Interface
	if iface == "" {
		iface = routeDevice(cfg.Server)
	}
	if iface == "" {
		first, err := firstDevice()
		if err != nil {
			return captureHint(err)
		}
		iface = first
	}
	c := sharedCapture
	c.mu.Lock()
	defer c.mu.Unlock()
	c.logPackets = cfg.LogPackets
	if cfg.Filter != "" {
		c.filter, c.fixedFilter = cfg.Filter, true
	} else {
		c.filter, c.endpoints = configuredFilter(cfg.Server)
	}
	if err := c.openLocked(iface); err != nil {
		return err
	}
	sharedWire.start(c.follow)
	stdlog.Printf("[PCAP] capturing on %s, filter %q, %s; every failed handshake gets a wire verdict for the policy net (forged_reset, hello_dropped, cut_off, retransmitted)", iface, c.filter, pcap.Version())
	return nil
}

func (c *captureSession) openLocked(device string) error {
	h, err := openCapture(device)
	if err != nil {
		return captureHint(fmt.Errorf("open %s: %w", device, err))
	}
	if err := h.SetBPFFilter(c.filter); err != nil {
		h.Close()
		return fmt.Errorf("filter %q: %w", c.filter, err)
	}
	if c.handle != nil {
		c.handle.Close()
	}
	c.handle, c.device, c.ips = h, device, deviceIPs(device)
	sharedWire.linkTo(h.LinkType())
	go c.read(h, c.logPackets)
	return nil
}

func (c *captureSession) read(h *pcap.Handle, logPackets bool) {
	defer h.Close()
	for pkt := range gopacket.NewPacketSource(h, h.LinkType()).Packets() {
		if logPackets {
			logPacket(pkt)
		}
		sharedWire.see(pkt)
	}
}

func (c *captureSession) follow(local, remote *net.TCPAddr) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.fixedFilter {
		if endpoints, added := addEndpoint(c.endpoints, remote.String()); added {
			c.endpoints, c.filter = endpoints, endpointFilter(endpoints)
			if err := c.handle.SetBPFFilter(c.filter); err != nil {
				stdlog.Printf("[PCAP] could not widen the filter to %s: %v", remote, err)
			} else {
				stdlog.Printf("[PCAP] the client dials %s, filter now %q", remote, c.filter)
			}
		}
	}
	for _, ip := range c.ips {
		if ip.Equal(local.IP) {
			return
		}
	}
	device := deviceWithIP(local.IP)
	if device == "" {
		if !c.unknown[local.IP.String()] {
			c.unknown[local.IP.String()] = true
			stdlog.Printf("[PCAP] no capture device holds %s, the tunnel's flows from it go unseen", local.IP)
		}
		return
	}
	if err := c.openLocked(device); err != nil {
		stdlog.Printf("[PCAP] the route to the server moved to %s but capture could not follow: %v", device, err)
		return
	}
	stdlog.Printf("[PCAP] the route to the server moved to %s (%s), capture followed", device, local.IP)
}

var tlsHandshakeType = map[byte]string{1: "ClientHello", 2: "ServerHello", 11: "Certificate", 16: "ClientKeyExchange", 20: "Finished"}
var tlsContentType = map[byte]string{0x14: "change_cipher_spec", 0x15: "alert", 0x16: "handshake", 0x17: "application_data"}

func logPacket(pkt gopacket.Packet) {
	tcp, ok := pkt.Layer(layers.LayerTypeTCP).(*layers.TCP)
	if !ok {
		return
	}
	src, dst, ok := packetEndpoints(pkt, tcp)
	if !ok {
		return
	}
	choice, dialFlow := sharedWire.choiceOf(src, dst)
	flow := pkt.NetworkLayer().NetworkFlow()

	fields := []string{
		"ip.src=" + flow.Src().String(), "ip.dst=" + flow.Dst().String(),
		fmt.Sprintf("tcp.srcport=%d", tcp.SrcPort), fmt.Sprintf("tcp.dstport=%d", tcp.DstPort),
		fmt.Sprintf("tcp.seq=%d", tcp.Seq), fmt.Sprintf("tcp.ack=%d", tcp.Ack),
		fmt.Sprintf("tcp.hdr_len=%d", tcp.DataOffset*4),
	}

	var names []string
	var fb int
	for _, f := range []struct {
		on  bool
		bit int
		nm  string
	}{
		{tcp.FIN, 0x001, "FIN"}, {tcp.SYN, 0x002, "SYN"}, {tcp.RST, 0x004, "RST"},
		{tcp.PSH, 0x008, "PSH"}, {tcp.ACK, 0x010, "ACK"}, {tcp.URG, 0x020, "URG"},
		{tcp.ECE, 0x040, "ECE"}, {tcp.CWR, 0x080, "CWR"}, {tcp.NS, 0x100, "NS"},
	} {
		if f.on {
			fb |= f.bit
			names = append(names, f.nm)
		}
	}
	fields = append(fields, fmt.Sprintf("tcp.flags=0x%03x[%s]", fb, strings.Join(names, ",")),
		fmt.Sprintf("tcp.len=%d", len(tcp.Payload)),
		fmt.Sprintf("tcp.window=%d", tcp.Window),
		fmt.Sprintf("tcp.checksum=0x%04x", tcp.Checksum),
		fmt.Sprintf("tcp.urgent=%d", tcp.Urgent))

	var opts []string
	for _, o := range tcp.Options {
		opts = append(opts, o.OptionType.String())
	}
	if len(opts) > 0 {
		fields = append(fields, "tcp.options="+strings.Join(opts, "+"))
	}

	if ip := pkt.Layer(layers.LayerTypeIPv4); ip != nil {
		v := ip.(*layers.IPv4)
		df := "0"
		if v.Flags&layers.IPv4DontFragment != 0 {
			df = "1"
		}
		fields = append(fields,
			fmt.Sprintf("ip.ttl=%d", v.TTL), fmt.Sprintf("ip.id=%d", v.Id),
			"ip.flags.df="+df, fmt.Sprintf("ip.len=%d", v.Length), fmt.Sprintf("ip.dsfield=0x%02x", v.TOS))
	}

	if p := tcp.Payload; len(p) >= 5 {
		if ct, ok := tlsContentType[p[0]]; ok {
			recLen := int(p[3])<<8 | int(p[4])
			lenField := fmt.Sprintf("tls.record.length=%d", recLen)
			hello := dialFlow && p[0] == tlsRecordHandshake
			fields = append(fields, fmt.Sprintf("tls.record.content_type=%s(%d)", ct, p[0]),
				markIf(lenField, hello && choice.netRecords),
				fmt.Sprintf("tls.record.version=0x%02x%02x", p[1], p[2]))
			if p[0] == tlsRecordHandshake && len(p) >= 6 {
				if hs, ok := tlsHandshakeType[p[5]]; ok {
					fields = append(fields, markIf("tls.handshake.type="+hs, hello && p[5] == tlsClientHelloType && choice.netFingerprint))
				}
			}
		}
	}

	writePacketLine(strings.Join(fields, " "))
}
