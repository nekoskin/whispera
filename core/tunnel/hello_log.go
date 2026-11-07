package tunnel

import (
	"fmt"
	stdlog "log"
	"strconv"
	"strings"

	utls "github.com/refraction-networking/utls"
	"golang.org/x/crypto/cryptobyte"
)

const (
	tlsRecordHandshake = 22
	tlsClientHelloType = 1
	tlsHandshakeHeader = 4
)

const netChoiceMark = "-n"

var curveNames = map[utls.CurveID]string{
	utls.X25519:             "x25519",
	utls.CurveP256:          "secp256r1",
	utls.CurveP384:          "secp384r1",
	utls.CurveP521:          "secp521r1",
	utls.X25519MLKEM768:     "X25519MLKEM768",
	utls.SecP256r1MLKEM768:  "SecP256r1MLKEM768",
	utls.SecP384r1MLKEM1024: "SecP384r1MLKEM1024",
}

func clientStream(segs []wireSegment) []byte {
	var stream []byte
	var next uint32
	started := false
	for _, s := range segs {
		payload := s.tcp.Payload
		if s.inbound || len(payload) == 0 {
			continue
		}
		if !started {
			next, started = s.tcp.Seq, true
		}
		if seqAfter(s.tcp.Seq, next) {
			break
		}
		skip := next - s.tcp.Seq
		if int(skip) >= len(payload) {
			continue
		}
		stream = append(stream, payload[skip:]...)
		next = s.tcp.Seq + uint32(len(payload))
	}
	return stream
}

func assembleHello(segs []wireSegment) ([]byte, int, int, bool) {
	sent := clientStream(segs)
	stream := cryptobyte.String(sent)
	var message []byte
	var version uint16
	records := 0
	for {
		var kind uint8
		var recordVersion uint16
		var body cryptobyte.String
		if !stream.ReadUint8(&kind) || !stream.ReadUint16(&recordVersion) || !stream.ReadUint16LengthPrefixed(&body) {
			return nil, 0, 0, false
		}
		if kind != tlsRecordHandshake {
			return nil, 0, 0, false
		}
		if records == 0 {
			version = recordVersion
		}
		records++
		message = append(message, body...)
		if len(message) < tlsHandshakeHeader {
			continue
		}
		if message[0] != tlsClientHelloType {
			return nil, 0, 0, false
		}
		size := tlsHandshakeHeader + (int(message[1])<<16 | int(message[2])<<8 | int(message[3]))
		if len(message) < size {
			continue
		}
		var record cryptobyte.Builder
		record.AddUint8(tlsRecordHandshake)
		record.AddUint16(version)
		record.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes(message[:size]) })
		hello, err := record.Bytes()
		if err != nil {
			return nil, 0, 0, false
		}
		return hello, records, len(sent) - len(stream), true
	}
}

func markIf(field string, set bool) string {
	if set {
		return field + netChoiceMark
	}
	return field
}

func curveName(id utls.CurveID) string {
	if name, ok := curveNames[id]; ok {
		return name
	}
	return "0x" + strconv.FormatUint(uint64(id), 16)
}

func helloGroups(spec *utls.ClientHelloSpec) (groups, shares []string) {
	for _, ext := range spec.Extensions {
		switch e := ext.(type) {
		case *utls.SupportedCurvesExtension:
			for _, c := range e.Curves {
				groups = append(groups, curveName(c))
			}
		case *utls.KeyShareExtension:
			for _, k := range e.KeyShares {
				shares = append(shares, curveName(k.Group))
			}
		}
	}
	return groups, shares
}

func describeHello(hello []byte, records int, choice dialChoice) (string, error) {
	spec, err := (&utls.Fingerprinter{AllowBluntMimicry: true}).FingerprintClientHello(hello)
	if err != nil {
		return "", err
	}
	var fields []string
	if choice.netFingerprint {
		fields = append(fields, "tls.handshake.fingerprint="+choice.fingerprint)
	}
	if choice.netRecords {
		fields = append(fields, fmt.Sprintf("tls.record.count=%d", records))
	}
	if choice.netDropPQ {
		_, shares := helloGroups(spec)
		fields = append(fields, "tls.handshake.extensions_key_share_group="+strings.Join(shares, ","))
	}
	return strings.Join(fields, " "), nil
}

func logHello(src, dst string, hello []byte, records int, choice dialChoice) {
	fields, err := describeHello(hello, records, choice)
	if err != nil {
		stdlog.Printf("[PCAP] hello %s > %s could not be read: %v", src, dst, err)
		return
	}
	if fields != "" {
		stdlog.Printf("[PCAP] hello %s > %s set by the policy net: %s", src, dst, fields)
	}
}
