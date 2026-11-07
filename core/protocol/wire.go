package protocol

import (
	"math"
	"strconv"
	"strings"
	"time"
)

type WireVerdict int

const (
	WireNoSignature WireVerdict = iota
	WireForgedReset
	WireHelloDropped
	WireCutOff
	WireRetransmitted
	wireVerdictCount
)

const polWireDims = int(wireVerdictCount) - 1

var wireVerdictNames = [wireVerdictCount]string{"none", "forged_reset", "hello_dropped", "cut_off", "retransmitted"}

func (v WireVerdict) String() string {
	if !v.valid() {
		return wireVerdictNames[WireNoSignature]
	}
	return wireVerdictNames[v]
}

func (v WireVerdict) valid() bool { return v >= 0 && v < wireVerdictCount }

func (v WireVerdict) feature() int {
	if v <= WireNoSignature || v >= wireVerdictCount {
		return -1
	}
	return int(v) - 1
}

func (v WireVerdict) Blocked() bool { return v == WireForgedReset }

func ParseWireVerdict(name string) WireVerdict {
	for v, n := range wireVerdictNames {
		if n == name {
			return WireVerdict(v)
		}
	}
	return WireNoSignature
}

type DialMeasure struct {
	Captured      bool          `json:"c,omitempty"`
	HelloBytes    int           `json:"hb,omitempty"`
	HelloSegments int           `json:"hs,omitempty"`
	HelloAcked    int           `json:"ha,omitempty"`
	Retransmits   int           `json:"rt,omitempty"`
	Reset         bool          `json:"r,omitempty"`
	ResetAfter    time.Duration `json:"ra,omitempty"`
	ResetTTL      int           `json:"rl,omitempty"`
	ServerTTL     int           `json:"sl,omitempty"`
	Connect       time.Duration `json:"cn,omitempty"`
	LiveDown      int64         `json:"ld,omitempty"`
	LiveFor       time.Duration `json:"lf,omitempty"`
	Packets       []WirePacket  `json:"p,omitempty"`
	ChainPos      int           `json:"cp,omitempty"`
	ChainGap      time.Duration `json:"cg,omitempty"`
	Tail          []WirePacket  `json:"tp,omitempty"`
}

type WirePacket struct {
	Inbound bool          `json:"i,omitempty"`
	Size    int           `json:"s,omitempty"`
	Gap     time.Duration `json:"g,omitempty"`
	Flags   uint8         `json:"f,omitempty"`
	TTL     int           `json:"t,omitempty"`
	Window  int           `json:"w,omitempty"`
	Record  uint8         `json:"r,omitempty"`
	RecLen  int           `json:"l,omitempty"`
	SeqGap  int64         `json:"sd,omitempty"`
	AckGap  int64         `json:"ad,omitempty"`
	MSS     int           `json:"ms,omitempty"`
	WScale  int           `json:"ws,omitempty"`
	Options uint8         `json:"o,omitempty"`
	Records int           `json:"n,omitempty"`
	Hello   uint8         `json:"h,omitempty"`
	Alert   uint8         `json:"a,omitempty"`
}

const (
	WireSYN uint8 = 1 << iota
	WireACK
	WireRST
	WireFIN
	WirePSH
	WireURG
	WireECE
	WireCWR
	wireFlagCount = iota
)

const (
	WireOptWScale uint8 = 1 << iota
	WireOptSACK
	WireOptTimestamps
)

const (
	tlsClientHello = 1
	tlsServerHello = 2
	tlsAlertFatal  = 2
)

var wireRecordTypes = [...]uint8{20, 21, 22, 23}

const (
	WirePacketsMax     = 50
	wireOrderDims      = 2
	wireOptionDims     = 4
	wireTLSDims        = 4
	polPacketDims      = 4 + wireFlagCount + len(wireRecordTypes) + 2 + wireOrderDims + wireOptionDims + wireTLSDims
	packetSeqGapCap    = 1 << 16
	packetMSSCap       = 1 << 16
	packetWScaleMax    = 14
	packetRecordsCap   = 16
	polMeasDims        = 4 + polChainDims
	polChainDims       = 2
	chainPosCap        = 16
	chainGapCap        = 2 * time.Second
	measHelloBytesCap  = 1 << 14
	measTTLScale       = 64
	measConnectCap     = 10 * time.Second
	measLiveDownCap    = 1 << 24
	measLiveForCap     = 10 * time.Minute
	packetGapCap       = 10 * time.Second
	packetWindowCap    = 1 << 16
	wirePacketLegacy   = 8
	wirePacketFields   = 16
	wirePacketSep      = "/"
	wirePacketFieldSep = ":"
)

func logScale(x, limit float64) float64 {
	if x <= 0 {
		return 0
	}
	return math.Min(math.Log2(1+x)/math.Log2(1+limit), 1)
}

func indicator(set bool) float64 {
	if set {
		return 1
	}
	return 0
}

func (m DialMeasure) features() [polMeasDims]float64 {
	chain := m.chainFeatures()
	return [polMeasDims]float64{
		indicator(len(m.Packets) > 0),
		logScale(float64(m.Connect.Milliseconds()), float64(measConnectCap.Milliseconds())),
		logScale(float64(m.LiveDown), measLiveDownCap),
		logScale(float64(m.LiveFor.Milliseconds()), float64(measLiveForCap.Milliseconds())),
		chain[0], chain[1],
	}
}

func (m DialMeasure) chainFeatures() [polChainDims]float64 {
	return chainFeatures(m.ChainPos, m.ChainGap)
}

func chainFeatures(pos int, gap time.Duration) [polChainDims]float64 {
	since := 1.0
	if gap > 0 {
		since = logScale(float64(gap.Milliseconds()), float64(chainGapCap.Milliseconds()))
	}
	return [polChainDims]float64{logScale(float64(pos), chainPosCap), since}
}

func packetFeatures(pkts []WirePacket) [][]float64 {
	serverTTL := 0
	for _, p := range pkts {
		if p.Inbound && p.Flags&WireRST == 0 && p.TTL > 0 {
			serverTTL = p.TTL
			break
		}
	}
	out := make([][]float64, len(pkts))
	for i, p := range pkts {
		f := make([]float64, 0, polPacketDims)
		f = append(f, indicator(p.Inbound),
			logScale(float64(p.Size), measHelloBytesCap),
			logScale(float64(p.Gap.Microseconds()), float64(packetGapCap.Microseconds())))
		ttl := 0.0
		if p.Inbound && serverTTL > 0 && p.TTL > 0 {
			ttl = math.Max(-1, math.Min(1, float64(p.TTL-serverTTL)/measTTLScale))
		}
		f = append(f, ttl)
		for bit := 0; bit < wireFlagCount; bit++ {
			f = append(f, indicator(p.Flags&(1<<bit) != 0))
		}
		for _, typ := range wireRecordTypes {
			f = append(f, indicator(p.Record == typ))
		}
		f = append(f, logScale(float64(p.RecLen), measHelloBytesCap), logScale(float64(p.Window), packetWindowCap))
		f = append(f, signedLogScale(float64(p.SeqGap), packetSeqGapCap), signedLogScale(float64(p.AckGap), packetSeqGapCap))
		wscale := 0.0
		if p.Options&WireOptWScale != 0 {
			wscale = math.Min(float64(p.WScale), packetWScaleMax) / packetWScaleMax
		}
		f = append(f, logScale(float64(p.MSS), packetMSSCap), wscale,
			indicator(p.Options&WireOptSACK != 0), indicator(p.Options&WireOptTimestamps != 0))
		f = append(f, logScale(float64(p.Records), packetRecordsCap),
			indicator(p.Hello == tlsClientHello), indicator(p.Hello == tlsServerHello), indicator(p.Alert == tlsAlertFatal))
		out[i] = f
	}
	return out
}

func signedLogScale(x, limit float64) float64 {
	if x < 0 {
		return -logScale(-x, limit)
	}
	return logScale(x, limit)
}

func EncodeWirePackets(pkts []WirePacket) string {
	parts := make([]string, len(pkts))
	for i, p := range pkts {
		dir := "o"
		if p.Inbound {
			dir = "i"
		}
		parts[i] = strings.Join([]string{dir, strconv.Itoa(p.Size), strconv.FormatInt(p.Gap.Microseconds(), 10),
			strconv.Itoa(int(p.Flags)), strconv.Itoa(p.TTL), strconv.Itoa(p.Window), strconv.Itoa(int(p.Record)), strconv.Itoa(p.RecLen),
			strconv.FormatInt(p.SeqGap, 10), strconv.FormatInt(p.AckGap, 10), strconv.Itoa(p.MSS), strconv.Itoa(p.WScale),
			strconv.Itoa(int(p.Options)), strconv.Itoa(p.Records), strconv.Itoa(int(p.Hello)), strconv.Itoa(int(p.Alert))}, wirePacketFieldSep)
	}
	return strings.Join(parts, wirePacketSep)
}

const (
	wireSeqGapField = 8
	wireAckGapField = 9
)

func ParseWirePackets(s string) []WirePacket {
	if s == "" {
		return nil
	}
	var out []WirePacket
	for _, part := range strings.Split(s, wirePacketSep) {
		fields := strings.Split(part, wirePacketFieldSep)
		if (len(fields) != wirePacketFields && len(fields) != wirePacketLegacy) || (fields[0] != "i" && fields[0] != "o") {
			return nil
		}
		n := make([]int64, wirePacketFields)
		for i, v := range fields {
			if i == 0 {
				continue
			}
			x, err := strconv.ParseInt(v, 10, 64)
			if err != nil || (x < 0 && i != wireSeqGapField && i != wireAckGapField) {
				return nil
			}
			n[i] = x
		}
		out = append(out, WirePacket{Inbound: fields[0] == "i", Size: int(n[1]), Gap: time.Duration(n[2]) * time.Microsecond,
			Flags: uint8(n[3]), TTL: int(n[4]), Window: int(n[5]), Record: uint8(n[6]), RecLen: int(n[7]),
			SeqGap: n[8], AckGap: n[9], MSS: int(n[10]), WScale: int(n[11]), Options: uint8(n[12]), Records: int(n[13]),
			Hello: uint8(n[14]), Alert: uint8(n[15])})
		if len(out) == WirePacketsMax {
			break
		}
	}
	return out
}

func (m DialMeasure) valid() bool {
	if len(m.Packets) > WirePacketsMax || len(m.Tail) > WirePacketsMax {
		return false
	}
	for _, p := range append(append([]WirePacket(nil), m.Packets...), m.Tail...) {
		if p.Size < 0 || p.Gap < 0 || p.TTL < 0 || p.Window < 0 || p.RecLen < 0 || p.MSS < 0 || p.WScale < 0 || p.Records < 0 {
			return false
		}
	}
	return m.ChainPos >= 0 && m.ChainGap >= 0 && m.HelloBytes >= 0 && m.HelloSegments >= 0 && m.HelloAcked >= 0 && m.Retransmits >= 0 &&
		m.ResetAfter >= 0 && m.ResetTTL >= 0 && m.ServerTTL >= 0 && m.Connect >= 0 && m.LiveDown >= 0 && m.LiveFor >= 0
}
