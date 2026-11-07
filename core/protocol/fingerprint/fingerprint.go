package fingerprint

import (
	"encoding/binary"
	"encoding/hex"
	logger "github.com/nekoskin/whispera/common/log"
	"hash/fnv"
	mrand "math/rand"
	"net"
	"os"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/nekoskin/whispera/core/protocol/camo"

	utls "github.com/refraction-networking/utls"
)

var (
	collectMu    sync.RWMutex
	collectSpecs []*utls.ClientHelloSpec
	collectRaw   [][]byte
	collectSeen  = map[string]bool{}
)

const maxCollect = 32

var (
	forcedFingerprintMu sync.RWMutex
	forcedFingerprintID utls.ClientHelloID
)

func SpecFromRaw(raw []byte) (*utls.ClientHelloSpec, error) {
	fp := &utls.Fingerprinter{AllowBluntMimicry: true}
	return fp.FingerprintClientHello(raw)
}

func isPQCurve(g utls.CurveID) bool {
	return g == utls.X25519MLKEM768 || g == utls.X25519Kyber768Draft00
}

func DropPQEnabled() bool { return os.Getenv("WHISPERA_DROP_PQ") == "1" }

func DropECHEnabled() bool { return os.Getenv("WHISPERA_DROP_ECH") == "1" }

func ForcedALPN() ([]string, bool) {
	v := strings.TrimSpace(os.Getenv("WHISPERA_ALPN"))
	if v == "" {
		return nil, false
	}
	var out []string
	for _, p := range strings.Split(v, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out, len(out) > 0
}

func SetALPN(spec *utls.ClientHelloSpec, protos []string) {
	for _, ext := range spec.Extensions {
		if a, ok := ext.(*utls.ALPNExtension); ok {
			a.AlpnProtocols = protos
			return
		}
	}
	spec.Extensions = append(spec.Extensions, &utls.ALPNExtension{AlpnProtocols: protos})
}

func DropECH(spec *utls.ClientHelloSpec) {
	kept := spec.Extensions[:0]
	for _, ext := range spec.Extensions {
		switch e := ext.(type) {
		case *utls.GREASEEncryptedClientHelloExtension:
			continue
		case *utls.GenericExtension:
			if e.Id == 0xfe0d {
				continue
			}
		}
		kept = append(kept, ext)
	}
	spec.Extensions = kept
}

func DropPQKeyShares(spec *utls.ClientHelloSpec) {
	for _, ext := range spec.Extensions {
		switch e := ext.(type) {
		case *utls.KeyShareExtension:
			kept := e.KeyShares[:0]
			for _, k := range e.KeyShares {
				if isPQCurve(k.Group) {
					continue
				}
				if k.Group != utls.GREASE_PLACEHOLDER && len(k.Data) > 0 {
					k.Data = nil
				}
				kept = append(kept, k)
			}
			e.KeyShares = kept
		case *utls.SupportedCurvesExtension:
			kept := e.Curves[:0]
			for _, c := range e.Curves {
				if !isPQCurve(c) {
					kept = append(kept, c)
				}
			}
			e.Curves = kept
		}
	}
	ensurePadding(spec)
}

func ensurePadding(spec *utls.ClientHelloSpec) {
	for _, ext := range spec.Extensions {
		if _, ok := ext.(*utls.UtlsPaddingExtension); ok {
			return
		}
	}
	pad := &utls.UtlsPaddingExtension{GetPaddingLen: utls.BoringPaddingStyle}
	for i, ext := range spec.Extensions {
		if _, ok := ext.(utls.PreSharedKeyExtension); ok {
			spec.Extensions = slices.Insert(spec.Extensions, i, utls.TLSExtension(pad))
			return
		}
	}
	spec.Extensions = append(spec.Extensions, pad)
}

var namedFingerprints = map[string]utls.ClientHelloID{
	"chrome":      utls.HelloChrome_Auto,
	"chrome_120":  utls.HelloChrome_120,
	"chrome_115":  utls.HelloChrome_115_PQ,
	"firefox":     utls.HelloFirefox_Auto,
	"firefox_120": utls.HelloFirefox_120,
	"safari":      utls.HelloSafari_Auto,
	"ios":         utls.HelloIOS_Auto,
	"android":     utls.HelloAndroid_11_OkHttp,
	"edge":        utls.HelloEdge_Auto,
}

func IsKnown(name string) bool {
	if name == "random" {
		return true
	}
	_, ok := namedFingerprints[name]
	return ok
}

func SetForced(name string) {
	id, ok := namedFingerprints[name]
	forcedFingerprintMu.Lock()
	defer forcedFingerprintMu.Unlock()
	if !ok {
		forcedFingerprintID = utls.ClientHelloID{}
		return
	}
	forcedFingerprintID = id
}

func specHandshakeReady(spec *utls.ClientHelloSpec) bool {
	if spec == nil {
		return false
	}
	c0, c1 := net.Pipe()
	defer c0.Close()
	defer c1.Close()
	u := utls.UClient(c0, &utls.Config{
		ServerName:                         "example.com",
		InsecureSkipVerify:                 true,
		PreferSkipResumptionOnNilExtension: true,
	}, utls.HelloCustom)
	if err := u.ApplyPreset(spec); err != nil {
		return false
	}
	if err := u.BuildHandshakeState(); err != nil {
		return false
	}
	hello := u.HandshakeState.Hello
	if hello == nil || len(hello.Random) != 32 {
		return false
	}
	return len(camo.ExtractX25519KeyShare(hello.KeyShares)) > 0
}

func AddCollected(spec *utls.ClientHelloSpec, raw []byte) {
	if len(raw) == 0 || !specHandshakeReady(spec) {
		return
	}
	key, keyed := collectKey(raw)

	collectMu.Lock()
	if keyed && collectSeen[key] {
		collectMu.Unlock()
		return
	}
	added := false
	if len(collectSpecs) < maxCollect {
		collectSpecs = append(collectSpecs, spec)
		collectRaw = append(collectRaw, raw)
		if keyed {
			collectSeen[key] = true
		}
		added = true
	}
	collectMu.Unlock()

	if added && keyed {
		persistFingerprint(key, raw)
	}
}

func collectKey(raw []byte) (string, bool) {
	exts, ok := clientHelloExtTypes(raw)
	if !ok {
		return "", false
	}
	norm := make([]uint16, len(exts))
	for i, t := range exts {
		if isGREASE(t) {
			t = 0x0a0a
		}
		norm[i] = t
	}
	sort.Slice(norm, func(i, j int) bool { return norm[i] < norm[j] })

	h := fnv.New64a()
	var b [2]byte
	for _, t := range norm {
		binary.BigEndian.PutUint16(b[:], t)
		_, _ = h.Write(b[:])
	}
	return strconv.FormatUint(h.Sum64(), 16), true
}

func CollectedCapacity() int {
	return maxCollect
}

func Forced() (utls.ClientHelloID, bool) {
	forcedFingerprintMu.RLock()
	defer forcedFingerprintMu.RUnlock()
	return forcedFingerprintID, forcedFingerprintID.Client != ""
}

func pick() (id utls.ClientHelloID, raw []byte) {
	if forced, ok := Forced(); ok {
		return forced, nil
	}

	collectOnce.Do(initCollect)

	if raw, ok := DeviceHello(); ok {
		return utls.HelloCustom, raw
	}

	collectMu.RLock()
	defer collectMu.RUnlock()

	if len(collectRaw) > 0 {
		i := mrand.Intn(len(collectRaw))
		return utls.HelloCustom, append([]byte(nil), collectRaw[i]...)
	}

	traceLog.Errorw("fingerprint pool empty, using emergency hello")
	return utls.HelloChrome_Auto, nil
}

var (
	helloEdge156    = utls.ClientHelloID{Client: "Edge", Version: "156"}
	helloFirefox153 = utls.ClientHelloID{Client: "Firefox", Version: "153"}
)

var presets = []utls.ClientHelloID{
	utls.HelloChrome_Auto,
	utls.HelloFirefox_Auto,
	utls.HelloSafari_Auto,
	helloEdge156,
	helloFirefox153,
}

type capturedHello struct {
	record  string
	shuffle bool
}

var capturedHellos = map[utls.ClientHelloID]capturedHello{
	helloEdge156: {shuffle: true, record: "16030106e0010006dc03030ad3e0eda3bffafae5495ff7c02c90b307914a37d59188f6b6e940ad356cab1f20b72691afd859140f312649f2a7e8b662" +
		"0d06f3d857b789f5e8ff75ae300b912800200a0a130113021303c02bc02fc02cc030cca9cca8c013c014009c009d002f0035010006733a3a0000002d" +
		"0002010100170000fe0d00da00000100018c0020c8f273e07534757812e0586db0d5e264a2e3cc3168de5b948a3302a54aed6f5100b036c6dec17da1" +
		"c732e702d8829f76315a61c2378956e86627f25d78e545504a6c015c10685e6f28186d12a2491b42284f8f495cc9772f24ef244c63f1fe0fdedcefef" +
		"f6798f174e373a43943f406da3dac177e78ce346a906d3b0172c7ffd9926c2049ce78584121150e36bc8d475207b2c69fb8b6b2a64e3ed5181f1a1c9" +
		"a5c874fc6e94477004260e6b22e0b326d68dc4efb59b1176a491fdfa207c086647f39b6515c90f760e8367b1bb14fee7202c001b0003020002000000" +
		"14001200000f7777772e6578616d706c652e636f6d000500050100000000000b00020100002b000706caca03040303003304ef04edaaaa00010011ec" +
		"04c0cfab8ea02606d0ca6ed82c336d4668c757925730374d906c7ab9c821f18aee4021f551522a862acc422f71949846bba575804fcdfb3492924f4f" +
		"45ac47a8b58828b4f4f64803eb7bb6400829771175a897dd3b93cae42efca77127d64f06864775a330781c4e5ac4a804626a5643a50ba78d45b25362" +
		"35aff96665b3e4a7cc806929a6af1a777e55167a40015532aa94bc670ae4708f427722b734c311ba88f9704931babb3a0885a01881f3794be4166b92" +
		"288bfae0068de535f1085aeed40d19189cc021756c2584f242226660bed6db816f30c724ca68709a4c39948f304786ada450e4f466edb4b16589b62d" +
		"a9c02b5c162eaba64265428be070ec309aa3c9238b31c2514519f665b6d08c324801b571517468dc82bba48edf418a649c6415b58540643bd4e6a1be" +
		"aa55ef39b65fc102aee05177118247c421c6989368d0454de075b7a02c1ab11682745b25189d0960b45db48230090604e06117649a23131f677a396c" +
		"3c33dae19e314833356b3c2c8ab85984a1180132d475b5fec353b91b50f32c66b8916977633af031b2dec2097fd98770566ad65354e605ac2bb81a65" +
		"5a317513cf5ae02d111b0149b68e771140426b88d1922dd29580d204c6371a789484bce7a01158f96dfbd16898e5cfc016a7892bcbc85b25c5198db6" +
		"2b8b7dea5e0f16899a8b94d9898c70c6c1423a01894991a9b481923884cf449babc9a0a1d3b3562c2bbf7a694679a2870945b545cd5fc35b5e18c9b2" +
		"2117f5a35a6400b15d04c0aeb56d5b21518e1baf00e540b0b182698a635f0026f24b9173e3a3c44a5e13f2693439b6734748cf1758d4510e80198e7a" +
		"a43d315452f5b324604a760dc402378ca52d47a4e420781c1825423bc09c87283256b94223a952f617fa870630036b025b0704b499d5d68cc89bc40e" +
		"0438c378aa67ea711e6a63fcc5667c708fae16b423c721428710bb003f859cc2993986f42b143cf68f78a55eabfa3bd665402f97ca8712bfbc1b581e" +
		"4cbc0787abd88580b1d55c05a99985835a9ef21b2072bebc3c422e235316b1694326b1dd703e41a805cc5189d9f958d636bd80660a6738cbc555c5b6" +
		"3b51b52302252c2501812b9cb652a4b7b0247023dfd3cfafd3a5b843547f4b00e27808a0eac8d9a43a8fe73786a48857730857a85b3f49a5c81b2333" +
		"f53741d09a6f3b4385f5bc72821badb1536c6409ec6c4f356a884d167676d8b8f6db4328120a97035bb486a432f21c8f44cbede83000c26fecb86590" +
		"4989eada7451e5a4e9138792760e7fe91161324491813e9beab4023b84f3a26e45952aa8a5033c5cbb62a83eff7a92f893ca994c7c49b892230ccadc" +
		"9a9db018991a94457318ad10948c354320ebb65038040a74f27eef506165f35eeeaca135722a35995dc0e71eb9e98eb25511327b6e596532ef571990" +
		"d4bb6879895075a844e019d875ae5e0099ea2160f6a9377425437ad24c70b14dc2415528fcc94286074f464bb18506ea9255032034ffbb7985568387" +
		"921d38c1714b836eb27bc2c8e2850291b93a62a4cf00370fc81c4fc14df217c62c580bc6a676c94a032b7068e0692c39b0418fd5048c366b76f7c4f6" +
		"c5379ca6a607b6a97b2405f2597f894fe50acffb79faca569af8e5edc3b742035c81276b1ab5cf392d9e74e24e4b86c5ac524aa9e5ec1929a5dfa325" +
		"900a6faa2b15c07ad515182f4d81e8b4c911001d00204dcf48c091c6d9c68bbc78e9b13bae58ec61da8b485f934182f0fa288862ce07000d001a0018" +
		"0a0a09040905090604030804040105030805050108060601000a000c000aaaaa11ec001d001700180012000044cd0005000302683200230000001000" +
		"0e000c02683208687474702f312e31ff010001001a1a000100"},
	helloFirefox153: {record: "160301076501000761030369cc3b6de6d8e9198ac5796512a7386cf5716d71932e6bb255d1b681fea2746a20c38fca371df5def78146bf2436dd1581" +
		"76e754c55886f1a3f8c97f00fea0147e0020130113031302c02bc02fcca9cca8c02cc030c00ac013c014009c009d002f0035010006f8000000140012" +
		"00000f7777772e6578616d706c652e636f6d00170000ff01000100000a0010000e11ec001d00170018001901000101000b0002010000230000001000" +
		"0e000c02683208687474702f312e310005000501000000000022000a00080403050306030203001200000033052f052d11ec04c0275225ec3b6fe609" +
		"41658ac8b5675c8c33388b85bfc3524b45d88f6dd074e30b2cce59af7d212010b409217cad820bcfee2a5c4a20b16f809688a64df7a8534c780c7376" +
		"c5c033b33b64cd9e89c293ea87c6b408da8109eef4a5ff00a43a780aead1944d412d5189588be800231c1558735c4cb22a2b3510b8579f9ae2b704d0" +
		"94fbe9920c6c2dff56405d201a756c9b91e9a37cfa7d6ec8270016ccb0163b88060543517086862339d153e4d789a0fb786835868231756b297179b0" +
		"5818c38b6599b2027cb55fa815cf1304b7ec4a7926cfb1252f90b965cc49283f651e4654083366444f514d15360e1031b1e8846c4dd75f4228ab0847" +
		"bc0740c354e519a0a26a900a07632cb4239c3dad9b7b1e238f9d7914a58c6292d68226fb530189591153b0122c9910d94409209170a6a1f41a73efc3" +
		"65af3b59607b8f45c14f7dd97eff540391c66a6793a0f3675a9d6b55e068062a551fba4c18f7406f5edb8e8cc9a2a176af0607d03f7212544124ece6" +
		"39d71219e33c1b2ff663269919513bba7da2a1066776c5951d1299a1b70c5f4fc12359c4478b3c243b8c5494f40bed78a067ec4954423e53d2605ba9" +
		"70d6da6b887c3b721722fbdc36fe0cc9fe4706bbb24fc13a109641b61bb2cf13993440639ab0844ee9b97b2f4a45f2ccc65919267539a4f784326c97" +
		"521129147facc4b0ea26927630bf4c3cca63aa4ddc42b7669a06f36f145299ab382f1010594d70b696e167ada41eb6eb14fc91210bbc6889c48036f6" +
		"83115b6dd061b794c970ac72c476685e45f55992c69d98d283c60c924bf12e06cc776e6929351320ab347d7f911b1cb215a64854af1604983ccd6c01" +
		"74a6ebb82f4a860b501f1d287c4c9a907526c5b1802e5bf261da5981d3f96c4fbcb68a29bb21b367a9e1a5ad222db3a43defac479a08b06901156b37" +
		"3127a757ec978697eb4d37eb14daea630f83374bc9047b1b35eb699f20e942eaa59e560378eed90a4fa8138a6ca88d4c5120793a615b604a7a0977ac" +
		"273a053cf08b865a202804b525d1db47092797032ba50a89aa667944164c13d115923a1237899a47d82c8250559913d57bd304b72f33732a7982fe60" +
		"01b6157afdcbbcafb54547fb78c4788fbcf8234849741fb3557a1c13ec7561d3a30fc0eabafbe05632849a8094046038511ed216e142b4454cacb9c1" +
		"3ad0196ef14b98da00c9f3c0a1cf24454f6cae64a518b6843363f16039741b827a247117398450ce51a51c0a2672ecd08d9060c86094b6fd4894de5b" +
		"a1739c8a6c9b61b85727e947383d19a7d311263610707dc831a9b90e05f345445cc826eba940c2a0d5da4c31419554957d9bf3af1bba3be703bf3cdb" +
		"31c0450904b60cf5c0c7b6a56614965da2e773502537434a07e3819647c311768bbb1aea451f9190bd832f70d5b1506a8add0593dad35698fa37fef6" +
		"c9bf9aa587d440e7a21cc40891feb61e6440069dd96601e279e4f4b602c0ad0c72af65817d77056b6d78a270abc755392767fb6b08d2435ea40814b4" +
		"bec048a2805ba9574617d9a130f5018a5509c55f8a1b88e99298e8c30c9194bec159e6174d35e0a1c38aadb3766e6112a173057030f78072c3119d4a" +
		"3bcbeb91db54c6fdc25bf6e9775ae35adf99a144ff49bdcec9b2966d116d9b5f27f212b362d2de43a6d950caccc33a52fa9a82c8d61f953d845f7ceb" +
		"042fb1ea84012f1e001d002062d2de43a6d950caccc33a52fa9a82c8d61f953d845f7ceb042fb1ea84012f1e0017004104f83f98c7595d621384428e" +
		"4224924c73378fd7522aa525adf52be0a9a98f48f41c59b28613ddbf3540788bc62690ba6c7bae453a13860591a0bdc308dc76c20e002b0005040304" +
		"0303000d0018001604030503060308040805080604010501060102030201002d00020101001c00024001001b000706000100020003fe0d0119000001" +
		"000330002015a925a4b4e0de89578dc8cf0e3b5580405d94121a7c519fe71a7ee103da43ba00ef8fd04ce6c972980c06f00be26d8b6e91cbe188ef11" +
		"8206343b7aa97e73aaa3b72103d8e8c4b6f1b8c20c3c600c45679b6dfd82f2fdf8e94d5a798e64775e70f3ab60d8d1b23b8fbadeaa468b9cbbeeecd2" +
		"f98afffeef73049d78851116bae957471ff1854cc953bf5518f63e61d472f400ac77e250aa527ddf2c9061ab9145e34d35fc09742c2660551b362694" +
		"cb75260ce876697bd47ce51431d218d1c423d08480a0f2428daa9b0efa24de63ccdb4be96ba2b114875258555ac2c2279e1511bf8259950fe7fba03f" +
		"32a6041c2de9e02464ee0c52fba9f0b30fb2effb00a83fc54fd1cfc69144d580608aa5da9d89"},
}

func SpecFor(id utls.ClientHelloID) (*utls.ClientHelloSpec, error) {
	captured, ok := capturedHellos[id]
	if !ok {
		spec, err := utls.UTLSIdToSpec(id)
		return &spec, err
	}
	raw, err := hex.DecodeString(captured.record)
	if err != nil {
		return nil, err
	}
	spec, err := SpecFromRaw(raw)
	if err != nil {
		return nil, err
	}
	for _, ext := range spec.Extensions {
		if sni, ok := ext.(*utls.SNIExtension); ok {
			sni.ServerName = ""
		}
	}
	if captured.shuffle {
		spec.Extensions = utls.ShuffleChromeTLSExtensions(spec.Extensions)
	}
	return spec, nil
}

func PresetCount() int { return len(presets) }

func PresetIndex(id utls.ClientHelloID) (int, bool) {
	i := slices.Index(presets, id)
	return i, i >= 0
}

func PresetAt(i int) utls.ClientHelloID {
	if i < 0 || i >= len(presets) {
		return utls.HelloChrome_Auto
	}
	return presets[i]
}

func PoolSize() int {
	collectOnce.Do(initCollect)
	collectMu.RLock()
	defer collectMu.RUnlock()
	return len(collectRaw)
}

func RawAt(i int) []byte {
	collectOnce.Do(initCollect)
	collectMu.RLock()
	defer collectMu.RUnlock()
	if i < 0 || i >= len(collectRaw) {
		return nil
	}
	return append([]byte(nil), collectRaw[i]...)
}

var (
	sessionFPOnce sync.Once
	sessionFPID   utls.ClientHelloID
	sessionFPRaw  []byte
)

func Session() (utls.ClientHelloID, []byte) {
	if forced, ok := Forced(); ok {
		return forced, nil
	}

	sessionFPOnce.Do(func() {
		sessionFPID, sessionFPRaw = pick()
	})
	return sessionFPID, append([]byte(nil), sessionFPRaw...)
}

func isGREASE(v uint16) bool {
	return byte(v>>8) == byte(v) && v&0x0f0f == 0x0a0a
}

func clientHelloExtTypes(raw []byte) ([]uint16, bool) {
	b := raw
	if len(b) >= 5 && b[0] == 0x16 {
		b = b[5:]
	}
	if len(b) < 4 || b[0] != 0x01 {
		return nil, false
	}
	b = b[4:]

	if len(b) < 34 {
		return nil, false
	}
	b = b[34:]

	if len(b) < 1 || len(b) < 1+int(b[0]) {
		return nil, false
	}
	b = b[1+int(b[0]):]

	if len(b) < 2 {
		return nil, false
	}
	csLen := int(b[0])<<8 | int(b[1])
	if len(b) < 2+csLen {
		return nil, false
	}
	b = b[2+csLen:]

	if len(b) < 1 || len(b) < 1+int(b[0]) {
		return nil, false
	}
	b = b[1+int(b[0]):]

	if len(b) < 2 {
		return nil, false
	}
	extTotal := int(b[0])<<8 | int(b[1])
	b = b[2:]
	if len(b) < extTotal {
		extTotal = len(b)
	}
	b = b[:extTotal]

	var types []uint16
	for len(b) >= 4 {
		t := uint16(b[0])<<8 | uint16(b[1])
		l := int(b[2])<<8 | int(b[3])
		types = append(types, t)
		if len(b) < 4+l {
			break
		}
		b = b[4+l:]
	}
	return types, true
}

var traceLog = logger.Trace()
