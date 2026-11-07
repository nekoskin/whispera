package fingerprint

import (
	"os"
	"path/filepath"
	"sync"

	utls "github.com/refraction-networking/utls"
)

var collectOnce sync.Once

var (
	collectDirMu       sync.RWMutex
	collectDirOverride string
)

func SetCollectDir(dir string) {
	collectDirMu.Lock()
	collectDirOverride = dir
	collectDirMu.Unlock()
}

func collectDirPath() string {
	collectDirMu.RLock()
	d := collectDirOverride
	collectDirMu.RUnlock()
	if d != "" {
		return d
	}
	return os.Getenv("WHISPERA_FP_DIR")
}

func CollectRawClientHello(record []byte) error {
	fp := &utls.Fingerprinter{AllowBluntMimicry: true}
	spec, err := fp.FingerprintClientHello(record)
	if err != nil {
		return err
	}
	AddCollected(spec, record)
	return nil
}

func persistFingerprint(key string, raw []byte) {
	dir := collectDirPath()
	if dir == "" || len(raw) == 0 {
		return
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return
	}
	path := filepath.Join(dir, key+".bin")
	if _, err := os.Stat(path); err == nil {
		return
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return
	}
	_ = os.Rename(tmp, path)
}

func LoadCollectDir(dir string) (int, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return 0, err
	}
	n := 0
	for _, e := range entries {
		if e.IsDir() || filepath.Ext(e.Name()) != ".bin" {
			continue
		}
		data, rerr := os.ReadFile(filepath.Join(dir, e.Name()))
		if rerr != nil {
			continue
		}
		if CollectRawClientHello(data) == nil {
			n++
		}
	}
	return n, nil
}

func initCollect() {
	loadSeedFingerprints()
	dir := collectDirPath()
	if dir == "" {
		return
	}
	_, _ = LoadCollectDir(dir)
}
