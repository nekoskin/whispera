//go:build !pcap && !(windows && (amd64 || 386))

package tunnel

import "errors"

func CaptureBuilt() bool { return false }

func StartPcap(PcapConfig) error { return errors.New("packet capture is not in this build") }

func LogCaptureDevices() {}
