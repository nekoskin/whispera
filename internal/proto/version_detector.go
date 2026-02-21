package proto

import (
	"whispera/internal/proto/headers"
)

type VersionDetector struct {
	preferV2 bool
}

func NewVersionDetector(preferV2 bool) *VersionDetector {
	return &VersionDetector{preferV2: preferV2}
}

func (vd *VersionDetector) CanUseV2() bool {
	return vd.preferV2
}

func (vd *VersionDetector) NegotiateVersion(peerVersion byte) byte {
	if peerVersion == headers.Version2 && vd.preferV2 {
		return headers.Version2
	}

	if peerVersion == headers.Version {
		return headers.Version
	}

	return headers.Version
}

func IsV2Supported() bool {
	return true
}
