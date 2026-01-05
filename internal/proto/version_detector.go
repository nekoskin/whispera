package proto

import (
	"whispera/internal/proto/headers"
)

// VersionDetector - определяет версию протокола и поддерживает обратную совместимость
type VersionDetector struct {
	preferV2 bool // Предпочитать V2 протокол
}

// NewVersionDetector создает детектор версий
func NewVersionDetector(preferV2 bool) *VersionDetector {
	return &VersionDetector{preferV2: preferV2}
}

// CanUseV2 проверяет, можно ли использовать V2 протокол
func (vd *VersionDetector) CanUseV2() bool {
	return vd.preferV2
}

// NegotiateVersion определяет версию протокола для использования
// Возвращает версию, которую можно использовать
func (vd *VersionDetector) NegotiateVersion(peerVersion byte) byte {
	// Если пир поддерживает V2 и мы предпочитаем V2, используем V2
	if peerVersion == headers.Version2 && vd.preferV2 {
		return headers.Version2
	}

	// По умолчанию используем V1 для совместимости
	if peerVersion == headers.Version {
		return headers.Version
	}

	// Если версия неизвестна, используем V1
	return headers.Version
}

// IsV2Supported проверяет поддержку V2 протокола
func IsV2Supported() bool {
	// V2 всегда поддерживается (если код скомпилирован)
	return true
}
