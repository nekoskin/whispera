package containers

type LegacyWrapper struct {
	fmtType ContainerType
}

func NewLegacyWrapper(t ContainerType) ContainerWrapper {
	return &LegacyWrapper{fmtType: t}
}

func (w *LegacyWrapper) ContentType() string {
	switch w.fmtType {
	case FormatAVI:
		return "video/x-msvideo"
	case FormatWMV:
		return "video/x-ms-wmv"
	case FormatFLV:
		return "video/x-flv"
	default:
		return "application/octet-stream"
	}
}

func (w *LegacyWrapper) GetInitSegment() ([]byte, error) {
	switch w.fmtType {
	case FormatAVI:
		return []byte{
			'R', 'I', 'F', 'F',
			0xFF, 0xFF, 0xFF, 0xFF,
			'A', 'V', 'I', ' ',
			'L', 'I', 'S', 'T',
			0, 0, 0, 200,
			'h', 'd', 'r', 'l',
		}, nil
	case FormatFLV:
		return []byte{
			'F', 'L', 'V',
			0x01,
			0x05,
			0, 0, 0, 9,
			0, 0, 0, 0,
		}, nil
	default:
		return []byte{}, nil
	}
}

func (w *LegacyWrapper) WrapData(data []byte) ([]byte, error) {
	if w.fmtType == FormatFLV {
		return data, nil
	}
	return data, nil
}

func (w *LegacyWrapper) UnwrapData(data []byte) ([]byte, error) {
	return data, nil
}
