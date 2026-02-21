package containers

type MPEGTSWrapper struct {
	packer *Packer
	parser *Parser
}

func NewMPEGTSWrapper() ContainerWrapper {
	return &MPEGTSWrapper{
		packer: NewPacker(0x100),
		parser: NewParser(0x100),
	}
}

func (w *MPEGTSWrapper) ContentType() string {
	return "video/mp2t"
}

func (w *MPEGTSWrapper) GetInitSegment() ([]byte, error) {
	return []byte{}, nil
}

func (w *MPEGTSWrapper) WrapData(data []byte) ([]byte, error) {
	return w.packer.WrapData(data), nil
}

func (w *MPEGTSWrapper) UnwrapData(data []byte) ([]byte, error) {
	return w.parser.UnwrapData(data)
}
