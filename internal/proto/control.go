package proto

const (
	CtrlKeepAlive byte = 0x01
	CtrlRekey     byte = 0x02
	CtrlPing      byte = 0x03
	CtrlPong      byte = 0x04
	CtrlFrag      byte = 0x05
	CtrlAuth      byte = 0x06
	CtrlAck       byte = 0x07
	CtrlNack      byte = 0x08
)
