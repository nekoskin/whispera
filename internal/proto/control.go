package proto

const (
	CtrlKeepAlive byte = 0x01
	CtrlRekey     byte = 0x02 // payload: 32-byte salt
	CtrlPing      byte = 0x03 // payload: 8-byte unix nano timestamp
	CtrlPong      byte = 0x04 // payload: 8-byte unix nano timestamp (echo)
	CtrlFrag      byte = 0x05 // payload: [FragID(4)|FragIdx(2)|FragCnt(2)|chunk]
	CtrlAuth      byte = 0x06 // payload: UTF-8 token/UUID
	CtrlAck       byte = 0x07 // payload: [Seq(4)] - подтверждение получения пакета с seq
	CtrlNack      byte = 0x08 // payload: [Seq(4)] - не подтверждение (пакет потерян)
)
