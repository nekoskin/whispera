package containers

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"time"
)

type fMP4Wrapper struct {
	sequenceNumber uint32
	startTime      time.Time
}

func NewFMP4Wrapper() ContainerWrapper {
	return &fMP4Wrapper{
		sequenceNumber: 1,
		startTime:      time.Now(),
	}
}

func (w *fMP4Wrapper) ContentType() string {
	return "video/mp4"
}

func (w *fMP4Wrapper) GetInitSegment() ([]byte, error) {
	buf := new(bytes.Buffer)

	ftypSize := uint32(32)
	buf.Write(encodeUint32(ftypSize))
	buf.WriteString("ftyp")
	buf.WriteString("mp42")
	buf.Write(encodeUint32(0))
	buf.WriteString("mp42")
	buf.WriteString("isom")
	buf.WriteString("avc1")
	buf.WriteString("dash")




	moovBuf := new(bytes.Buffer)

	writeAtom(moovBuf, "mvhd", generateMVHD())

	trakBuf := new(bytes.Buffer)
	writeAtom(trakBuf, "tkhd", generateTKHD())

	mdiaBuf := new(bytes.Buffer)
	writeAtom(mdiaBuf, "mdhd", generateMDHD())
	writeAtom(mdiaBuf, "hdlr", generateHDLR())

	minfBuf := new(bytes.Buffer)
	writeAtom(minfBuf, "vmhd", []byte{0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0})
	dinfBuf := new(bytes.Buffer)
	drefData := []byte{
		0, 0, 0, 0,
		0, 0, 0, 1,
		0, 0, 0, 12,
		'u', 'r', 'l', ' ',
		0, 0, 0, 1,
	}
	writeAtom(dinfBuf, "dref", drefData)
	writeAtom(minfBuf, "dinf", dinfBuf.Bytes())

	stblBuf := new(bytes.Buffer)
	writeAtom(stblBuf, "stts", []byte{0, 0, 0, 0, 0, 0, 0, 0})
	writeAtom(stblBuf, "stsc", []byte{0, 0, 0, 0, 0, 0, 0, 0})
	writeAtom(stblBuf, "stsz", []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0})
	writeAtom(stblBuf, "stco", []byte{0, 0, 0, 0, 0, 0, 0, 0})

	writeAtom(minfBuf, "stbl", stblBuf.Bytes())

	writeAtom(mdiaBuf, "minf", minfBuf.Bytes())
	writeAtom(trakBuf, "mdia", mdiaBuf.Bytes())

	writeAtom(moovBuf, "trak", trakBuf.Bytes())

	mvexBuf := new(bytes.Buffer)
	trexData := make([]byte, 32)
	binary.BigEndian.PutUint32(trexData[4:8], 1)
	binary.BigEndian.PutUint32(trexData[8:12], 1)
	writeAtom(mvexBuf, "trex", trexData)
	writeAtom(moovBuf, "mvex", mvexBuf.Bytes())

	writeAtom(buf, "moov", moovBuf.Bytes())

	return buf.Bytes(), nil
}

func (w *fMP4Wrapper) WrapData(data []byte) ([]byte, error) {
	buf := new(bytes.Buffer)

	moofBuf := new(bytes.Buffer)

	mfhdData := make([]byte, 8)
	binary.BigEndian.PutUint32(mfhdData[4:], w.sequenceNumber)
	writeAtom(moofBuf, "mfhd", mfhdData)

	trafBuf := new(bytes.Buffer)

	tfhdData := []byte{
		0, 0x02, 0x00, 0x00,
		0, 0, 0, 1,
	}
	writeAtom(trafBuf, "tfhd", tfhdData)

	tfdtData := make([]byte, 8)
	binary.BigEndian.PutUint32(tfdtData[4:], w.sequenceNumber*1000)
	writeAtom(trafBuf, "tfdt", tfdtData)

	trunBuf := new(bytes.Buffer)
	trunBuf.Write([]byte{0, 0, 0x02, 0x01})
	trunBuf.Write(encodeUint32(1))



	trunBuf.Write(encodeUint32(96))
	trunBuf.Write(encodeUint32(uint32(len(data))))

	writeAtom(trafBuf, "trun", trunBuf.Bytes())

	writeAtom(moofBuf, "traf", trafBuf.Bytes())
	writeAtom(buf, "moof", moofBuf.Bytes())

	writeAtom(buf, "mdat", data)

	w.sequenceNumber++
	return buf.Bytes(), nil
}

func (w *fMP4Wrapper) UnwrapData(data []byte) ([]byte, error) {
	reader := bytes.NewReader(data)
	var payloadBuf bytes.Buffer

	for reader.Len() > 0 {
		if reader.Len() < 8 {
			break
		}

		var size uint32
		if err := binary.Read(reader, binary.BigEndian, &size); err != nil {
			return nil, err
		}

		header := make([]byte, 4)
		if _, err := reader.Read(header); err != nil {
			return nil, err
		}
		atomType := string(header)

		contentLen := int64(size) - 8
		if contentLen < 0 {
			return nil, errors.New("invalid atom size")
		}

		if atomType == "mdat" {
			chunk := make([]byte, contentLen)
			if _, err := reader.Read(chunk); err != nil {
				return nil, err
			}
			payloadBuf.Write(chunk)
		} else {
			if _, err := reader.Seek(contentLen, io.SeekCurrent); err != nil {
				return nil, err
			}
		}
	}

	if payloadBuf.Len() == 0 {
		return []byte{}, nil
	}

	return payloadBuf.Bytes(), nil
}


func writeAtom(w *bytes.Buffer, typ string, data []byte) {
	size := uint32(8 + len(data))
	w.Write(encodeUint32(size))
	w.WriteString(typ)
	w.Write(data)
}

func encodeUint32(v uint32) []byte {
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, v)
	return b
}

func generateMVHD() []byte {
	b := make([]byte, 100)
	binary.BigEndian.PutUint32(b[12:16], 1000)
	b[36] = 0x00
	b[37] = 0x01
	binary.BigEndian.PutUint32(b[96:], 2)
	return b
}

func generateTKHD() []byte {
	b := make([]byte, 84)
	b[3] = 0x07
	binary.BigEndian.PutUint32(b[12:16], 1)
	binary.BigEndian.PutUint32(b[76:80], 1920<<16)
	binary.BigEndian.PutUint32(b[80:84], 1080<<16)
	return b
}

func generateMDHD() []byte {
	b := make([]byte, 24)
	binary.BigEndian.PutUint32(b[12:16], 1000)
	return b
}

func generateHDLR() []byte {
	b := new(bytes.Buffer)
	b.Write([]byte{0, 0, 0, 0})
	b.Write([]byte{0, 0, 0, 0})
	b.WriteString("vide")
	b.Write(make([]byte, 12))
	b.WriteString("VideoHandler")
	b.WriteByte(0)
	return b.Bytes()
}
