package whispera

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

const (
	Version byte = 1

	MaxPadding = 64

	MinPacketSize = 32
)

type Command byte

const (
	CommandTCP   Command = 0x01
	CommandUDP   Command = 0x02
	CommandMux   Command = 0x03
	CommandPing  Command = 0x04
	CommandPong  Command = 0x05
	CommandData  Command = 0x10
	CommandClose Command = 0x11
	CommandReset Command = 0x12
)

type Addon byte

const (
	AddonNone           Addon = 0x00
	AddonObfuscation    Addon = 0x01
	AddonCompression    Addon = 0x02
	AddonPadding        Addon = 0x04
	AddonEncrypted      Addon = 0x08
	AddonMLProfile      Addon = 0x10
	AddonTimingMask     Addon = 0x20
	AddonFragmented     Addon = 0x40
	AddonTLSFingerprint Addon = 0x80
)

type TLSFingerprintType byte

const (
	FingerprintAuto    TLSFingerprintType = 0x00
	FingerprintChrome  TLSFingerprintType = 0x01
	FingerprintFirefox TLSFingerprintType = 0x02
	FingerprintSafari  TLSFingerprintType = 0x03
	FingerprintiOS     TLSFingerprintType = 0x04
	FingerprintAndroid TLSFingerprintType = 0x05
	FingerprintRandom  TLSFingerprintType = 0xFF
)

type AddressType byte

const (
	AddrTypeIPv4   AddressType = 0x01
	AddrTypeDomain AddressType = 0x02
	AddrTypeIPv6   AddressType = 0x03
)

type ObfuscationProfile byte

const (
	ProfileNone     ObfuscationProfile = 0x00
	ProfileVK       ObfuscationProfile = 0x01
	ProfileYandex   ObfuscationProfile = 0x02
	ProfileMailRu   ObfuscationProfile = 0x03
	ProfileTelegram ObfuscationProfile = 0x04
	ProfileYouTube  ObfuscationProfile = 0x05
	ProfileGeneric  ObfuscationProfile = 0x06
	ProfileML       ObfuscationProfile = 0xFF
)

type CompressionType byte

const (
	CompressionNone CompressionType = 0x00
	CompressionLZ4  CompressionType = 0x01
	CompressionZstd CompressionType = 0x02
)

type RequestHeader struct {
	Version   byte
	UUID      [16]byte
	Addons    Addon
	AddonData *AddonData
	Command   Command
	Port      uint16
	AddrType  AddressType
	Address   []byte
}

type AddonData struct {
	ObfuscationProfile ObfuscationProfile
	CompressionType    CompressionType
	PaddingLength      byte
	FragmentID         uint16
	FragmentTotal      byte
	FragmentSeq        byte
}

type ResponseHeader struct {
	Version   byte
	Addons    Addon
	AddonData *AddonData
}

func ReadRequestHeader(r io.Reader) (*RequestHeader, error) {
	hdr := &RequestHeader{}

	var version [1]byte
	if _, err := io.ReadFull(r, version[:]); err != nil {
		return nil, err
	}
	hdr.Version = version[0]

	if hdr.Version != Version {
		return nil, errors.New("unsupported Whispera protocol version")
	}

	if _, err := io.ReadFull(r, hdr.UUID[:]); err != nil {
		return nil, err
	}

	var addons [1]byte
	if _, err := io.ReadFull(r, addons[:]); err != nil {
		return nil, err
	}
	hdr.Addons = Addon(addons[0])

	if hdr.Addons != AddonNone {
		addonData, err := readAddonData(r, hdr.Addons)
		if err != nil {
			return nil, err
		}
		hdr.AddonData = addonData
	}

	var cmd [1]byte
	if _, err := io.ReadFull(r, cmd[:]); err != nil {
		return nil, err
	}
	hdr.Command = Command(cmd[0])

	if hdr.Command == CommandTCP || hdr.Command == CommandUDP {
		var port [2]byte
		if _, err := io.ReadFull(r, port[:]); err != nil {
			return nil, err
		}
		hdr.Port = binary.BigEndian.Uint16(port[:])

		var addrType [1]byte
		if _, err := io.ReadFull(r, addrType[:]); err != nil {
			return nil, err
		}
		hdr.AddrType = AddressType(addrType[0])

		switch hdr.AddrType {
		case AddrTypeIPv4:
			hdr.Address = make([]byte, 4)
			if _, err := io.ReadFull(r, hdr.Address); err != nil {
				return nil, err
			}
		case AddrTypeIPv6:
			hdr.Address = make([]byte, 16)
			if _, err := io.ReadFull(r, hdr.Address); err != nil {
				return nil, err
			}
		case AddrTypeDomain:
			var domainLen [1]byte
			if _, err := io.ReadFull(r, domainLen[:]); err != nil {
				return nil, err
			}
			if domainLen[0] == 0 {
				return nil, errors.New("empty domain name")
			}
			hdr.Address = make([]byte, domainLen[0])
			if _, err := io.ReadFull(r, hdr.Address); err != nil {
				return nil, err
			}
		default:
			return nil, errors.New("invalid address type")
		}
	}

	return hdr, nil
}

func readAddonData(r io.Reader, addons Addon) (*AddonData, error) {
	data := &AddonData{}

	var buf [256]byte

	if addons&AddonObfuscation != 0 || addons&AddonMLProfile != 0 {
		var profile [1]byte
		if _, err := io.ReadFull(r, profile[:]); err != nil {
			return nil, err
		}
		data.ObfuscationProfile = ObfuscationProfile(profile[0])
	}

	if addons&AddonCompression != 0 {
		var comp [1]byte
		if _, err := io.ReadFull(r, comp[:]); err != nil {
			return nil, err
		}
		data.CompressionType = CompressionType(comp[0])
	}

	if addons&AddonPadding != 0 {
		var padLen [1]byte
		if _, err := io.ReadFull(r, padLen[:]); err != nil {
			return nil, err
		}
		data.PaddingLength = padLen[0]

		if data.PaddingLength > 0 {
			if _, err := io.ReadFull(r, buf[:data.PaddingLength]); err != nil {
				return nil, err
			}
		}
	}

	if addons&AddonFragmented != 0 {
		var fragInfo [4]byte
		if _, err := io.ReadFull(r, fragInfo[:]); err != nil {
			return nil, err
		}
		data.FragmentID = binary.BigEndian.Uint16(fragInfo[0:2])
		data.FragmentTotal = fragInfo[2]
		data.FragmentSeq = fragInfo[3]
	}

	return data, nil
}

func WriteRequestHeader(w io.Writer, hdr *RequestHeader) error {
	if _, err := w.Write([]byte{hdr.Version}); err != nil {
		return err
	}

	if _, err := w.Write(hdr.UUID[:]); err != nil {
		return err
	}

	if _, err := w.Write([]byte{byte(hdr.Addons)}); err != nil {
		return err
	}

	if hdr.Addons != AddonNone && hdr.AddonData != nil {
		if err := writeAddonData(w, hdr.Addons, hdr.AddonData); err != nil {
			return err
		}
	}

	if _, err := w.Write([]byte{byte(hdr.Command)}); err != nil {
		return err
	}

	if hdr.Command == CommandTCP || hdr.Command == CommandUDP {
		var port [2]byte
		binary.BigEndian.PutUint16(port[:], hdr.Port)
		if _, err := w.Write(port[:]); err != nil {
			return err
		}

		if _, err := w.Write([]byte{byte(hdr.AddrType)}); err != nil {
			return err
		}

		if hdr.AddrType == AddrTypeDomain {
			if _, err := w.Write([]byte{byte(len(hdr.Address))}); err != nil {
				return err
			}
		}
		if _, err := w.Write(hdr.Address); err != nil {
			return err
		}
	}

	return nil
}

func writeAddonData(w io.Writer, addons Addon, data *AddonData) error {
	if addons&AddonObfuscation != 0 || addons&AddonMLProfile != 0 {
		if _, err := w.Write([]byte{byte(data.ObfuscationProfile)}); err != nil {
			return err
		}
	}

	if addons&AddonCompression != 0 {
		if _, err := w.Write([]byte{byte(data.CompressionType)}); err != nil {
			return err
		}
	}

	if addons&AddonPadding != 0 {
		paddingLen := data.PaddingLength
		if paddingLen > MaxPadding {
			paddingLen = MaxPadding
		}
		if _, err := w.Write([]byte{paddingLen}); err != nil {
			return err
		}
		if paddingLen > 0 {
			var padding [MaxPadding]byte
			rand.Read(padding[:paddingLen])
			if _, err := w.Write(padding[:paddingLen]); err != nil {
				return err
			}
		}
	}

	if addons&AddonFragmented != 0 {
		var fragInfo [4]byte
		binary.BigEndian.PutUint16(fragInfo[0:2], data.FragmentID)
		fragInfo[2] = data.FragmentTotal
		fragInfo[3] = data.FragmentSeq
		if _, err := w.Write(fragInfo[:]); err != nil {
			return err
		}
	}

	return nil
}

func ReadResponseHeader(r io.Reader) (*ResponseHeader, error) {
	hdr := &ResponseHeader{}

	var buf [2]byte

	if _, err := io.ReadFull(r, buf[:1]); err != nil {
		return nil, err
	}
	hdr.Version = buf[0]

	if _, err := io.ReadFull(r, buf[:1]); err != nil {
		return nil, err
	}
	hdr.Addons = Addon(buf[0])

	if hdr.Addons != AddonNone {
		addonData, err := readAddonData(r, hdr.Addons)
		if err != nil {
			return nil, err
		}
		hdr.AddonData = addonData
	}

	return hdr, nil
}

func WriteResponseHeader(w io.Writer, hdr *ResponseHeader) error {
	if _, err := w.Write([]byte{hdr.Version}); err != nil {
		return err
	}

	if _, err := w.Write([]byte{byte(hdr.Addons)}); err != nil {
		return err
	}

	if hdr.Addons != AddonNone && hdr.AddonData != nil {
		if err := writeAddonData(w, hdr.Addons, hdr.AddonData); err != nil {
			return err
		}
	}

	return nil
}

func HeaderSize(hdr *RequestHeader) int {
	size := 1 + 16 + 1 + 1

	if hdr.Addons != AddonNone {
		if hdr.Addons&AddonObfuscation != 0 || hdr.Addons&AddonMLProfile != 0 {
			size += 1
		}
		if hdr.Addons&AddonCompression != 0 {
			size += 1
		}
		if hdr.Addons&AddonPadding != 0 && hdr.AddonData != nil {
			size += 1 + int(hdr.AddonData.PaddingLength)
		}
		if hdr.Addons&AddonFragmented != 0 {
			size += 4
		}
	}

	if hdr.Command == CommandTCP || hdr.Command == CommandUDP {
		size += 2 + 1
		switch hdr.AddrType {
		case AddrTypeIPv4:
			size += 4
		case AddrTypeIPv6:
			size += 16
		case AddrTypeDomain:
			size += 1 + len(hdr.Address)
		}
	}

	return size
}

func NewRequestHeader(uuid [16]byte, cmd Command, addr string, port uint16) *RequestHeader {
	hdr := &RequestHeader{
		Version: Version,
		UUID:    uuid,
		Addons:  AddonObfuscation | AddonCompression,
		Command: cmd,
		Port:    port,
		AddonData: &AddonData{
			ObfuscationProfile: ProfileML,
			CompressionType:    CompressionLZ4,
		},
	}

	if ip := parseIP(addr); ip != nil {
		if len(ip) == 4 {
			hdr.AddrType = AddrTypeIPv4
		} else {
			hdr.AddrType = AddrTypeIPv6
		}
		hdr.Address = ip
	} else {
		hdr.AddrType = AddrTypeDomain
		hdr.Address = []byte(addr)
	}

	return hdr
}

func parseIP(s string) []byte {
	var ip [4]byte
	n, _ := fmt.Sscanf(s, "%d.%d.%d.%d", &ip[0], &ip[1], &ip[2], &ip[3])
	if n == 4 {
		return ip[:]
	}
	return nil
}
