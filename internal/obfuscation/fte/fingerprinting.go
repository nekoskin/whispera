package fte

import (
	"fmt"
	"math/rand"
	"strconv"
	"strings"
)

type JA4Parameters struct {
	SNI                 string
	ALPN                string
	SignatureAlgorithms string
}

func (fte *FTE) generateUniqueJA3Fingerprint(service string) string {
	tlsParams := fte.getServiceTLSParameters(service)
	ja3String := fmt.Sprintf("%s,%s,%s,%s,%s",
		tlsParams.Version,
		tlsParams.CipherSuites,
		tlsParams.Extensions,
		tlsParams.EllipticCurves,
		tlsParams.EllipticCurvePointFormats)
	return ja3String
}

func (fte *FTE) getServiceTLSParameters(service string) *TLSParameters {
	hash := fte.calculateServiceHash(service)
	baseVersion := "771"
	cipherSuites := fte.generateUniqueCipherSuites(service, hash)
	extensions := fte.generateUniqueExtensions(service, hash)
	ellipticCurves := fte.generateUniqueEllipticCurves(service, hash)
	pointFormats := fte.generateUniquePointFormats(service, hash)
	return &TLSParameters{
		Version:                   baseVersion,
		CipherSuites:              cipherSuites,
		Extensions:                extensions,
		EllipticCurves:            ellipticCurves,
		EllipticCurvePointFormats: pointFormats,
	}
}

func (fte *FTE) generateUniqueJA4Fingerprint(service string) string {
	tlsParams := fte.getServiceTLSParameters(service)
	ja4Params := fte.getServiceJA4Parameters(service)
	ja4String := fmt.Sprintf("%s,%s,%s,%s,%s,%s",
		tlsParams.Version,
		tlsParams.CipherSuites,
		tlsParams.Extensions,
		ja4Params.SNI,
		ja4Params.ALPN,
		ja4Params.SignatureAlgorithms)
	return ja4String
}

func (fte *FTE) getServiceJA4Parameters(service string) *JA4Parameters {
	hash := fte.calculateServiceHash(service)
	sni := fte.generateUniqueSNI(service, hash)
	alpn := fte.generateUniqueALPN(service, hash)
	signatureAlgorithms := fte.generateUniqueSignatureAlgorithms(service, hash)
	return &JA4Parameters{SNI: sni, ALPN: alpn, SignatureAlgorithms: signatureAlgorithms}
}

func (fte *FTE) generateUniqueSNI(service string, hash int) string {
	switch service {
	case "vk":
		return []string{"vk.com", "m.vk.com", "api.vk.com", "oauth.vk.com"}[hash%4]
	case ProfileYandexFTE:
		return []string{"yandex.ru", "m.yandex.ru", "api.yandex.ru", "oauth.yandex.ru"}[hash%4]
	case ProfileMailruFTE:
		return []string{"mail.ru", "m.mail.ru", "api.mail.ru", "oauth.mail.ru"}[hash%4]
	case ProfileRutubeFTE:
		return []string{"rutube.ru", "m.rutube.ru", "api.rutube.ru", "oauth.rutube.ru"}[hash%4]
	case ProfileOzonFTE:
		return []string{"ozon.ru", "m.ozon.ru", "api.ozon.ru", "oauth.ozon.ru"}[hash%4]
	default:
		return "example.com"
	}
}

func (fte *FTE) generateUniqueALPN(service string, hash int) string {
	alpnOptions := []string{"h2,http/1.1"}
	switch service {
	case "vk":
		alpnOptions = []string{"h2,http/1.1", "h2", "http/1.1", "h2,http/1.1,spdy/3.1"}
	case ProfileYandexFTE:
		alpnOptions = []string{"h2,http/1.1", "h2", "http/1.1", "h2,http/1.1,spdy/3.1", "h2,http/1.1,spdy/3.1,spdy/3"}
	case ProfileMailruFTE:
		alpnOptions = []string{"h2,http/1.1", "h2", "http/1.1", "h2,http/1.1,spdy/3.1", "h2,http/1.1,spdy/3.1,spdy/3", "h2,http/1.1,spdy/3.1,spdy/3,spdy/2"}
	case ProfileRutubeFTE:
		alpnOptions = []string{"h2,http/1.1", "h2", "http/1.1", "h2,http/1.1,spdy/3.1", "h2,http/1.1,spdy/3.1,spdy/3", "h2,http/1.1,spdy/3.1,spdy/3,spdy/2", "h2,http/1.1,spdy/3.1,spdy/3,spdy/2,spdy/1"}
	case ProfileOzonFTE:
		alpnOptions = []string{"h2,http/1.1", "h2", "http/1.1", "h2,http/1.1,spdy/3.1", "h2,http/1.1,spdy/3.1,spdy/3", "h2,http/1.1,spdy/3.1,spdy/3,spdy/2", "h2,http/1.1,spdy/3.1,spdy/3,spdy/2,spdy/1", "h2,http/1.1,spdy/3.1,spdy/3,spdy/2,spdy/1,spdy/0"}
	}
	return alpnOptions[hash%len(alpnOptions)]
}

func (fte *FTE) generateUniqueSignatureAlgorithms(service string, hash int) string {
	algos := []string{"rsa_pss_rsae_sha256", "rsa_pkcs1_sha256", "ecdsa_sha256", "rsa_pss_rsae_sha384", "rsa_pkcs1_sha384", "ecdsa_sha384", "rsa_pss_rsae_sha512", "rsa_pkcs1_sha512", "ecdsa_sha512"}
	switch service {
	case "vk":
		algos = append(algos, "rsa_pss_rsae_sha256", "rsa_pkcs1_sha256", "ecdsa_sha256")
	case ProfileYandexFTE:
		algos = append(algos, "rsa_pss_rsae_sha256", "rsa_pkcs1_sha256", "ecdsa_sha256", "rsa_pss_rsae_sha384")
	case ProfileMailruFTE:
		algos = append(algos, "rsa_pss_rsae_sha256", "rsa_pkcs1_sha256", "ecdsa_sha256", "rsa_pss_rsae_sha384", "rsa_pkcs1_sha384")
	}
	fte.shuffleStrings(algos, hash)
	return strings.Join(algos, ",")
}

func (fte *FTE) generateUniqueCipherSuites(service string, hash int) string {
	baseCiphers := []string{"4865", "4866", "4867", "49195", "49199", "49196", "49200", "52393", "52392", "49171", "49172", "156", "157", "47", "53"}
	switch service {
	case "vk":
		baseCiphers = append(baseCiphers, "4865", "4866", "4867")
	case ProfileYandexFTE:
		baseCiphers = append(baseCiphers, "4865", "4866", "4867", "49195")
	case ProfileMailruFTE:
		baseCiphers = append(baseCiphers, "4865", "4866", "4867", "49195", "49199")
	case ProfileRutubeFTE:
		baseCiphers = append(baseCiphers, "4865", "4866", "4867", "49195", "49199", "49196")
	case ProfileOzonFTE:
		baseCiphers = append(baseCiphers, "4865", "4866", "4867", "49195", "49199", "49196", "49200")
	}
	fte.shuffleStrings(baseCiphers, hash)
	return fte.modifyCipherSuite(strings.Join(baseCiphers, "-"), hash%7)
}

func (fte *FTE) generateUniqueExtensions(service string, hash int) string {
	baseExts := []string{"0", "23", "65281", "10", "11", "35", "16", "5", "13", "18", "51", "45", "43", "27", "17513"}
	switch service {
	case "vk":
		baseExts = append(baseExts, "0", "23", "65281")
	case ProfileYandexFTE:
		baseExts = append(baseExts, "0", "23", "65281", "10")
	case ProfileMailruFTE:
		baseExts = append(baseExts, "0", "23", "65281", "10", "11")
	case ProfileRutubeFTE:
		baseExts = append(baseExts, "0", "23", "65281", "10", "11", "35")
	case ProfileOzonFTE:
		baseExts = append(baseExts, "0", "23", "65281", "10", "11", "35", "16")
	}
	fte.shuffleStrings(baseExts, hash)
	return fte.modifyExtensions(strings.Join(baseExts, "-"), hash%11)
}

func (fte *FTE) generateUniqueEllipticCurves(service string, hash int) string {
	curves := []string{"29", "23", "24"}
	switch service {
	case "vk":
		curves = append(curves, "29", "23")
	case ProfileYandexFTE:
		curves = append(curves, "29", "23", "24")
	case ProfileMailruFTE:
		curves = append(curves, "29", "23", "24", "25")
	case ProfileRutubeFTE:
		curves = append(curves, "29", "23", "24", "25", "26")
	case ProfileOzonFTE:
		curves = append(curves, "29", "23", "24", "25", "26", "27")
	}
	fte.shuffleStrings(curves, hash)
	return strings.Join(curves, "-")
}

func (fte *FTE) generateUniquePointFormats(service string, hash int) string {
	formats := []string{"0"}
	switch service {
	case "vk":
		formats = append(formats, "0", "1")
	case ProfileYandexFTE:
		formats = append(formats, "0", "1", "2")
	}
	fte.shuffleStrings(formats, hash)
	return strings.Join(formats, "-")
}

func (fte *FTE) shuffleStrings(slice []string, hash int) {
	r := rand.New(rand.NewSource(int64(hash)))
	for i := len(slice) - 1; i > 0; i-- {
		j := r.Intn(i + 1)
		slice[i], slice[j] = slice[j], slice[i]
	}
}

func (fte *FTE) calculateServiceHash(service string) int {
	hash := 0
	for _, char := range service {
		hash = hash*31 + int(char)
	}
	return hash
}

func (fte *FTE) modifyCipherSuite(baseCiphers string, mod int) string {
	if mod%2 == 0 {
		return baseCiphers
	}
	return baseCiphers + "-" + strconv.Itoa(4865+mod)
}

func (fte *FTE) modifyExtensions(baseExtensions string, mod int) string {
	if mod%3 == 0 {
		return baseExtensions
	}
	return baseExtensions + "-" + strconv.Itoa(65281+mod)
}
