package configuri

import (
	"errors"
	"net/url"
	"strings"
)

// ApplyConfigURI parses a whispera:// URI and populates the provided pointers with extracted values.
// It returns the optional token part (userinfo) if present.
func ApplyConfigURI(
	raw string,
	server, serverTCP, serverWS, serverWS2, metricsAddr *string,
	p2pEnabled *bool,
	p2pBootstrapCSV, p2pListen, pskHex, serverPubHex *string,
) (string, error) {
	if !strings.HasPrefix(strings.ToLower(raw), "whispera://") {
		return "", errors.New("invalid scheme: expect whispera://")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return "", err
	}
	if u.Host == "" {
		return "", errors.New("missing host:port")
	}

	token := ""
	if u.User != nil {
		token = u.User.Username()
	}

	*server = u.Host

	q := u.Query()
	switch strings.ToLower(q.Get("proto")) {
	case "psk":
		if v := q.Get("psk"); v != "" {
			*pskHex = v
		} else {
			return "", errors.New("proto=psk requires psk")
		}
	case "noise", "":
		if v := q.Get("server_pub"); v != "" {
			*serverPubHex = v
		} else {
			return "", errors.New("proto=noise requires server_pub")
		}
	default:
		return "", errors.New("unknown proto")
	}

	if v := q.Get("tcp"); v != "" {
		*serverTCP = v
	}
	if v := q.Get("ws"); v != "" {
		*serverWS = v
	}
	if v := q.Get("ws2"); v != "" {
		*serverWS2 = v
	}
	if v := q.Get("metrics"); v != "" {
		*metricsAddr = v
	}
	if v := q.Get("p2p"); v == "1" {
		*p2pEnabled = true
	}
	if v := q.Get("p2p_bootstrap"); v != "" {
		*p2pBootstrapCSV = v
	}
	if v := q.Get("p2p_listen"); v != "" {
		*p2pListen = v
	}

	return token, nil
}

