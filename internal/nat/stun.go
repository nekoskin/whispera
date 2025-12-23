package nat

import (
	"net"

	"whispera/internal/util"

	"github.com/pion/stun"
)

// DiscoverPublicUDP queries a STUN server and returns the detected public UDP address.
func DiscoverPublicUDP(stunServer string) (*net.UDPAddr, error) {
	c, err := stun.Dial("udp", stunServer)
	if err != nil {
		return nil, err
	}
	defer util.SafeClose("stun.Conn", c.Close)
	var mapped stun.XORMappedAddress
	if err := c.Do(stun.MustBuild(stun.TransactionID, stun.BindingRequest), func(e stun.Event) {
		if e.Error != nil {
			return
		}
		_ = mapped.GetFrom(e.Message)
	}); err != nil {
		return nil, err
	}
	return &net.UDPAddr{IP: mapped.IP, Port: mapped.Port}, nil
}
