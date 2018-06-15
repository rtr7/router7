// Package dhcp4d implements a DHCPv4 server.
package dhcp4d

import (
	"bytes"
	"log"
	"math/rand"
	"net"
	"time"

	"router7/internal/netconfig"

	"github.com/krolaw/dhcp4"
)

type Lease struct {
	Num          int       `json:"num"` // relative to Handler.start
	Addr         net.IP    `json:"addr"`
	HardwareAddr string    `json:"hardware_addr"`
	Hostname     string    `json:"hostname"`
	Expiry       time.Time `json:"expiry"`
}

func (l *Lease) Expired(at time.Time) bool {
	return !l.Expiry.IsZero() && at.After(l.Expiry)
}

type Handler struct {
	serverIP    net.IP
	start       net.IP // first IP address to hand out
	leaseRange  int    // number of IP addresses to hand out
	leasePeriod time.Duration
	options     dhcp4.Options
	leasesHW    map[string]*Lease
	leasesIP    map[int]*Lease

	timeNow func() time.Time

	// Leases is called whenever a new lease is handed out
	Leases func([]*Lease)
}

func NewHandler(dir string) (*Handler, error) {
	serverIP, err := netconfig.LinkAddress(dir, "lan0")
	if err != nil {
		return nil, err
	}
	serverIP = serverIP.To4()
	start := make(net.IP, len(serverIP))
	copy(start, serverIP)
	start[len(start)-1] += 1
	return &Handler{
		leasesHW:    make(map[string]*Lease),
		leasesIP:    make(map[int]*Lease),
		serverIP:    serverIP,
		start:       start,
		leaseRange:  200,
		leasePeriod: 2 * time.Hour,
		options: dhcp4.Options{
			dhcp4.OptionSubnetMask:       []byte{255, 255, 255, 0},
			dhcp4.OptionRouter:           []byte(serverIP),
			dhcp4.OptionDomainNameServer: []byte(serverIP),
			dhcp4.OptionDomainName:       []byte("lan"),
			dhcp4.OptionDomainSearch:     []byte{0x03, 'l', 'a', 'n', 0x00},
		},
		timeNow: time.Now,
	}, nil
}

// SetLeases overwrites the leases database with the specified leases, typically
// loaded from persistent storage. There is no locking, so SetLeases must be
// called before Serve.
func (h *Handler) SetLeases(leases []*Lease) {
	h.leasesHW = make(map[string]*Lease)
	h.leasesIP = make(map[int]*Lease)
	for _, l := range leases {
		h.leasesHW[l.HardwareAddr] = l
		h.leasesIP[l.Num] = l
	}
}

func (h *Handler) findLease() int {
	now := h.timeNow()
	if len(h.leasesIP) < h.leaseRange {
		// TODO: hash the hwaddr like dnsmasq
		i := rand.Intn(h.leaseRange)
		if l, ok := h.leasesIP[i]; !ok || l.Expired(now) {
			return i
		}
		for i := 0; i < h.leaseRange; i++ {
			if l, ok := h.leasesIP[i]; !ok || l.Expired(now) {
				return i
			}
		}
	}
	return -1
}

func (h *Handler) canLease(reqIP net.IP, hwaddr string) int {
	if len(reqIP) != 4 || reqIP.Equal(net.IPv4zero) {
		return -1
	}

	leaseNum := dhcp4.IPRange(h.start, reqIP) - 1
	if leaseNum < 0 || leaseNum >= h.leaseRange {
		return -1
	}

	l, ok := h.leasesIP[leaseNum]
	if !ok {
		return leaseNum // lease available
	}

	if l.HardwareAddr == hwaddr {
		return leaseNum // lease already owned by requestor
	}

	if l.Expired(h.timeNow()) {
		return leaseNum // lease expired
	}

	return -1 // lease unavailable
}

// TODO: is ServeDHCP always run from the same goroutine, or do we need locking?
func (h *Handler) ServeDHCP(p dhcp4.Packet, msgType dhcp4.MessageType, options dhcp4.Options) dhcp4.Packet {
	reqIP := net.IP(options[dhcp4.OptionRequestedIPAddress])
	if reqIP == nil {
		reqIP = net.IP(p.CIAddr())
	}

	switch msgType {
	case dhcp4.Discover:
		free := -1
		hwAddr := p.CHAddr().String()

		// try to offer the requested IP, if any and available
		if !bytes.Equal(reqIP.To4(), net.IPv4zero) {
			free = h.canLease(reqIP, hwAddr)
		}

		// offer previous lease for this HardwareAddr, if any
		if lease, ok := h.leasesHW[hwAddr]; ok {
			free = lease.Num
		}

		if free == -1 {
			free = h.findLease()
		}

		if free == -1 {
			log.Printf("Cannot reply with DHCPOFFER: no more leases available")
			return nil // no free leases
		}

		return dhcp4.ReplyPacket(p,
			dhcp4.Offer,
			h.serverIP,
			dhcp4.IPAdd(h.start, free),
			h.leasePeriod,
			h.options.SelectOrderOrAll(options[dhcp4.OptionParameterRequestList]))

	case dhcp4.Request:
		if server, ok := options[dhcp4.OptionServerIdentifier]; ok && !net.IP(server).Equal(h.serverIP) {
			return nil // message not for this dhcp server
		}
		nak := dhcp4.ReplyPacket(p, dhcp4.NAK, h.serverIP, nil, 0, nil)
		leaseNum := h.canLease(reqIP, p.CHAddr().String())
		if leaseNum == -1 {
			return nak
		}

		lease := &Lease{
			Num:          leaseNum,
			Addr:         make([]byte, 4),
			HardwareAddr: p.CHAddr().String(),
			Expiry:       time.Now().Add(h.leasePeriod),
			Hostname:     string(options[dhcp4.OptionHostName]),
		}
		copy(lease.Addr, reqIP.To4())

		if l, ok := h.leasesHW[lease.HardwareAddr]; ok {
			if l.Expiry.IsZero() {
				// Retain permanent lease properties
				lease.Expiry = time.Time{}
				lease.Hostname = l.Hostname
			}

			// Release any old leases for this client
			delete(h.leasesIP, l.Num)
		}

		h.leasesIP[leaseNum] = lease
		h.leasesHW[lease.HardwareAddr] = lease
		if h.Leases != nil {
			var leases []*Lease
			for _, l := range h.leasesIP {
				leases = append(leases, l)
			}
			h.Leases(leases)
		}
		return dhcp4.ReplyPacket(p, dhcp4.ACK, h.serverIP, reqIP, h.leasePeriod,
			h.options.SelectOrderOrAll(options[dhcp4.OptionParameterRequestList]))

	}
	return nil
}
