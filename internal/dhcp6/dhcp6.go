// Copyright 2018 Google Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package dhcp6 implements a DHCPv6 client.
package dhcp6

import (
	"fmt"
	"log"
	"net"
	"strconv"
	"time"

	"github.com/insomniacslk/dhcp/dhcpv6"
	"github.com/insomniacslk/dhcp/iana"
)

type ClientConfig struct {
	InterfaceName string // e.g. eth0

	// LocalAddr allows overwriting the source address used for sending DHCPv6
	// packets. It defaults to the first link-local address of InterfaceName.
	LocalAddr *net.UDPAddr

	// RemoteAddr allows addressing a specific DHCPv6 server. It defaults to
	// the dhcpv6.AllDHCPRelayAgentsAndServers multicast address.
	RemoteAddr *net.UDPAddr

	// DUID contains all bytes (including the prefixing uint16 type field) for a
	// DHCP Unique Identifier (e.g. []byte{0x00, 0x0a, 0x00, 0x03, 0x00, 0x01,
	// 0x4c, 0x5e, 0xc, 0x41, 0xbf, 0x39}).
	//
	// Fiber7 assigns static IPv6 /48 networks to DUIDs, so it is important to
	// be able to carry it around between devices.
	DUID []byte

	Conn           net.PacketConn // for testing
	TransactionIDs []uint32       // for testing
}

// Config contains the obtained network configuration.
type Config struct {
	RenewAfter time.Time   `json:"valid_until"`
	Prefixes   []net.IPNet `json:"prefixes"` // e.g. 2a02:168:4a00::/48
	DNS        []string    `json:"dns"`      // e.g. 2001:1620:2777:1::10, 2001:1620:2777:2::20
}

type Client struct {
	interfaceName string
	raddr         *net.UDPAddr
	timeNow       func() time.Time
	duid          *dhcpv6.Duid
	advertise     dhcpv6.DHCPv6

	cfg Config
	err error

	Conn           net.PacketConn // TODO: unexport
	transactionIDs []uint32

	ReadTimeout  time.Duration
	WriteTimeout time.Duration

	RemoteAddr net.Addr
}

func NewClient(cfg ClientConfig) (*Client, error) {
	iface, err := net.InterfaceByName(cfg.InterfaceName)
	if err != nil {
		return nil, err
	}

	// if no LocalAddr is specified, get the interface's link-local address
	laddr := cfg.LocalAddr
	if laddr == nil {
		llAddr, err := dhcpv6.GetLinkLocalAddr(cfg.InterfaceName)
		if err != nil {
			return nil, err
		}
		laddr = &net.UDPAddr{
			IP:   llAddr,
			Port: dhcpv6.DefaultClientPort,
			// HACK: Zone should ideally be cfg.InterfaceName, but Go’s
			// ipv6ZoneCache is only updated every 60s, so the addition of the
			// veth interface will not be picked up for all tests after the
			// first test.
			Zone: strconv.Itoa(iface.Index),
		}
	}

	// if no RemoteAddr is specified, use AllDHCPRelayAgentsAndServers
	raddr := cfg.RemoteAddr
	if raddr == nil {
		raddr = &net.UDPAddr{
			IP:   dhcpv6.AllDHCPRelayAgentsAndServers,
			Port: dhcpv6.DefaultServerPort,
		}
	}

	var duid *dhcpv6.Duid
	if cfg.DUID != nil {
		var err error
		duid, err = dhcpv6.DuidFromBytes(cfg.DUID)
		if err != nil {
			return nil, err
		}
		fmt.Printf("duid: %T, %v, %#v", duid, duid, duid)
	} else {
		iface, err := net.InterfaceByName(cfg.InterfaceName)
		if err != nil {
			return nil, err
		}

		duid = &dhcpv6.Duid{
			Type:          dhcpv6.DUID_LLT,
			HwType:        iana.HwTypeEthernet,
			Time:          dhcpv6.GetTime(),
			LinkLayerAddr: iface.HardwareAddr,
		}
	}

	// prepare the socket to listen on for replies
	conn := cfg.Conn
	if conn == nil {
		udpConn, err := net.ListenUDP("udp6", laddr)
		if err != nil {
			return nil, err
		}
		conn = udpConn
	}

	return &Client{
		interfaceName:  cfg.InterfaceName,
		timeNow:        time.Now,
		raddr:          raddr,
		Conn:           conn,
		duid:           duid,
		transactionIDs: cfg.TransactionIDs,
		ReadTimeout:    dhcpv6.DefaultReadTimeout,
		WriteTimeout:   dhcpv6.DefaultWriteTimeout,
	}, nil
}

func (c *Client) Close() error {
	return c.Conn.Close()
}

const maxUDPReceivedPacketSize = 8192 // arbitrary size. Theoretically could be up to 65kb

func (c *Client) sendReceive(packet dhcpv6.DHCPv6, expectedType dhcpv6.MessageType) (dhcpv6.DHCPv6, error) {
	if packet == nil {
		return nil, fmt.Errorf("Packet to send cannot be nil")
	}
	if expectedType == dhcpv6.MessageTypeNone {
		// infer the expected type from the packet being sent
		if packet.Type() == dhcpv6.MessageTypeSolicit {
			expectedType = dhcpv6.MessageTypeAdvertise
		} else if packet.Type() == dhcpv6.MessageTypeRequest {
			expectedType = dhcpv6.MessageTypeReply
		} else if packet.Type() == dhcpv6.MessageTypeRelayForward {
			expectedType = dhcpv6.MessageTypeRelayReply
		} else if packet.Type() == dhcpv6.MessageTypeLeaseQuery {
			expectedType = dhcpv6.MessageTypeLeaseQueryReply
		} // and probably more
	}

	// send the packet out
	c.Conn.SetWriteDeadline(time.Now().Add(c.WriteTimeout))
	if _, err := c.Conn.WriteTo(packet.ToBytes(), c.raddr); err != nil {
		return nil, err
	}

	// wait for a reply
	c.Conn.SetReadDeadline(time.Now().Add(c.ReadTimeout))
	var (
		adv       dhcpv6.DHCPv6
		isMessage bool
	)
	msg, ok := packet.(*dhcpv6.DHCPv6Message)
	if ok {
		isMessage = true
	}
	for {
		buf := make([]byte, maxUDPReceivedPacketSize)
		n, _, err := c.Conn.ReadFrom(buf)
		if err != nil {
			return nil, err
		}
		adv, err = dhcpv6.FromBytes(buf[:n])
		if err != nil {
			log.Printf("non-DHCP: %v", err)
			// skip non-DHCP packets
			continue
		}
		if recvMsg, ok := adv.(*dhcpv6.DHCPv6Message); ok && isMessage {
			// if a regular message, check the transaction ID first
			// XXX should this unpack relay messages and check the XID of the
			// inner packet too?
			if msg.TransactionID() != recvMsg.TransactionID() {
				log.Printf("different XID: got %v, want %v", recvMsg.TransactionID(), msg.TransactionID())
				// different XID, we don't want this packet for sure
				continue
			}
		}
		if expectedType == dhcpv6.MessageTypeNone {
			// just take whatever arrived
			break
		} else if adv.Type() == expectedType {
			break
		}
	}
	return adv, nil
}

func (c *Client) solicit(solicit dhcpv6.DHCPv6) (dhcpv6.DHCPv6, dhcpv6.DHCPv6, error) {
	var err error
	if solicit == nil {
		solicit, err = dhcpv6.NewSolicitForInterface(c.interfaceName, dhcpv6.WithClientID(*c.duid))
		if err != nil {
			return nil, nil, err
		}
	}
	if len(c.transactionIDs) > 0 {
		id := c.transactionIDs[0]
		c.transactionIDs = c.transactionIDs[1:]
		solicit.(*dhcpv6.DHCPv6Message).SetTransactionID(id)
	}
	iapd := []byte{0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	opt, err := dhcpv6.ParseOptIAForPrefixDelegation(iapd)
	if err != nil {
		return nil, nil, err
	}
	solicit.AddOption(opt)
	advertise, err := c.sendReceive(solicit, dhcpv6.MessageTypeNone)
	return solicit, advertise, err
}

func (c *Client) request(advertise dhcpv6.DHCPv6) (dhcpv6.DHCPv6, dhcpv6.DHCPv6, error) {

	request, err := dhcpv6.NewRequestFromAdvertise(advertise, dhcpv6.WithClientID(*c.duid))
	if err != nil {
		return nil, nil, err
	}
	if iapd := advertise.GetOneOption(dhcpv6.OptionIAPD); iapd != nil {
		request.AddOption(iapd)
	}

	if len(c.transactionIDs) > 0 {
		id := c.transactionIDs[0]
		c.transactionIDs = c.transactionIDs[1:]
		request.(*dhcpv6.DHCPv6Message).SetTransactionID(id)
	}
	reply, err := c.sendReceive(request, dhcpv6.MessageTypeNone)
	return request, reply, err
}

func (c *Client) ObtainOrRenew() bool {
	c.err = nil // clear previous error
	_, advertise, err := c.solicit(nil)
	if err != nil {
		c.err = err
		return true
	}

	c.advertise = advertise
	_, reply, err := c.request(advertise)
	if err != nil {
		c.err = err
		return true
	}
	var newCfg Config
	for _, opt := range reply.Options() {
		switch o := opt.(type) {
		case *dhcpv6.OptIAForPrefixDelegation:
			t1 := c.timeNow().Add(time.Duration(o.T1()) * time.Second)
			if t1.Before(newCfg.RenewAfter) || newCfg.RenewAfter.IsZero() {
				newCfg.RenewAfter = t1
			}
			for b := o.Options(); len(b) > 0; {
				sopt, err := dhcpv6.ParseOption(b)
				if err != nil {
					c.err = err
					return true
				}
				b = b[4+sopt.Length():]

				prefix, ok := sopt.(*dhcpv6.OptIAPrefix)
				if !ok {
					continue
				}

				newCfg.Prefixes = append(newCfg.Prefixes, net.IPNet{
					IP:   prefix.IPv6Prefix(),
					Mask: net.CIDRMask(int(prefix.PrefixLength()), 128),
				})
			}

		case *dhcpv6.OptDNSRecursiveNameServer:
			for _, ns := range o.NameServers {
				newCfg.DNS = append(newCfg.DNS, ns.String())
			}
		}
	}
	c.cfg = newCfg
	return true
}

func (c *Client) Release() (release dhcpv6.DHCPv6, reply dhcpv6.DHCPv6, err error) {
	release, err = dhcpv6.NewRequestFromAdvertise(c.advertise, dhcpv6.WithClientID(*c.duid))
	if err != nil {
		return nil, nil, err
	}
	release.(*dhcpv6.DHCPv6Message).SetMessage(dhcpv6.MessageTypeRelease)

	if len(c.transactionIDs) > 0 {
		id := c.transactionIDs[0]
		c.transactionIDs = c.transactionIDs[1:]
		release.(*dhcpv6.DHCPv6Message).SetTransactionID(id)
	}
	reply, err = c.sendReceive(release, dhcpv6.MessageTypeNone)
	return release, reply, err
}

func (c *Client) Err() error {
	return c.err
}

func (c *Client) Config() Config {
	return c.cfg
}
