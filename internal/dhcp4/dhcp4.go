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

// Package dhcp4 implements a DHCPv4 client.
package dhcp4

import (
	"bytes"
	"fmt"
	"log"
	"net"
	"sync"
	"syscall"
	"time"

	"github.com/google/gopacket/layers"
	"github.com/mdlayher/raw"
	"github.com/rtr7/dhcp4"
	"golang.org/x/sys/unix"
)

type Config struct {
	RenewAfter time.Time `json:"valid_until"`
	ClientIP   string    `json:"client_ip"`   // e.g. 85.195.207.62
	SubnetMask string    `json:"subnet_mask"` // e.g. 255.255.255.128
	Router     string    `json:"router"`      // e.g. 85.195.207.1
	DNS        []string  `json:"dns"`         // e.g. 77.109.128.2, 213.144.129.20
}

type Client struct {
	Interface *net.Interface // e.g. net.InterfaceByName("eth0")

	err          error
	once         sync.Once
	connection   net.PacketConn
	hardwareAddr net.HardwareAddr
	hostname     string
	cfg          Config
	timeNow      func() time.Time
	generateXID  func() uint32

	// last DHCPACK packet for renewal/release
	Ack *layers.DHCPv4
}

func serverID(pkt *layers.DHCPv4) []layers.DHCPOption {
	for _, o := range pkt.Options {
		if o.Type == layers.DHCPOptServerID {
			return []layers.DHCPOption{o}
		}
	}
	return nil
}

func (c *Client) packet(xid uint32, opts []layers.DHCPOption) *layers.DHCPv4 {
	return &layers.DHCPv4{
		Operation:    layers.DHCPOpRequest,
		HardwareType: layers.LinkTypeEthernet,
		HardwareLen:  uint8(len(layers.EthernetBroadcast)),
		HardwareOpts: 0, // clients set this to zero (used by relay agents)
		Xid:          xid,
		Secs:         0, // TODO: fill in?
		Flags:        0, // we can receive IP packets via unicast
		ClientHWAddr: c.hardwareAddr,
		ServerName:   nil,
		File:         nil,
		Options:      opts,
	}
}

// ObtainOrRenew returns false when encountering a permanent error.
func (c *Client) ObtainOrRenew() bool {
	c.once.Do(func() {
		if c.timeNow == nil {
			c.timeNow = time.Now
		}
		if c.connection == nil && c.Interface != nil {
			conn, err := raw.ListenPacket(c.Interface, syscall.ETH_P_IP, &raw.Config{
				LinuxSockDGRAM: true,
			})
			if err != nil {
				c.err = err
				return
			}
			c.connection = conn
		}
		if c.connection == nil && c.Interface == nil {
			c.err = fmt.Errorf("Interface is nil")
			return
		}
		if c.hardwareAddr == nil {
			c.hardwareAddr = c.Interface.HardwareAddr
		}
		if c.generateXID == nil {
			c.generateXID = dhcp4.XIDGenerator(c.hardwareAddr)
		}
		if c.hostname == "" {
			var utsname unix.Utsname
			if err := unix.Uname(&utsname); err != nil {
				log.Fatal(err)
			}
			c.hostname = string(utsname.Nodename[:bytes.IndexByte(utsname.Nodename[:], 0)])
		}
	})
	// TODO: handle c.err from c.once
	c.err = nil // clear previous error
	ack, err := c.dhcpRequest()
	if err != nil {
		if errno, ok := err.(syscall.Errno); ok && errno == syscall.EAGAIN {
			c.err = fmt.Errorf("DHCP: timeout (server(s) unreachable)")
			return true // temporary error
		}
		c.err = fmt.Errorf("DHCP: %v", err)
		return true // temporary error
	}
	c.Ack = ack
	c.cfg.ClientIP = ack.YourClientIP.String()
	lease := dhcp4.LeaseFromACK(ack)
	if mask := lease.Netmask; len(mask) > 0 {
		c.cfg.SubnetMask = fmt.Sprintf("%d.%d.%d.%d", mask[0], mask[1], mask[2], mask[3])
	}
	if len(lease.Router) > 0 {
		c.cfg.Router = lease.Router.String()
	}
	if len(lease.DNS) > 0 {
		c.cfg.DNS = make([]string, len(lease.DNS))
		for idx, ip := range lease.DNS {
			c.cfg.DNS[idx] = ip.String()
		}
	}
	c.cfg.RenewAfter = c.timeNow().Add(lease.RenewalTime)
	return true
}

func (c *Client) Release() error {
	release := c.packet(c.generateXID(), append([]layers.DHCPOption{
		dhcp4.MessageTypeOpt(layers.DHCPMsgTypeRelease),
	}, serverID(c.Ack)...))
	release.ClientIP = c.Ack.YourClientIP
	if err := dhcp4.Write(c.connection, release); err != nil {
		return err
	}

	c.Ack = nil
	return nil
}

func (c *Client) Err() error {
	return c.err
}

func (c *Client) Config() Config {
	return c.cfg
}

func (c *Client) dhcpRequest() (*layers.DHCPv4, error) {
	var last *layers.DHCPv4

	if c.Ack != nil {
		last = c.Ack
	} else {
		discover := c.packet(c.generateXID(), []layers.DHCPOption{
			dhcp4.MessageTypeOpt(layers.DHCPMsgTypeDiscover),
			dhcp4.HostnameOpt(c.hostname),
			dhcp4.ClientIDOpt(layers.LinkTypeEthernet, c.hardwareAddr),
			dhcp4.ParamsRequestOpt(
				layers.DHCPOptDNS,
				layers.DHCPOptRouter,
				layers.DHCPOptSubnetMask),
		})
		if err := dhcp4.Write(c.connection, discover); err != nil {
			return nil, err
		}

		// Look for DHCPOFFER packet (described in RFC2131 4.3.1):
		c.connection.SetDeadline(time.Now().Add(10 * time.Second))
		for {
			offer, err := dhcp4.Read(c.connection)
			if err != nil {
				return nil, err
			}
			if offer == nil {
				continue // not a DHCPv4 packet
			}
			if offer.Xid != discover.Xid {
				continue // broadcast reply for different DHCP transaction
			}
			if !dhcp4.HasMessageType(offer.Options, layers.DHCPMsgTypeOffer) {
				continue
			}
			last = offer
			break
		}
	}

	// Build a DHCPREQUEST packet:
	request := c.packet(last.Xid, append([]layers.DHCPOption{
		dhcp4.MessageTypeOpt(layers.DHCPMsgTypeRequest),
		dhcp4.RequestIPOpt(last.YourClientIP),
		dhcp4.HostnameOpt(c.hostname),
		dhcp4.ClientIDOpt(layers.LinkTypeEthernet, c.hardwareAddr),
		dhcp4.ParamsRequestOpt(
			layers.DHCPOptDNS,
			layers.DHCPOptRouter,
			layers.DHCPOptSubnetMask),
	}, serverID(last)...))
	if err := dhcp4.Write(c.connection, request); err != nil {
		return nil, err
	}

	c.connection.SetDeadline(time.Now().Add(10 * time.Second))
	for {
		// Look for DHCPACK packet (described in RFC2131 4.3.1):
		ack, err := dhcp4.Read(c.connection)
		if err != nil {
			return nil, err
		}
		if ack == nil {
			continue // not a DHCPv4 packet
		}
		if ack.Xid != request.Xid {
			continue // broadcast reply for different DHCP transaction
		}
		if !dhcp4.HasMessageType(ack.Options, layers.DHCPMsgTypeAck) {
			continue
		}
		return ack, nil
	}
}
