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

package wg

import (
	"fmt"
	"net"
	"unsafe"

	"github.com/google/nftables/binaryutil"
	"github.com/mdlayher/genetlink"
	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
)

func allowedIPFromNet(n *net.IPNet) ([]byte, error) {
	ones, _ := n.Mask.Size()
	family := uint16(unix.AF_INET)
	if n.IP.To4() == nil {
		family = unix.AF_INET6
	}
	return netlink.MarshalAttributes([]netlink.Attribute{
		{Type: wgallowedip_a_family, Data: binaryutil.NativeEndian.PutUint16(family)},
		{Type: wgallowedip_a_ipaddr, Data: n.IP},
		{Type: wgallowedip_a_cidr_mask, Data: []byte{byte(ones)}},
	})
}

func sockaddrFromEndpoint(endpoint string) ([]byte, error) {
	host, service, err := net.SplitHostPort(endpoint)
	if err != nil {
		return nil, err
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return nil, fmt.Errorf("invalid endpoint %q: %q is not an IP", endpoint, host)
	}
	port, err := net.LookupPort("udp4", service)
	if err != nil {
		return nil, err
	}
	if ip.To4() == nil {
		addr := unix.RawSockaddrInet6{
			Family: unix.AF_INET6,
			Port:   uint16((port&0xFF)<<8) | uint16((port&0xFF00)>>8),
			Addr: func() [16]byte {
				var buf [16]byte
				copy(buf[:], ip)
				return buf
			}(),
		}
		sap := (*[28]byte)(unsafe.Pointer(&addr))
		return (*sap)[:], nil
	} else {
		addr := unix.RawSockaddrInet4{
			Family: unix.AF_INET,
			Port:   uint16((port&0xFF)<<8) | uint16((port&0xFF00)>>8),
			Addr: func() [4]byte {
				var buf [4]byte
				copy(buf[:], ip.To4())
				return buf
			}(),
		}
		sap := (*[16]byte)(unsafe.Pointer(&addr))
		return (*sap)[:], nil
	}
}

func SetDevice(conn *genetlink.Conn, d *Device) error {
	family, err := conn.GetFamily("wireguard")
	if err != nil {
		return err
	}

	var peers []netlink.Attribute
	for _, p := range d.Peers {
		var ips []netlink.Attribute
		for _, net := range p.AllowedIPs {
			allowedIP, err := allowedIPFromNet(net)
			if err != nil {
				return err
			}
			ips = append(ips, netlink.Attribute{Type: unix.NLA_F_NESTED, Data: allowedIP})
		}
		allowedIPs, err := netlink.MarshalAttributes(ips)
		if err != nil {
			return err
		}

		attrs := []netlink.Attribute{
			{Type: wgpeer_a_public_key, Data: p.PublicKey},
			{Type: wgpeer_a_flags, Data: binaryutil.NativeEndian.PutUint32(0)},

			{Type: wgpeer_a_persistent_keepalive_interval, Data: binaryutil.NativeEndian.PutUint16(0)},
			{Type: wgpeer_a_allowedips, Data: allowedIPs},
		}
		if p.Endpoint != "" {
			sockaddr, err := sockaddrFromEndpoint(p.Endpoint)
			if err != nil {
				return err
			}
			attrs = append(attrs, netlink.Attribute{Type: wgpeer_a_endpoint, Data: sockaddr})
		}
		peer, err := netlink.MarshalAttributes(attrs)
		if err != nil {
			return err
		}
		peers = append(peers, netlink.Attribute{Type: unix.NLA_F_NESTED, Data: peer})
	}
	peersData, err := netlink.MarshalAttributes(peers)
	if err != nil {
		return err
	}

	data, err := netlink.MarshalAttributes([]netlink.Attribute{
		{Type: wgdevice_a_ifname, Data: []byte(d.Ifname + "\x00")},
		{Type: wgdevice_a_flags, Data: binaryutil.NativeEndian.PutUint32(0)},
		{Type: wgdevice_a_private_key, Data: d.PrivateKey},
		{Type: wgdevice_a_listen_port, Data: binaryutil.NativeEndian.PutUint16(d.ListenPort)},
		{Type: wgdevice_a_fwmark, Data: binaryutil.NativeEndian.PutUint32(0)},
		{Type: unix.NLA_F_NESTED | wgdevice_a_peers, Data: peersData},
	})
	if err != nil {
		return err
	}
	get := genetlink.Message{
		Header: genetlink.Header{
			Command: wg_cmd_set_device,
			Version: family.Version,
		},
		Data: data,
	}

	const flags = netlink.Request | netlink.Acknowledge
	reply, err := conn.Execute(get, family.ID, flags)
	if err != nil {
		return err
	}
	if got, want := len(reply), 1; got != want {
		return fmt.Errorf("unexpected number of replies: got %d, want %d", got, want)
	}
	return nil
}
