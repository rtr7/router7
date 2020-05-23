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

// Package radvd implements IPv6 router advertisments.
package radvd

import (
	"log"
	"net"
	"sync"
	"time"

	"github.com/mdlayher/ndp"

	"golang.org/x/net/ipv6"
)

type Server struct {
	pc     *ipv6.PacketConn
	ifname string

	mu       sync.Mutex
	prefixes []net.IPNet
	iface    *net.Interface
}

func NewServer() (*Server, error) {
	return &Server{}, nil
}

func (s *Server) SetPrefixes(prefixes []net.IPNet) {
	s.mu.Lock()
	if s.ifname != "" {
		var err error
		// Gather details about the interface again, the MAC address might have been
		// changed.
		s.iface, err = net.InterfaceByName(s.ifname)
		if err != nil {
			log.Fatal(err) // interface vanished
		}
	}
	s.prefixes = prefixes
	s.mu.Unlock()
	if s.iface != nil {
		s.sendAdvertisement(nil)
	}
}

func (s *Server) Serve(ifname string, conn net.PacketConn) error {
	var err error
	s.ifname = ifname
	s.iface, err = net.InterfaceByName(ifname)
	if err != nil {
		return err
	}

	defer conn.Close()
	s.pc = ipv6.NewPacketConn(conn)
	s.pc.SetHopLimit(255)          // as per RFC 4861, section 4.1
	s.pc.SetMulticastHopLimit(255) // as per RFC 4861, section 4.1

	var filter ipv6.ICMPFilter
	filter.SetAll(true)
	filter.Accept(ipv6.ICMPTypeRouterSolicitation)
	if err := s.pc.SetICMPFilter(&filter); err != nil {
		return err
	}

	go func() {
		for {
			s.sendAdvertisement(nil) // TODO: handle error
			time.Sleep(1 * time.Minute)
		}
	}()

	// A 512 bytes buffer is sufficient for router solicitation packets, which
	// are basically empty.
	buf := make([]byte, 512)
	for {
		n, _, addr, err := s.pc.ReadFrom(buf)
		if err != nil {
			return err
		}
		// TODO: isn’t this guaranteed by the filter above?
		if n == 0 ||
			ipv6.ICMPType(buf[0]) != ipv6.ICMPTypeRouterSolicitation {
			continue
		}
		if err := s.sendAdvertisement(addr); err != nil {
			return err
		}
	}

	return nil
}

func (s *Server) ListenAndServe(ifname string) error {
	// TODO(correctness): would it be better to listen on
	// net.IPv6linklocalallrouters? Just specifying that results in an error,
	// though.
	conn, err := net.ListenIP("ip6:ipv6-icmp", &net.IPAddr{net.IPv6unspecified, ""})
	if err != nil {
		return err
	}
	return s.Serve(ifname, conn)
}

var ipv6LinkLocal = func(cidr string) *net.IPNet {
	_, net, err := net.ParseCIDR(cidr)
	if err != nil {
		panic(err)
	}
	return net
}("fe80::/10")

func (s *Server) sendAdvertisement(addr net.Addr) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.prefixes == nil {
		return nil // nothing to do
	}
	if addr == nil {
		addr = &net.IPAddr{
			IP:   net.IPv6linklocalallnodes,
			Zone: s.iface.Name,
		}
	}

	var options []ndp.Option

	if len(s.prefixes) > 0 {
		addrs, err := s.iface.Addrs()
		if err != nil {
			return err
		}
		var linkLocal net.IP
		for _, addr := range addrs {
			ipnet, ok := addr.(*net.IPNet)
			if !ok {
				continue
			}
			if ipv6LinkLocal.Contains(ipnet.IP) {
				linkLocal = ipnet.IP
				break
			}
		}
		if !linkLocal.Equal(net.IPv6zero) {
			options = append(options, &ndp.RecursiveDNSServer{
				Lifetime: 30 * time.Minute,
				Servers:  []net.IP{linkLocal},
			})
		}
	}

	for _, prefix := range s.prefixes {
		ones, _ := prefix.Mask.Size()
		// Use the first /64 subnet within larger prefixes
		if ones < 64 {
			ones = 64
		}

		options = append(options, &ndp.PrefixInformation{
			PrefixLength:                   uint8(ones),
			OnLink:                         true,
			AutonomousAddressConfiguration: true,
			ValidLifetime:                  2 * time.Hour,
			PreferredLifetime:              30 * time.Minute,
			Prefix:                         prefix.IP,
		})
	}

	options = append(options,
		&ndp.DNSSearchList{
			// TODO: audit all lifetimes and express them in relation to each other
			Lifetime: 20 * time.Minute,
			// TODO: single source of truth for search domain name
			DomainNames: []string{"lan"},
		},
		ndp.NewMTU(uint32(s.iface.MTU)),
		&ndp.LinkLayerAddress{
			Direction: ndp.Source,
			Addr:      s.iface.HardwareAddr,
		},
	)

	ra := &ndp.RouterAdvertisement{
		CurrentHopLimit: 64,
		RouterLifetime:  30 * time.Minute,
		Options:         options,
	}

	mb, err := ndp.MarshalMessage(ra)
	if err != nil {
		return err
	}
	log.Printf("sending to %s", addr)
	if _, err := s.pc.WriteTo(mb, nil, addr); err != nil {
		return err
	}
	return nil
}
