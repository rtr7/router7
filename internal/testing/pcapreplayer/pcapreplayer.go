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

// Package pcapreplayer provides a net.PacketConn which replays a pcap file, and
// optionally records a new golden file.
package pcapreplayer

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

func pcapopen(input, output string) (*pcapgo.Reader, *pcapgo.Writer, error) {
	f, err := os.Open(input)
	if err != nil {
		return nil, nil, err
	}
	pcapr, err := pcapgo.NewReader(f)
	if err != nil {
		return nil, nil, err
	}

	var pcapw *pcapgo.Writer
	if output != "" {
		if err := os.MkdirAll(filepath.Dir(output), 0755); err != nil {
			return nil, nil, err
		}
		of, err := os.Create(output)
		if err != nil {
			return nil, nil, err
		}
		pcapw = pcapgo.NewWriter(of)
		if err := pcapw.WriteFileHeader(1600, layers.LinkTypeEthernet); err != nil {
			return nil, nil, err
		}
	}
	return pcapr, pcapw, nil
}

func readFrom(r *pcapgo.Reader, buf []byte) (int, net.IP, error) {
	data, _, err := r.ReadPacketData()
	if err != nil {
		return 0, nil, err
	}
	pkt := gopacket.NewPacket(data, layers.LayerTypeEthernet, gopacket.DecodeOptions{})
	// TODO: get source IP
	udp := pkt.Layer(layers.LayerTypeUDP)
	if udp == nil {
		return 0, nil, fmt.Errorf("pcap contained unexpected non-UDP packet")
	}

	//log.Printf("ReadFrom(): %x, %v, pkt = %+v", udp.LayerPayload(), err, pkt)
	copy(buf, udp.LayerPayload())
	return len(udp.LayerPayload()), net.ParseIP("192.168.23.1"), err
}

func mustParseMAC(s string) net.HardwareAddr {
	hw, err := net.ParseMAC(s)
	if err != nil {
		panic(err)
	}
	return hw
}

type layer interface {
	gopacket.NetworkLayer

	// Cannot embed gopacket.SerializableLayer because it includes a conflicting
	// definition of LayerType():
	SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error
}

func pcapwrite(w *pcapgo.Writer, ip layer, udp *layers.UDP, b []byte) error {
	buf := gopacket.NewSerializeBuffer()
	udp.SetNetworkLayerForChecksum(ip)
	var ethernetType layers.EthernetType
	switch ip.LayerType() {
	case layers.LayerTypeIPv4:
		ethernetType = layers.EthernetTypeIPv4
	case layers.LayerTypeIPv6:
		ethernetType = layers.EthernetTypeIPv6
	}
	gopacket.SerializeLayers(buf,
		gopacket.SerializeOptions{
			FixLengths:       true,
			ComputeChecksums: true,
		},
		&layers.Ethernet{
			SrcMAC:       mustParseMAC("00:00:5E:00:53:00"), // RFC7042
			DstMAC:       mustParseMAC("33:33:00:01:00:02"), // IPv6mcast_01:00:02
			EthernetType: ethernetType,
		},
		ip,
		udp,
		gopacket.Payload(b),
	)
	got := buf.Bytes()

	ci := gopacket.CaptureInfo{
		CaptureLength: len(got),
		Length:        len(got),
	}
	if err := w.WritePacket(ci, got); err != nil {
		return fmt.Errorf("pcap.WritePacket(): %v", err)
	}
	return nil
}

// packetConn is a net.PacketConn which replays a pcap file.
type packetConn struct {
	pcapr *pcapgo.Reader
	pcapw *pcapgo.Writer
}

// NewPacketConn returns a net.PacketConn which replays packets from pcap file input,
// writing packets to pcap file output (if non-empty).
//
// See https://en.wikipedia.org/wiki/Pcap for details on pcap.
func NewPacketConn(input, output string) (net.PacketConn, error) {
	pcapr, pcapw, err := pcapopen(input, output)
	return &packetConn{pcapr, pcapw}, err
}

func (r *packetConn) LocalAddr() net.Addr                { return nil }
func (r *packetConn) Close() error                       { return nil }
func (r *packetConn) SetDeadline(t time.Time) error      { return nil }
func (r *packetConn) SetReadDeadline(t time.Time) error  { return nil }
func (r *packetConn) SetWriteDeadline(t time.Time) error { return nil }

func (r *packetConn) WriteTo(b []byte, addr net.Addr) (n int, err error) {
	if r.pcapw == nil {
		return len(b), nil
	}

	return len(b), pcapwrite(r.pcapw,
		&layers.IPv6{
			Version:      6,
			TrafficClass: 0,
			NextHeader:   layers.IPProtocolUDP,
			HopLimit:     1,
			SrcIP:        net.ParseIP("fe80::200:5eff:fe00:5300"),
			DstIP:        net.ParseIP("ff02::1:2"),
		},
		&layers.UDP{
			SrcPort: 546,
			DstPort: 547,
		},
		b)
}

func (r *packetConn) ReadFrom(buf []byte) (int, net.Addr, error) {
	l, ip, err := readFrom(r.pcapr, buf)
	return l, &net.IPAddr{IP: ip}, err
}

// dhcp4conn is a dhcp4client.ConnectionInt which replays a pcap file.
type dhcp4conn struct {
	pcapr *pcapgo.Reader
	pcapw *pcapgo.Writer
}

// NewDHCP4Conn returns a dhcp4client.ConnectionInt which replays packets from
// pcap file input, writing packets to pcap file output (if non-empty).
//
// See https://en.wikipedia.org/wiki/Pcap for details on pcap.
func NewDHCP4Conn(input, output string) (net.PacketConn, error) {
	pcapr, pcapw, err := pcapopen(input, output)
	return &dhcp4conn{pcapr: pcapr, pcapw: pcapw}, err
}

func (r *dhcp4conn) LocalAddr() net.Addr                { return nil }
func (r *dhcp4conn) Close() error                       { return nil }
func (r *dhcp4conn) SetDeadline(t time.Time) error      { return nil }
func (r *dhcp4conn) SetReadDeadline(t time.Time) error  { return nil }
func (r *dhcp4conn) SetWriteDeadline(t time.Time) error { return nil }

func (r *dhcp4conn) WriteTo(b []byte, addr net.Addr) (n int, err error) {
	if r.pcapw == nil {
		return len(b), nil
	}

	return len(b), pcapwrite(r.pcapw,
		&layers.IPv4{
			Version:  4,
			TTL:      255,
			Protocol: layers.IPProtocolUDP,
			SrcIP:    net.ParseIP("0.0.0.0"),
			DstIP:    net.ParseIP("255.255.255.255"),
		},
		&layers.UDP{
			SrcPort: 68,
			DstPort: 67,
		},
		b)
}

func (r *dhcp4conn) ReadFrom(buf []byte) (int, net.Addr, error) {
	data, _, err := r.pcapr.ReadPacketData()
	if err != nil {
		return 0, nil, err
	}
	pkt := gopacket.NewPacket(data, layers.LayerTypeEthernet, gopacket.DecodeOptions{})
	// TODO: get source IP
	eth := pkt.Layer(layers.LayerTypeEthernet)
	if eth == nil {
		return 0, nil, fmt.Errorf("pcap contained unexpected non-IPv4 packet")
	}

	//log.Printf("ReadFrom(): %x, %v, pkt = %+v", udp.LayerPayload(), err, pkt)
	copy(buf, eth.LayerPayload())
	ip := net.ParseIP("192.168.23.1")
	return len(eth.LayerPayload()), &net.IPAddr{IP: ip}, nil
}
