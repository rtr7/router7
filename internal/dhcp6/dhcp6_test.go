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

package dhcp6

import (
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/insomniacslk/dhcp/dhcpv6"
	"github.com/rtr7/router7/internal/testing/pcapreplayer"
)

func TestDHCP6(t *testing.T) {
	pcappath := os.Getenv("ROUTER7_PCAP_DIR")
	if pcappath != "" {
		pcappath = filepath.Join(pcappath, "dhcp6.pcap")
	}
	conn, err := pcapreplayer.NewPacketConn("testdata/fiber7.pcap", pcappath)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	laddr, err := net.ResolveUDPAddr("udp6", "[fe80::42:aff:fea5:966e]:546")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	c, err := NewClient(ClientConfig{
		// NOTE(stapelberg): dhcpv6.NewSolicitForInterface requires an interface
		// name to get the MAC address.
		InterfaceName: "lo",
		LocalAddr:     laddr,
		Conn:          conn,
		TransactionIDs: []dhcpv6.TransactionID{
			{0x48, 0xe5, 0x9e}, // SOLICIT
			{0x73, 0x8c, 0x3b}, // REQUEST
		},
		HardwareAddr: []byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66},
	})
	if err != nil {
		t.Fatal(err)
	}
	c.timeNow = func() time.Time { return now }

	c.ObtainOrRenew()
	if err := c.Err(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	got := c.Config()
	want := Config{
		RenewAfter: now.Add(20 * time.Minute),
		Prefixes: []net.IPNet{
			mustParseCIDR("2a02:168:4a00::/48"),
		},
		DNS: []string{
			"2001:1620:2777:1::10",
			"2001:1620:2777:2::20",
		},
	}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Fatalf("unexpected config: diff (-want +got):\n%s", diff)
	}
}

func mustParseCIDR(s string) net.IPNet {
	_, net, err := net.ParseCIDR(s)
	if err != nil {
		panic(err)
	}
	return *net
}
