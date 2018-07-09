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

package integration_test

import (
	"os"
	"os/exec"
	"regexp"
	"strings"
	"testing"

	"github.com/rtr7/router7/internal/dhcp6"
	"github.com/rtr7/router7/internal/testing/dnsmasq"

	"github.com/google/go-cmp/cmp"
)

var v6AddrRe = regexp.MustCompile(`2001:db8::[^ ]+`)

func TestDHCPv6(t *testing.T) {
	const ns = "ns1" // name of the network namespace to use for this test

	if err := exec.Command("ip", "netns", "add", ns).Run(); err != nil {
		t.Fatalf("ip netns add %s: %v", ns, err)
	}
	defer exec.Command("ip", "netns", "delete", ns).Run()

	nsSetup := []*exec.Cmd{
		exec.Command("ip", "link", "add", "veth1a", "type", "veth", "peer", "name", "veth1b", "netns", ns),

		// Disable Duplicate Address Detection: until DAD completes, the link-local
		// address remains in state “tentative”, resulting in any attempts to
		// bind(2) to the address to fail with -EADDRNOTAVAIL.
		exec.Command("/bin/sh", "-c", "echo 0 > /proc/sys/net/ipv6/conf/veth1a/accept_dad"),
		exec.Command("ip", "netns", "exec", ns, "/bin/sh", "-c", "echo 0 > /proc/sys/net/ipv6/conf/veth1b/accept_dad"),

		exec.Command("ip", "link", "set", "veth1a", "up"),
		exec.Command("ip", "netns", "exec", ns, "ip", "addr", "add", "192.168.23.1/24", "dev", "veth1b"),
		exec.Command("ip", "netns", "exec", ns, "ip", "addr", "add", "2001:db8::1/64", "dev", "veth1b"),
		exec.Command("ip", "netns", "exec", ns, "ip", "link", "set", "veth1b", "up"),
	}

	for _, cmd := range nsSetup {
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			t.Fatalf("%v: %v", cmd.Args, err)
		}
	}

	dnsmasq := dnsmasq.Run(t, "veth1b", ns)
	defer dnsmasq.Kill()

	// f, err := os.Create("/tmp/pcap6")
	// if err != nil {
	// 	t.Fatal(err)
	// }
	// defer f.Close()
	// pcapw := pcapgo.NewWriter(f)
	// if err := pcapw.WriteFileHeader(1600, layers.LinkTypeEthernet); err != nil {
	// 	t.Fatal(err)
	// }
	// handle, err := pcap.OpenLive("veth0a", 1600, true, pcap.BlockForever)
	// if err != nil {
	// 	t.Fatal(err)
	// }
	// pkgsrc := gopacket.NewPacketSource(handle, handle.LinkType())
	// closed := make(chan struct{})
	// go func() {
	// 	for packet := range pkgsrc.Packets() {
	// 		//if packet.Layer(layers.LayerTypeDHCPv6) != nil {
	// 		fmt.Printf("packet: %+v\n", packet)
	// 		if err := pcapw.WritePacket(packet.Metadata().CaptureInfo, packet.Data()); err != nil {
	// 			t.Fatalf("pcap.WritePacket(): %v", err)
	// 		}
	// 		//}
	// 	}
	// 	close(closed)
	// }()
	// // TODO: test the capture daemon
	// defer func() {
	// 	time.Sleep(1 * time.Second)
	// 	handle.Close()
	// 	<-closed
	// }()

	duid := []byte{0x00, 0x0a, 0x00, 0x03, 0x00, 0x01, 0x4c, 0x5e, 0xc, 0x41, 0xbf, 0x39}
	c, err := dhcp6.NewClient(dhcp6.ClientConfig{
		InterfaceName: "veth1a",
		DUID:          duid,
	})
	if err != nil {
		t.Fatal(err)
	}
	c.ObtainOrRenew()
	if err := c.Err(); err != nil {
		t.Fatal(err)
	}
	got := c.Config()
	want := dhcp6.Config{
		DNS: []string{"2001:db8::1"},
	}
	if diff := cmp.Diff(got, want); diff != "" {
		t.Fatalf("unexpected config: diff (-got +want):\n%s", diff)
	}

	c.Release()

	{
		dnsmasq.Kill() // flush log
		got := dnsmasq.Actions()
		want := []string{
			"DHCPSOLICIT(veth1b) 00:0a:00:03:00:01:4c:5e:0c:41:bf:39",
			"DHCPADVERTISE(veth1b) 2001:db8::c 00:0a:00:03:00:01:4c:5e:0c:41:bf:39",
			"DHCPREQUEST(veth1b) 00:0a:00:03:00:01:4c:5e:0c:41:bf:39",
			"DHCPREPLY(veth1b) 2001:db8::c 00:0a:00:03:00:01:4c:5e:0c:41:bf:39",
			"DHCPRELEASE(veth1b) 00:0a:00:03:00:01:4c:5e:0c:41:bf:39",
		}
		withoutMac := func(line string) string {
			return v6AddrRe.ReplaceAllString(strings.TrimSpace(line), "")
		}
		if diff := cmp.Diff(got, want, cmp.Transformer("WithoutMAC", withoutMac)); diff != "" {
			t.Errorf("dnsmasq log does not contain expected DHCP sequence: diff (-got +want):\n%s", diff)
		}
	}
}
