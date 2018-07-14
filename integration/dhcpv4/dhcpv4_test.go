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
	"io/ioutil"
	"net"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/rtr7/router7/internal/dhcp4"
	"github.com/rtr7/router7/internal/testing/dnsmasq"

	"github.com/google/go-cmp/cmp"
)

func TestDHCPv4(t *testing.T) {
	const ns = "ns0" // name of the network namespace to use for this test

	add := exec.Command("ip", "netns", "add", ns)
	add.Stderr = os.Stderr
	if err := add.Run(); err != nil {
		t.Fatalf("%v: %v", add.Args, err)
	}
	defer exec.Command("ip", "netns", "delete", ns).Run()

	nsSetup := []*exec.Cmd{
		exec.Command("ip", "link", "add", "veth0a", "type", "veth", "peer", "name", "veth0b", "netns", ns),
		exec.Command("ip", "link", "set", "veth0a", "up"),
		exec.Command("ip", "link", "set", "veth0a", "address", "02:73:53:00:ca:fe"),
		exec.Command("ip", "netns", "exec", ns, "ip", "addr", "add", "192.168.23.1/24", "dev", "veth0b"),
		exec.Command("ip", "netns", "exec", ns, "ip", "link", "set", "veth0b", "up"),
		exec.Command("ip", "netns", "exec", ns, "ip", "link", "set", "veth0b"),
	}

	for _, cmd := range nsSetup {
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			t.Fatalf("%v: %v", cmd.Args, err)
		}
	}

	ready, err := ioutil.TempFile("", "router7")
	if err != nil {
		t.Fatal(err)
	}
	ready.Close()                 // dnsmasq will re-create the file anyway
	defer os.Remove(ready.Name()) // dnsmasq does not clean up its pid file

	dnsmasq := dnsmasq.Run(t, "veth0b", ns)
	defer dnsmasq.Kill()

	// f, err := os.Create("/tmp/pcap")
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
	// 		if packet.Layer(layers.LayerTypeDHCPv4) != nil {
	// 			log.Printf("packet: %+v", packet)
	// 			if err := pcapw.WritePacket(packet.Metadata().CaptureInfo, packet.Data()); err != nil {
	// 				t.Fatalf("pcap.WritePacket(): %v", err)
	// 			}
	// 		}
	// 	}
	// 	close(closed)
	// }()
	// // TODO: test the capture daemon
	// defer func() {
	// time.Sleep(1 * time.Second)
	// handle.Close()
	// 	<-closed
	// }()

	iface, err := net.InterfaceByName("veth0a")
	if err != nil {
		t.Fatal(err)
	}
	c := dhcp4.Client{
		Interface: iface,
	}
	// Obtain first, then renew
	for i := 0; i < 2; i++ {
		if !c.ObtainOrRenew() {
			t.Fatal(c.Err())
		}
		if err := c.Err(); err != nil {
			t.Fatal(err)
		}
	}

	// Renew once more, but with a new client object (simulating a dhcp4 process
	// restart).
	ack := c.Ack
	c = dhcp4.Client{
		Interface: iface,
		Ack:       ack,
	}
	if !c.ObtainOrRenew() {
		t.Fatal(c.Err())
	}
	if err := c.Err(); err != nil {
		t.Fatal(err)
	}

	cfg := c.Config()
	if got, want := cfg.Router, "192.168.23.1"; got != want {
		t.Errorf("config: unexpected router: got %q, want %q", got, want)
	}

	if err := c.Release(); err != nil {
		t.Fatal(err)
	}

	// TODO: use inotify on the leases db to wait for this event
	// TODO: alternatively, replace bytes.Buffer with a pipe and read from that
	time.Sleep(100 * time.Millisecond) // give dnsmasq some time to process the DHCPRELEASE

	dnsmasq.Kill() // to flush logs
	got := dnsmasq.Actions()
	want := []string{
		"DHCPDISCOVER(veth0b) 02:73:53:00:ca:fe",
		"DHCPOFFER(veth0b) 192.168.23.4 02:73:53:00:ca:fe",
		"DHCPREQUEST(veth0b) 192.168.23.4 02:73:53:00:ca:fe",
		"DHCPACK(veth0b) 192.168.23.4 02:73:53:00:ca:fe midna",

		"DHCPREQUEST(veth0b) 192.168.23.4 02:73:53:00:ca:fe",
		"DHCPACK(veth0b) 192.168.23.4 02:73:53:00:ca:fe midna",

		"DHCPREQUEST(veth0b) 192.168.23.4 02:73:53:00:ca:fe",
		"DHCPACK(veth0b) 192.168.23.4 02:73:53:00:ca:fe midna",

		"DHCPRELEASE(veth0b) 192.168.23.4 02:73:53:00:ca:fe",
	}
	trimSpace := func(line string) string {
		return strings.TrimSpace(line)
	}
	if diff := cmp.Diff(got, want, cmp.Transformer("TrimSpace", trimSpace)); diff != "" {
		t.Errorf("dnsmasq log does not contain expected DHCP sequence: diff (-got +want):\n%s", diff)
	}
}
