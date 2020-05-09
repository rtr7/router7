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
	"testing"

	"github.com/rtr7/router7/internal/radvd"

	"github.com/google/go-cmp/cmp"
)

func TestRouterAdvertisement(t *testing.T) {
	const ns = "ns2" // name of the network namespace to use for this test

	add := exec.Command("ip", "netns", "add", ns)
	add.Stderr = os.Stderr
	if err := add.Run(); err != nil {
		t.Fatalf("%v: %v", add.Args, err)
	}
	defer exec.Command("ip", "netns", "delete", ns).Run()

	nsSetup := []*exec.Cmd{
		exec.Command("ip", "link", "add", "veth2a", "type", "veth", "peer", "name", "veth2b", "netns", ns),

		// Disable Duplicate Address Detection: until DAD completes, the link-local
		// address remains in state “tentative”, resulting in any attempts to
		// bind(2) to the address to fail with -EADDRNOTAVAIL.
		exec.Command("/bin/sh", "-c", "echo 0 > /proc/sys/net/ipv6/conf/veth2a/accept_dad"),
		exec.Command("ip", "netns", "exec", ns, "/bin/sh", "-c", "echo 0 > /proc/sys/net/ipv6/conf/veth2b/accept_dad"),

		exec.Command("ip", "link", "set", "veth2a", "address", "02:73:53:00:ca:fe"),
		exec.Command("ip", "link", "set", "veth2a", "up"),
		exec.Command("ip", "netns", "exec", ns, "ip", "addr", "add", "192.168.23.1/24", "dev", "veth2b"),
		exec.Command("ip", "netns", "exec", ns, "ip", "link", "set", "veth2b", "up"),
		exec.Command("ip", "netns", "exec", ns, "ip", "link", "set", "veth2b"),

		exec.Command("/bin/sh", "-c", "echo 1 > /proc/sys/net/ipv6/conf/veth2a/forwarding"),
	}

	for _, cmd := range nsSetup {
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

	srv, err := radvd.NewServer()
	if err != nil {
		t.Fatal(err)
	}
	srv.SetPrefixes([]net.IPNet{
		net.IPNet{IP: net.ParseIP("2a02:168:4a00::"), Mask: net.CIDRMask(64, 128)},
	})
	conn, err := net.ListenIP("ip6:ipv6-icmp", &net.IPAddr{net.IPv6unspecified, ""})
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		if err := srv.Serve("veth2a", conn); err != nil {
			t.Fatal(err)
		}
	}()
	//time.Sleep(5 * time.Second)
	rdisc6 := exec.Command("ip", "netns", "exec", ns, "rdisc6",
		"--single",     // exit after first router advertisement
		"--retry", "1", // retry only once
		"--wait", "1000", // wait 1s
		"veth2b")
	rdisc6.Stderr = os.Stderr
	b, err := rdisc6.Output()
	if err != nil {
		t.Fatalf("%v: %v (output: %v)", rdisc6.Args, err, string(b))
	}
	got := string(b)
	want := `Soliciting ff02::2 (ff02::2) on veth2b...

Hop limit                 :           64 (      0x40)
Stateful address conf.    :           No
Stateful other conf.      :           No
Mobile home agent         :           No
Router preference         :       medium
Neighbor discovery proxy  :           No
Router lifetime           :         1800 (0x00000708) seconds
Reachable time            :  unspecified (0x00000000)
Retransmit time           :  unspecified (0x00000000)
 Recursive DNS server     : fe80::73:53ff:fe00:cafe
  DNS server lifetime     :         1800 (0x00000708) seconds
 Prefix                   : 2a02:168:4a00::/64
  On-link                 :          Yes
  Autonomous address conf.:          Yes
  Valid time              :         7200 (0x00001c20) seconds
  Pref. time              :         1800 (0x00000708) seconds
 MTU                      :         1500 bytes (valid)
 Source link-layer address: 02:73:53:00:CA:FE
 from fe80::73:53ff:fe00:cafe
`
	if diff := cmp.Diff(want, got); diff != "" {
		t.Fatalf("unexpected rdisc6 output: diff (-want +got):\n%s", diff)
	}
}
