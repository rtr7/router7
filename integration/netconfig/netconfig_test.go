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
	"bytes"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/rtr7/router7/internal/netconfig"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"

	"github.com/andreyvit/diff"
	"github.com/google/go-cmp/cmp"
	"github.com/google/nftables"
)

const goldenInterfaces = `
{
  "interfaces":[
    {
      "hardware_addr": "02:73:53:00:ca:fe",
      "name": "uplink0"
    },
    {
      "hardware_addr": "02:73:53:00:b0:0c",
      "spoof_hardware_addr": "02:73:53:00:b0:aa",
      "name": "lan0",
      "addr": "192.168.42.1/24"
    },
    {
      "name": "wg0",
      "addr": "fe80::1/64"
    }
  ]
}
`

const goldenWireguard = `
{
  "interfaces":[
    {
      "name": "wg0",
      "private_key": "gBCV3afBKfW7RycmeZFMpJykvO+58KfSEIyavay90kE=",
      "port": 51820,
      "peers": [
        {
          "public_key": "ScxV5nQsUIaaOp3qdwPqRcgMkR3oR6nyi1tBLUovqBs=",
          "endpoint": "192.168.42.23:12345",
          "allowed_ips": [
            "fe80::/64",
            "10.0.137.0/24"
          ]
        },
        {
          "public_key": "AVU3LodtnFaFnJmMyNNW7cUk4462lqnVULTFkjWYvRo=",
          "endpoint": "[::1]:12345",
          "allowed_ips": [
            "10.0.0.0/8"
          ]
        }
      ]
    },
    {
      "name": "wg1",
      "private_key": "gBCV3afBKfW7RycmeZFMpJykvO+58KfSEIyavay90kE=",
      "port": 51820,
      "peers": [
        {
          "public_key": "ScxV5nQsUIaaOp3qdwPqRcgMkR3oR6nyi1tBLUovqBs=",
          "allowed_ips": [
            "fe80::/64"
          ]
        }
      ]
    }
  ]
}
`

func goldenPortForwardings(additionalForwarding bool) string {
	add := ""
	if additionalForwarding {
		add = `
    {
      "port": "8045",
      "dest_addr": "192.168.42.22",
      "dest_port": "8045"
    },
`
	}
	return `
{
  "forwardings":[
    {
      "port": "8080",
      "dest_addr": "192.168.42.23",
      "dest_port": "9999"
    },
` + add + `
    {
      "port": "8040-8060",
      "dest_addr": "192.168.42.99",
      "dest_port": "8040-8060"
    },
    {
      "proto": "udp",
      "port": "53",
      "dest_addr": "192.168.42.99",
      "dest_port": "53"
    }
  ]
}
`
}

func goldenNftablesRules(additionalForwarding bool) string {
	add := ""
	if additionalForwarding {
		add = `
		ip daddr != 127.0.0.0/8 ip daddr != 10.0.0.0/24 fib daddr type 2 tcp dport 8045 dnat to 192.168.42.22:8045`
	}
	return `table ip nat {
	chain prerouting {
		type nat hook prerouting priority 0; policy accept;
		ip daddr != 127.0.0.0/8 ip daddr != 10.0.0.0/24 fib daddr type 2 tcp dport 8080 dnat to 192.168.42.23:9999` + add + `
		ip daddr != 127.0.0.0/8 ip daddr != 10.0.0.0/24 fib daddr type 2 tcp dport 8040-8060 dnat to 192.168.42.99:8040-8060
		ip daddr != 127.0.0.0/8 ip daddr != 10.0.0.0/24 fib daddr type 2 udp dport 53 dnat to 192.168.42.99:53
	}

	chain postrouting {
		type nat hook postrouting priority 100; policy accept;
		oifname "uplink0" masquerade
		iifname "lan0" oifname "lan0" ct status 0x20 masquerade
	}
}
table ip filter {
	counter fwded {
		packets 23 bytes 42
	}

	counter inputc {
		packets 23 bytes 42
	}

	counter outputc {
		packets 23 bytes 42
	}

	chain forward {
		type filter hook forward priority 0; policy accept;
		oifname "uplink0" tcp flags 0x2 tcp option maxseg size set rt mtu
		counter name "fwded"
	}

	chain input {
		type filter hook input priority 0; policy accept;
		counter name "inputc"
	}

	chain output {
		type filter hook output priority 0; policy accept;
		counter name "outputc"
	}
}
table ip6 filter {
	counter fwded {
		packets 23 bytes 42
	}

	counter inputc {
		packets 23 bytes 42
	}

	counter outputc {
		packets 23 bytes 42
	}

	chain forward {
		type filter hook forward priority 0; policy accept;
		oifname "uplink0" tcp flags 0x2 tcp option maxseg size set rt mtu
		counter name "fwded"
	}

	chain input {
		type filter hook input priority 0; policy accept;
		counter name "inputc"
	}

	chain output {
		type filter hook output priority 0; policy accept;
		counter name "outputc"
	}
}`
}

const goldenDhcp4 = `
{
  "valid_until":"2018-05-18T23:46:04.429895261+02:00",
  "client_ip":"85.195.207.62",
  "subnet_mask":"255.255.255.128",
  "router":"85.195.207.1",
  "dns":[
    "77.109.128.2",
    "213.144.129.20"
  ]
}
`

const goldenDhcp6 = `
{
  "valid_until":"0001-01-01T00:00:00Z",
  "prefixes":[
    {"IP":"2a02:168:4a00::","Mask":"////////AAAAAAAAAAAAAA=="}
  ],
  "dns":[
    "2001:1620:2777:1::10",
    "2001:1620:2777:2::20"
  ]
}
`

type wgLink struct {
	ns int
}

func (w *wgLink) Type() string { return "wireguard" }

func (w *wgLink) Attrs() *netlink.LinkAttrs {
	attrs := netlink.NewLinkAttrs()
	attrs.Name = "wg5"
	if w.ns > 0 {
		attrs.Namespace = netlink.NsFd(w.ns)
	}
	return &attrs
}

var wireGuardAvailable = func() bool {
	// The wg tool must also be available for our test to succeed:
	if _, err := exec.LookPath("wg"); err != nil {
		return false
	}

	// ns must not collide with any namespace used in the test functions: this
	// function will be called by the helper process, too.
	const ns = "ns4"
	add := exec.Command("ip", "netns", "add", ns)
	add.Stderr = os.Stderr
	if err := add.Run(); err != nil {
		log.Fatalf("%v: %v", add.Args, err)
	}
	defer exec.Command("ip", "netns", "delete", ns).Run()

	nsHandle, err := netns.GetFromName(ns)
	if err != nil {
		log.Printf("GetFromName: %v", err)
		return false
	}

	if err := netlink.LinkAdd(&wgLink{ns: int(nsHandle)}); err != nil {
		log.Printf("netlink.LinkAdd: %v", err)
		return false
	}

	return true
}()

func TestNetconfig(t *testing.T) {
	if os.Getenv("HELPER_PROCESS") == "1" {
		tmp, err := ioutil.TempDir("", "router7")
		if err != nil {
			t.Fatal(err)
		}
		defer os.RemoveAll(tmp)

		pf := goldenPortForwardings(os.Getenv("ADDITIONAL_PORT_FORWARDINGS") == "1")
		for _, golden := range []struct {
			filename, content string
		}{
			{"dhcp4/wire/lease.json", goldenDhcp4},
			{"dhcp6/wire/lease.json", goldenDhcp6},
			{"interfaces.json", goldenInterfaces},
			{"portforwardings.json", pf},
		} {
			if err := os.MkdirAll(filepath.Join(tmp, filepath.Dir(golden.filename)), 0755); err != nil {
				t.Fatal(err)
			}
			if err := ioutil.WriteFile(filepath.Join(tmp, golden.filename), []byte(golden.content), 0600); err != nil {
				t.Fatal(err)
			}
		}
		if wireGuardAvailable {
			if err := ioutil.WriteFile(filepath.Join(tmp, "wireguard.json"), []byte(goldenWireguard), 0600); err != nil {
				t.Fatal(err)
			}
		}

		if err := os.MkdirAll(filepath.Join(tmp, "root", "etc"), 0755); err != nil {
			t.Fatal(err)
		}

		if err := os.MkdirAll(filepath.Join(tmp, "root", "tmp"), 0755); err != nil {
			t.Fatal(err)
		}

		netconfig.DefaultCounterObj = &nftables.CounterObj{Packets: 23, Bytes: 42}
		if err := netconfig.Apply(tmp, filepath.Join(tmp, "root")); err != nil {
			t.Fatalf("netconfig.Apply: %v", err)
		}

		// Apply twice to ensure the absence of errors when dealing with
		// already-configured interfaces, addresses, routes, … (and ensure
		// nftables rules are replaced, not appendend to).
		netconfig.DefaultCounterObj = &nftables.CounterObj{Packets: 0, Bytes: 0}
		if err := netconfig.Apply(tmp, filepath.Join(tmp, "root")); err != nil {
			t.Fatalf("netconfig.Apply: %v", err)
		}

		b, err := ioutil.ReadFile(filepath.Join(tmp, "root", "tmp", "resolv.conf"))
		if err != nil {
			t.Fatal(err)
		}
		if got, want := strings.TrimSpace(string(b)), "nameserver 192.168.42.1"; got != want {
			t.Errorf("/tmp/resolv.conf: got %q, want %q", got, want)
		}

		return
	}
	const ns = "ns3" // name of the network namespace to use for this test

	add := exec.Command("ip", "netns", "add", ns)
	add.Stderr = os.Stderr
	if err := add.Run(); err != nil {
		t.Fatalf("%v: %v", add.Args, err)
	}
	defer exec.Command("ip", "netns", "delete", ns).Run()

	nsSetup := []*exec.Cmd{
		exec.Command("ip", "-netns", ns, "link", "add", "dummy0", "type", "dummy"),
		exec.Command("ip", "-netns", ns, "link", "add", "lan0", "type", "dummy"),
		exec.Command("ip", "-netns", ns, "link", "set", "dummy0", "address", "02:73:53:00:ca:fe"),
		exec.Command("ip", "-netns", ns, "link", "set", "lan0", "address", "02:73:53:00:b0:0c"),
	}

	for _, cmd := range nsSetup {
		if err := cmd.Run(); err != nil {
			t.Fatalf("%v: %v", cmd.Args, err)
		}
	}

	cmd := exec.Command("ip", "netns", "exec", ns, os.Args[0], "-test.run=^TestNetconfig$")
	cmd.Env = append(os.Environ(), "HELPER_PROCESS=1")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		t.Fatal(err)
	}

	t.Run("VerifyAddresses", func(t *testing.T) {
		link, err := exec.Command("ip", "-netns", ns, "link", "show", "dev", "lan0").Output()
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(link), "link/ether 02:73:53:00:b0:aa") {
			t.Errorf("lan0 MAC address is not 02:73:53:00:b0:aa")
		}

		addrs, err := exec.Command("ip", "-netns", ns, "address", "show", "dev", "uplink0").Output()
		if err != nil {
			t.Fatal(err)
		}

		addrRe := regexp.MustCompile(`(?m)^\s*inet 85.195.207.62/25 brd 85.195.207.127 scope global uplink0$`)
		if !addrRe.MatchString(string(addrs)) {
			t.Fatalf("regexp %s does not match %s", addrRe, string(addrs))
		}

		addrsLan, err := exec.Command("ip", "-netns", ns, "address", "show", "dev", "lan0").Output()
		if err != nil {
			t.Fatal(err)
		}
		addr6Re := regexp.MustCompile(`(?m)^\s*inet6 2a02:168:4a00::1/64 scope global\s*$`)
		if !addr6Re.MatchString(string(addrsLan)) {
			t.Fatalf("regexp %s does not match %s", addr6Re, string(addrsLan))
		}

		wantRoutes := []string{
			"default via 85.195.207.1 proto dhcp src 85.195.207.62 ",
			"85.195.207.0/25 proto kernel scope link src 85.195.207.62 ",
			"85.195.207.1 proto dhcp scope link src 85.195.207.62",
		}

		routes, err := ipLines("-netns", ns, "route", "show", "dev", "uplink0")
		if err != nil {
			t.Fatal(err)
		}

		if diff := cmp.Diff(wantRoutes, routes); diff != "" {
			t.Fatalf("routes: diff (-want +got):\n%s", diff)
		}
	})

	t.Run("VerifyWireguard", func(t *testing.T) {
		if !wireGuardAvailable {
			t.Skipf("WireGuard not available on this machine")
		}
		var stderr bytes.Buffer
		wg := exec.Command("ip", "netns", "exec", ns, "wg", "show", "wg0")
		wg.Stderr = &stderr
		out, err := wg.Output()
		if err != nil {
			t.Fatalf("%v: %v (stderr: %v)", wg.Args, err, strings.TrimSpace(stderr.String()))
		}
		const want = `interface: wg0
  public key: 3ck9nX4ylfXm0fq4pWJ9n8Jku4fvzIXBVe3BsCNldB8=
  private key: (hidden)
  listening port: 51820

peer: ScxV5nQsUIaaOp3qdwPqRcgMkR3oR6nyi1tBLUovqBs=
  endpoint: 192.168.42.23:12345
  allowed ips: 10.0.137.0/24, fe80::/64

peer: AVU3LodtnFaFnJmMyNNW7cUk4462lqnVULTFkjWYvRo=
  endpoint: [::1]:12345
  allowed ips: 10.0.0.0/8`
		got := strings.TrimSpace(string(out))
		// Enforce an order (it can change, or did change between kernel
		// versions):
		got = strings.ReplaceAll(got,
			"  allowed ips: fe80::/64, 10.0.137.0/24",
			"  allowed ips: 10.0.137.0/24, fe80::/64")
		if got != want {
			t.Fatalf("unexpected wg output: diff (-want +got):\n%s", diff.LineDiff(want, got))
		}

		out, err = exec.Command("ip", "-netns", ns, "address", "show", "dev", "wg0").Output()
		if err != nil {
			t.Fatal(err)
		}
		upRe := regexp.MustCompile(`wg0: <[^>]+,UP`)
		if !upRe.MatchString(string(out)) {
			t.Errorf("regexp %s does not match %s", upRe, string(out))
		}
		addr6Re := regexp.MustCompile(`(?m)^\s*inet6 fe80::1/64 scope link\s*$`)
		if !addr6Re.MatchString(string(out)) {
			t.Errorf("regexp %s does not match %s", addr6Re, string(out))
		}

	})

	opts := []cmp.Option{
		cmp.Transformer("formatting", func(line string) string {
			return strings.TrimSpace(strings.Replace(line, "dnat to", "dnat", -1))
		}),
	}

	t.Run("VerifyNftables", func(t *testing.T) {
		rules, err := ipLines("netns", "exec", ns, "nft", "--numeric", "list", "ruleset")
		if err != nil {
			t.Fatal(err)
		}
		if len(rules) < 2 {
			t.Fatalf("nftables rules not found")
		}

		got := strings.Join(rules, "\n")
		if diff := cmp.Diff(goldenNftablesRules(false), got, opts...); diff != "" {
			t.Fatalf("unexpected nftables rules: diff (-want +got):\n%s", diff)
		}
	})

	cmd = exec.Command("ip", "netns", "exec", ns, os.Args[0], "-test.run=^TestNetconfig$")
	cmd.Env = append(os.Environ(), "HELPER_PROCESS=1", "ADDITIONAL_PORT_FORWARDINGS=1")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		t.Fatal(err)
	}

	t.Run("VerifyAdditionalNftables", func(t *testing.T) {
		rules, err := ipLines("netns", "exec", ns, "nft", "--numeric", "list", "ruleset")
		if err != nil {
			t.Fatal(err)
		}
		if len(rules) < 2 {
			t.Fatalf("nftables rules not found")
		}

		if got, want := strings.Join(rules, "\n"), goldenNftablesRules(true); got != want {
			t.Fatalf("unexpected nftables rules: diff (-want +got):\n%s", diff.LineDiff(want, got))
		}
	})
}

const goldenInterfacesBridges = `
{
  "bridges":[
    {
      "name": "lan0",
      "interface_hardware_addrs": ["02:73:53:00:b0:0c"]
    }
  ],
  "interfaces":[
    {
      "hardware_addr": "02:73:53:00:ca:fe",
      "name": "uplink0"
    },
    {
      "spoof_hardware_addr": "02:73:53:00:b0:aa",
      "name": "lan0",
      "addr": "192.168.42.1/24"
    }
  ]
}
`

func TestNetconfigBridges(t *testing.T) {
	if os.Getenv("HELPER_PROCESS") == "1" {
		tmp, err := ioutil.TempDir("", "router7")
		if err != nil {
			t.Fatal(err)
		}
		defer os.RemoveAll(tmp)

		for _, golden := range []struct {
			filename, content string
		}{
			{"interfaces.json", goldenInterfacesBridges},
		} {
			if err := os.MkdirAll(filepath.Join(tmp, filepath.Dir(golden.filename)), 0755); err != nil {
				t.Fatal(err)
			}
			if err := ioutil.WriteFile(filepath.Join(tmp, golden.filename), []byte(golden.content), 0600); err != nil {
				t.Fatal(err)
			}
		}

		if err := os.MkdirAll(filepath.Join(tmp, "root", "etc"), 0755); err != nil {
			t.Fatal(err)
		}

		if err := os.MkdirAll(filepath.Join(tmp, "root", "tmp"), 0755); err != nil {
			t.Fatal(err)
		}

		netconfig.DefaultCounterObj = &nftables.CounterObj{Packets: 23, Bytes: 42}
		if err := netconfig.Apply(tmp, filepath.Join(tmp, "root")); err != nil {
			t.Fatalf("netconfig.Apply: %v", err)
		}

		// Apply twice to ensure the absence of errors when dealing with
		// already-configured interfaces, addresses, routes, … (and ensure
		// nftables rules are replaced, not appendend to).
		netconfig.DefaultCounterObj = &nftables.CounterObj{Packets: 0, Bytes: 0}
		if err := netconfig.Apply(tmp, filepath.Join(tmp, "root")); err != nil {
			t.Fatalf("netconfig.Apply: %v", err)
		}

		return
	}
	const ns = "ns6" // name of the network namespace to use for this test

	add := exec.Command("ip", "netns", "add", ns)
	add.Stderr = os.Stderr
	if err := add.Run(); err != nil {
		t.Fatalf("%v: %v", add.Args, err)
	}
	defer exec.Command("ip", "netns", "delete", ns).Run()

	nsSetup := []*exec.Cmd{
		exec.Command("ip", "-netns", ns, "link", "add", "dummy0", "type", "dummy"),
		exec.Command("ip", "-netns", ns, "link", "add", "eth0", "type", "dummy"),
		exec.Command("ip", "-netns", ns, "link", "set", "dummy0", "address", "02:73:53:00:ca:fe"),
		exec.Command("ip", "-netns", ns, "link", "set", "eth0", "address", "02:73:53:00:b0:0c"),
	}

	for _, cmd := range nsSetup {
		if err := cmd.Run(); err != nil {
			t.Fatalf("%v: %v", cmd.Args, err)
		}
	}

	cmd := exec.Command("ip", "netns", "exec", ns, os.Args[0], "-test.run=^TestNetconfigBridges")
	cmd.Env = append(os.Environ(), "HELPER_PROCESS=1")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		t.Fatal(err)
	}

	t.Run("VerifyAddresses", func(t *testing.T) {
		link, err := exec.Command("ip", "-netns", ns, "link", "show", "dev", "lan0", "type", "bridge").Output()
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(link), "link/ether 02:73:53:00:b0:aa") {
			t.Errorf("lan0 MAC address is not 02:73:53:00:b0:aa")
		}

		addrs, err := exec.Command("ip", "-netns", ns, "address", "show", "dev", "lan0").Output()
		if err != nil {
			t.Fatal(err)
		}

		addrRe := regexp.MustCompile(`(?m)^\s*inet 192.168.42.1/24 brd 192.168.42.255 scope global lan0`)
		if !addrRe.MatchString(string(addrs)) {
			t.Fatalf("regexp %s does not match %s", addrRe, string(addrs))
		}

		bridgeLinks, err := exec.Command("ip", "-netns", ns, "link", "show", "master", "lan0").Output()
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(bridgeLinks), ": eth0: ") {
			t.Errorf("lan0 bridge does not contain eth0 interface")
		}
	})
}

func ipLines(args ...string) ([]string, error) {
	cmd := exec.Command("ip", args...)
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("%v: %v", cmd.Args, err)
	}
	outstr := string(out)
	for strings.Contains(outstr, "  ") {
		outstr = strings.Replace(outstr, "  ", " ", -1)
	}

	return strings.Split(strings.TrimSpace(outstr), "\n"), nil
}

func TestDHCPv4OldAddressDeconfigured(t *testing.T) {
	if os.Getenv("HELPER_PROCESS") == "1" {
		tmp, err := ioutil.TempDir("", "router7")
		if err != nil {
			t.Fatal(err)
		}
		defer os.RemoveAll(tmp)

		for _, golden := range []struct {
			filename, content string
		}{
			{"dhcp4/wire/lease.json", goldenDhcp4},
			{"interfaces.json", goldenInterfaces},
		} {
			if err := os.MkdirAll(filepath.Join(tmp, filepath.Dir(golden.filename)), 0755); err != nil {
				t.Fatal(err)
			}
			if err := ioutil.WriteFile(filepath.Join(tmp, golden.filename), []byte(golden.content), 0600); err != nil {
				t.Fatal(err)
			}
		}

		if err := os.MkdirAll(filepath.Join(tmp, "root", "etc"), 0755); err != nil {
			t.Fatal(err)
		}

		if err := os.MkdirAll(filepath.Join(tmp, "root", "tmp"), 0755); err != nil {
			t.Fatal(err)
		}

		if err := netconfig.Apply(tmp, filepath.Join(tmp, "root")); err != nil {
			t.Fatalf("netconfig.Apply: %v", err)
		}

		const anotherDhcp4 = `
{
  "valid_until":"2018-05-18T23:46:04.429895261+02:00",
  "client_ip":"85.195.199.99",
  "subnet_mask":"255.255.255.128",
  "router":"85.195.199.1",
  "dns":[
    "77.109.128.2",
    "213.144.129.20"
  ]
}
`
		if err := ioutil.WriteFile(filepath.Join(tmp, "dhcp4/wire/lease.json"), []byte(anotherDhcp4), 0600); err != nil {
			t.Fatal(err)
		}

		if err := netconfig.Apply(tmp, filepath.Join(tmp, "root")); err != nil {
			t.Fatalf("netconfig.Apply: %v", err)
		}

		return
	}
	const ns = "ns5" // name of the network namespace to use for this test

	add := exec.Command("ip", "netns", "add", ns)
	add.Stderr = os.Stderr
	if err := add.Run(); err != nil {
		t.Fatalf("%v: %v", add.Args, err)
	}
	defer exec.Command("ip", "netns", "delete", ns).Run()

	nsSetup := []*exec.Cmd{
		exec.Command("ip", "-netns", ns, "link", "add", "dummy0", "type", "dummy"),
		exec.Command("ip", "-netns", ns, "link", "add", "lan0", "type", "dummy"),
		exec.Command("ip", "-netns", ns, "link", "set", "dummy0", "address", "02:73:53:00:ca:fe"),
		exec.Command("ip", "-netns", ns, "link", "set", "lan0", "address", "02:73:53:00:b0:0c"),
	}

	for _, cmd := range nsSetup {
		if err := cmd.Run(); err != nil {
			t.Fatalf("%v: %v", cmd.Args, err)
		}
	}

	cmd := exec.Command("ip", "netns", "exec", ns, os.Args[0], "-test.run=^TestDHCPv4OldAddressDeconfigured$")
	cmd.Env = append(os.Environ(), "HELPER_PROCESS=1")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		t.Fatal(err)
	}

	t.Run("VerifyAddresses", func(t *testing.T) {
		show := exec.Command("ip", "-netns", ns, "address", "show", "dev", "uplink0")
		show.Stderr = os.Stderr
		addrs, err := show.Output()
		if err != nil {
			t.Fatal(err)
		}

		oldAddrRe := regexp.MustCompile(`(?m)^\s*inet 85.195.207.62/25 brd 85.195.207.127 scope global uplink0$`)
		if oldAddrRe.MatchString(string(addrs)) {
			t.Fatalf("regexp %s unexpectedly still matches %s", oldAddrRe, string(addrs))
		}

		addrRe := regexp.MustCompile(`(?m)^\s*inet 85.195.199.99/25 brd 85.195.199.127 scope global uplink0$`)
		if !addrRe.MatchString(string(addrs)) {
			t.Fatalf("regexp %s does not match %s", addrRe, string(addrs))
		}

		wantRoutes := []string{
			"default via 85.195.199.1 proto dhcp src 85.195.199.99 ",
			"85.195.199.0/25 proto kernel scope link src 85.195.199.99 ",
			"85.195.199.1 proto dhcp scope link src 85.195.199.99",
		}

		routes, err := ipLines("-netns", ns, "route", "show", "dev", "uplink0")
		if err != nil {
			t.Fatal(err)
		}

		if diff := cmp.Diff(wantRoutes, routes); diff != "" {
			t.Fatalf("routes: diff (-want +got):\n%s", diff)
		}
	})
}
