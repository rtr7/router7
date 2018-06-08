package integration_test

import (
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"router7/internal/netconfig"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
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
    }
  ]
}
`

const goldenPortForwardings = `
{
  "forwardings":[
    {
      "port": 8080,
      "dest_addr": "192.168.42.23",
      "dest_port": 9999
    },
    {
      "port": 8022,
      "dest_addr": "192.168.42.99",
      "dest_port": 22
    }
  ]
}
`

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

func TestNetconfig(t *testing.T) {
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
			{"dhcp6/wire/lease.json", goldenDhcp6},
			{"interfaces.json", goldenInterfaces},
			{"portforwardings.json", goldenPortForwardings},
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

		if err := netconfig.Apply(tmp, filepath.Join(tmp, "root")); err != nil {
			t.Fatalf("netconfig.Apply: %v", err)
		}

		b, err := ioutil.ReadFile(filepath.Join(tmp, "root", "etc", "resolv.conf"))
		if err != nil {
			t.Fatal(err)
		}
		if got, want := strings.TrimSpace(string(b)), "nameserver 192.168.42.1"; got != want {
			t.Errorf("/etc/resolv.conf: got %q, want %q", got, want)
		}

		return
	}
	const ns = "ns1" // name of the network namespace to use for this test

	if err := exec.Command("ip", "netns", "add", ns).Run(); err != nil {
		t.Fatalf("ip netns add %s: %v", ns, err)
	}
	defer exec.Command("ip", "netns", "delete", ns).Run()

	nsSetup := []*exec.Cmd{
		exec.Command("ip", "netns", "exec", ns, "ip", "link", "add", "dummy0", "type", "dummy"),
		exec.Command("ip", "netns", "exec", ns, "ip", "link", "add", "lan0", "type", "dummy"),
		exec.Command("ip", "netns", "exec", ns, "ip", "link", "set", "dummy0", "address", "02:73:53:00:ca:fe"),
		exec.Command("ip", "netns", "exec", ns, "ip", "link", "set", "lan0", "address", "02:73:53:00:b0:0c"),
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

	link, err := exec.Command("ip", "netns", "exec", ns, "ip", "link", "show", "dev", "lan0").Output()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(link), "link/ether 02:73:53:00:b0:aa") {
		t.Errorf("lan0 MAC address is not 02:73:53:00:b0:aa")
	}

	addrs, err := exec.Command("ip", "netns", "exec", ns, "ip", "address", "show", "dev", "uplink0").Output()
	if err != nil {
		t.Fatal(err)
	}

	addrRe := regexp.MustCompile(`(?m)^\s*inet 85.195.207.62/25 brd 85.195.207.127 scope global uplink0$`)
	if !addrRe.MatchString(string(addrs)) {
		t.Fatalf("regexp %s does not match %s", addrRe, string(addrs))
	}

	addrsLan, err := exec.Command("ip", "netns", "exec", ns, "ip", "address", "show", "dev", "lan0").Output()
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

	routes, err := ipLines("netns", "exec", ns, "ip", "route", "show", "dev", "uplink0")
	if err != nil {
		t.Fatal(err)
	}

	if diff := cmp.Diff(routes, wantRoutes); diff != "" {
		t.Fatalf("routes: diff (-got +want):\n%s", diff)
	}

	rules, err := ipLines("netns", "exec", ns, "nft", "list", "ruleset")
	if err != nil {
		t.Fatal(err)
	}
	for n, rule := range rules {
		t.Logf("rule %d: %s", n, rule)
	}
	if len(rules) < 2 {
		t.Fatalf("nftables rules not found")
	}
	wantRules := []string{
		`table ip nat {`,
		`	chain prerouting {`,
		`		type nat hook prerouting priority 0; policy accept;`,
		`		iifname "uplink0" tcp dport 8022 dnat to 192.168.42.99:ssh`,
		`		iifname "uplink0" tcp dport http-alt dnat to 192.168.42.23:9999`,
		`	}`,
		``,
		`	chain postrouting {`,
		`		type nat hook postrouting priority 100; policy accept;`,
		`		oifname "uplink0" masquerade`,
		`	}`,
		`}`,
	}
	opts := []cmp.Option{
		cmp.Transformer("formatting", func(line string) string {
			return strings.TrimSpace(strings.Replace(line, "dnat to", "dnat", -1))
		}),
	}

	if diff := cmp.Diff(rules, wantRules, opts...); diff != "" {
		t.Fatalf("unexpected nftables rules: diff (-got +want):\n%s", diff)
	}
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
