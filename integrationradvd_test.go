package integration_test

import (
	"io/ioutil"
	"net"
	"os"
	"os/exec"
	"router7/internal/radvd"
	"testing"
)

func TestRouterAdvertisement(t *testing.T) {
	const ns = "ns0" // name of the network namespace to use for this test

	if err := exec.Command("ip", "netns", "add", ns).Run(); err != nil {
		t.Fatalf("ip netns add %s: %v", ns, err)
	}
	defer exec.Command("ip", "netns", "delete", ns).Run()

	nsSetup := []*exec.Cmd{
		exec.Command("ip", "link", "add", "veth0a", "type", "veth", "peer", "name", "veth0b", "netns", ns),

		// Disable Duplicate Address Detection: until DAD completes, the link-local
		// address remains in state “tentative”, resulting in any attempts to
		// bind(2) to the address to fail with -EADDRNOTAVAIL.
		exec.Command("/bin/sh", "-c", "echo 0 > /proc/sys/net/ipv6/conf/veth0a/accept_dad"),
		exec.Command("ip", "netns", "exec", ns, "/bin/sh", "-c", "echo 0 > /proc/sys/net/ipv6/conf/veth0b/accept_dad"),

		exec.Command("ip", "link", "set", "veth0a", "up"),
		exec.Command("ip", "netns", "exec", ns, "ip", "addr", "add", "192.168.23.1/24", "dev", "veth0b"),
		exec.Command("ip", "netns", "exec", ns, "ip", "link", "set", "veth0b", "up"),
		exec.Command("ip", "netns", "exec", ns, "ip", "link", "set", "veth0b"),
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
	go func() {
		if err := srv.ListenAndServe("veth0a"); err != nil {
			t.Fatal(err)
		}
	}()
	//time.Sleep(5 * time.Second)
	rdisc6 := exec.Command("ip", "netns", "exec", ns, "rdisc6",
		"--single",     // exit after first router advertisement
		"--retry", "1", // retry only once
		"--wait", "1000", // wait 1s
		"veth0b")
	rdisc6.Stderr = os.Stderr
	b, err := rdisc6.Output()
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("b = %s", string(b))

}
