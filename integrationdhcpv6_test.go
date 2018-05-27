package integration_test

import (
	"io/ioutil"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"

	"router7/internal/dhcp6"

	"github.com/google/go-cmp/cmp"
)

func TestDHCPv6(t *testing.T) {
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
		exec.Command("ip", "netns", "exec", ns, "ip", "addr", "add", "2001:db8::1/64", "dev", "veth0b"),
		exec.Command("ip", "netns", "exec", ns, "ip", "link", "set", "veth0b", "up"),
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

	dnsmasq := exec.Command("ip", "netns", "exec", ns, "dnsmasq",
		"--keep-in-foreground", // cannot use --no-daemon because we need --pid-file
		"--log-facility=-",     // log to stderr
		"--pid-file="+ready.Name(),
		"--bind-interfaces",
		"--interface=veth0b",
		"--dhcp-range=192.168.23.2,192.168.23.10",
		"--dhcp-range=::1,::10,constructor:veth0b",
		"--dhcp-authoritative", // eliminate timeouts
		"--no-ping",            // disable ICMP confirmation of unused addresses to eliminate tedious timeout
		"--leasefile-ro",       // do not create a lease database
	)
	dnsmasq.Stdout = os.Stdout
	dnsmasq.Stderr = os.Stderr
	if err := dnsmasq.Start(); err != nil {
		t.Fatal(err)
	}
	done := false // TODO: fix data race
	go func() {
		err := dnsmasq.Wait()
		if !done {
			t.Fatalf("dnsmasq exited prematurely: %v", err)
		}
	}()
	defer func() {
		done = true
		dnsmasq.Process.Kill()
	}()

	// TODO(later): use inotify instead of polling
	// Wait for dnsmasq to write its process id, at which point it is already
	// listening for requests.
	for {
		b, err := ioutil.ReadFile(ready.Name())
		if err != nil {
			t.Fatal(err)
		}
		if strings.TrimSpace(string(b)) == strconv.Itoa(dnsmasq.Process.Pid) {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

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

	c, err := dhcp6.NewClient(dhcp6.ClientConfig{
		InterfaceName: "veth0a",
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

	// time.Sleep(1 * time.Second)
	// handle.Close()
	// <-closed
}
