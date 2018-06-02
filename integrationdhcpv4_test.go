package integration_test

import (
	"bytes"
	"io/ioutil"
	"log"
	"net"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"router7/internal/dhcp4"

	"github.com/google/go-cmp/cmp"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/pcapgo"
)

func TestDHCPv4(t *testing.T) {
	const ns = "ns0" // name of the network namespace to use for this test

	if err := exec.Command("ip", "netns", "add", ns).Run(); err != nil {
		t.Fatalf("ip netns add %s: %v", ns, err)
	}
	defer exec.Command("ip", "netns", "delete", ns).Run()

	nsSetup := []*exec.Cmd{
		exec.Command("ip", "link", "add", "veth0a", "type", "veth", "peer", "name", "veth0b", "netns", ns),
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

	var stderr bytes.Buffer
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
	dnsmasq.Stderr = &stderr
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

	f, err := os.Create("/tmp/pcap")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	pcapw := pcapgo.NewWriter(f)
	if err := pcapw.WriteFileHeader(1600, layers.LinkTypeEthernet); err != nil {
		t.Fatal(err)
	}
	handle, err := pcap.OpenLive("veth0a", 1600, true, pcap.BlockForever)
	if err != nil {
		t.Fatal(err)
	}
	pkgsrc := gopacket.NewPacketSource(handle, handle.LinkType())
	closed := make(chan struct{})
	go func() {
		for packet := range pkgsrc.Packets() {
			if packet.Layer(layers.LayerTypeDHCPv4) != nil {
				log.Printf("packet: %+v", packet)
				if err := pcapw.WritePacket(packet.Metadata().CaptureInfo, packet.Data()); err != nil {
					t.Fatalf("pcap.WritePacket(): %v", err)
				}
			}
		}
		close(closed)
	}()
	// TODO: test the capture daemon

	iface, err := net.InterfaceByName("veth0a")
	if err != nil {
		t.Fatal(err)
	}
	c := dhcp4.Client{
		Interface: iface,
	}
	if !c.ObtainOrRenew() {
		t.Fatal(c.Err())
	}
	cfg := c.Config()
	t.Logf("cfg = %+v", cfg)
	if got, want := cfg.Router, "192.168.23.1"; got != want {
		t.Errorf("config: unexpected router: got %q, want %q", got, want)
	}

	if err := c.Release(); err != nil {
		t.Fatal(err)
	}

	// TODO: use inotify on the leases db to wait for this event
	// TODO: alternatively, replace bytes.Buffer with a pipe and read from that
	time.Sleep(100 * time.Millisecond) // give dnsmasq some time to process the DHCPRELEASE

	// Kill dnsmasq to flush its log
	done = true
	dnsmasq.Process.Kill()

	mac := iface.HardwareAddr.String()
	lines := strings.Split(strings.TrimSpace(stderr.String()), "\n")
	var dhcpActionRe = regexp.MustCompile(` (DHCP[^ ]*)`)
	var actions []string
	for _, line := range lines {
		if !strings.HasPrefix(line, "dnsmasq-dhcp") {
			continue
		}
		if !strings.Contains(line, mac) {
			continue
		}
		matches := dhcpActionRe.FindStringSubmatch(line)
		if matches == nil {
			continue
		}
		actions = append(actions, matches[1])
	}
	want := []string{
		"DHCPDISCOVER(veth0b)",
		"DHCPOFFER(veth0b)",
		"DHCPREQUEST(veth0b)",
		"DHCPACK(veth0b)",
		"DHCPRELEASE(veth0b)",
	}
	if diff := cmp.Diff(actions, want); diff != "" {
		t.Errorf("dnsmasq log does not contain expected DHCP sequence: diff (-got +want):\n%s", diff)
	}

	time.Sleep(1 * time.Second)
	handle.Close()
	<-closed
}
