package integration_test

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/d2g/dhcp4"
	"github.com/d2g/dhcp4client"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/pcapgo"
)

var (
	hardwareAddr net.HardwareAddr
)

func addHostname(p *dhcp4.Packet) {
	var utsname unix.Utsname
	if err := unix.Uname(&utsname); err != nil {
		log.Fatal(err)
	}
	nnb := utsname.Nodename[:bytes.IndexByte(utsname.Nodename[:], 0)]
	p.AddOption(dhcp4.OptionHostName, nnb)
}

func addClientId(p *dhcp4.Packet) {
	id := make([]byte, len(hardwareAddr)+1)
	id[0] = 1 // hardware type ethernet, https://tools.ietf.org/html/rfc1700
	copy(id[1:], hardwareAddr)
	p.AddOption(dhcp4.OptionClientIdentifier, id)
}

// dhcpRequest is a copy of (dhcp4client/Client).Request which
// includes the hostname.
func dhcpRequest(c *dhcp4client.Client) (bool, dhcp4.Packet, error) {
	discoveryPacket := c.DiscoverPacket()
	addHostname(&discoveryPacket)
	addClientId(&discoveryPacket)
	discoveryPacket.PadToMinSize()

	if err := c.SendPacket(discoveryPacket); err != nil {
		return false, discoveryPacket, err
	}

	offerPacket, err := c.GetOffer(&discoveryPacket)
	if err != nil {
		return false, offerPacket, err
	}

	requestPacket := c.RequestPacket(&offerPacket)
	addHostname(&requestPacket)
	addClientId(&requestPacket)
	requestPacket.PadToMinSize()

	if err := c.SendPacket(requestPacket); err != nil {
		return false, requestPacket, err
	}

	acknowledgement, err := c.GetAcknowledgement(&requestPacket)
	if err != nil {
		return false, acknowledgement, err
	}

	acknowledgementOptions := acknowledgement.ParseOptions()
	if dhcp4.MessageType(acknowledgementOptions[dhcp4.OptionDHCPMessageType][0]) != dhcp4.ACK {
		return false, acknowledgement, nil
	}

	return true, acknowledgement, nil
}

type connection interface {
	Close() error
	Write(packet []byte) error
	ReadFrom() ([]byte, net.IP, error)
	SetReadTimeout(t time.Duration) error
}
type replayer struct {
	underlying connection
}

func (r *replayer) Close() error                         { return r.underlying.Close() }
func (r *replayer) Write(b []byte) error                 { return r.underlying.Write(b) }
func (r *replayer) SetReadTimeout(t time.Duration) error { return r.underlying.SetReadTimeout(t) }

func (r *replayer) ReadFrom() ([]byte, net.IP, error) {
	d, ip, err := r.underlying.ReadFrom()
	log.Printf("d = %+v, ip = %v, err = %v", d, ip, err)
	return d, ip, err
}

func dhcp() error {
	v0, err := net.InterfaceByName("veth0a")
	if err != nil {
		return err
	}

	hardwareAddr = v0.HardwareAddr

	pktsock, err := dhcp4client.NewPacketSock(v0.Index)
	if err != nil {
		return err
	}
	dhcp, err := dhcp4client.New(
		dhcp4client.HardwareAddr(v0.HardwareAddr),
		dhcp4client.Timeout(5*time.Second),
		dhcp4client.Broadcast(false),
		dhcp4client.Connection(&replayer{underlying: pktsock}),
	)
	if err != nil {
		return err
	}

	//ok, ack, err := dhcpRequest(dhcp)
	fmt.Println(dhcpRequest(dhcp))
	return nil
}

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

	if err := dhcp(); err != nil {
		t.Fatal(err)
	}
	time.Sleep(1 * time.Second)
	handle.Close()
	<-closed
}
