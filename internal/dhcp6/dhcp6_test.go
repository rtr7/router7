package dhcp6

import (
	"fmt"
	"net"
	"os"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

type packet struct {
	data []byte
	ip   net.IP
	err  error
}

type replayer struct {
	pcapr *pcapgo.Reader
}

func (r *replayer) LocalAddr() net.Addr { return nil }
func (r *replayer) Close() error        { return nil }
func (r *replayer) WriteTo(b []byte, addr net.Addr) (n int, err error) {
	//log.Printf("-> %v", b)
	return len(b), nil
}
func (r *replayer) SetDeadline(t time.Time) error      { return nil }
func (r *replayer) SetReadDeadline(t time.Time) error  { return nil }
func (r *replayer) SetWriteDeadline(t time.Time) error { return nil }

func (r *replayer) ReadFrom(buf []byte) (int, net.Addr, error) {
	data, _, err := r.pcapr.ReadPacketData()
	if err != nil {
		return 0, nil, err
	}
	pkt := gopacket.NewPacket(data, layers.LayerTypeEthernet, gopacket.DecodeOptions{})
	// TODO: get source IP
	udp := pkt.Layer(layers.LayerTypeUDP)
	if udp == nil {
		return 0, nil, fmt.Errorf("pcap contained unexpected non-UDP packet")
	}

	//log.Printf("ReadFrom(): %x, %v, pkt = %+v", udp.LayerPayload(), err, pkt)
	copy(buf, udp.LayerPayload())
	return len(udp.LayerPayload()), &net.IPAddr{IP: net.ParseIP("192.168.23.1")}, err
}

func TestDHCP6(t *testing.T) {
	f, err := os.Open("testdata/fiber7.pcap")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	pcapr, err := pcapgo.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}

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
		Conn:          &replayer{pcapr: pcapr},
		TransactionIDs: []uint32{
			0x48e59e, // SOLICIT
			0x738c3b, // REQUEST
		},
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
	if diff := cmp.Diff(got, want); diff != "" {
		t.Fatalf("unexpected config: diff (-got +want):\n%s", diff)
	}
}

func mustParseCIDR(s string) net.IPNet {
	_, net, err := net.ParseCIDR(s)
	if err != nil {
		panic(err)
	}
	return *net
}
