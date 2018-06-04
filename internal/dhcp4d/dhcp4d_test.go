package dhcp4d

import (
	"bytes"
	"io/ioutil"
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/krolaw/dhcp4"
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
      "name": "lan0",
      "addr": "192.168.42.1/24"
    }
  ]
}
`

func TestLease(t *testing.T) {
	tmpdir, err := ioutil.TempDir("", "dhcp4dtest")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpdir)
	if err := ioutil.WriteFile(filepath.Join(tmpdir, "interfaces.json"), []byte(goldenInterfaces), 0644); err != nil {
		t.Fatal(err)
	}
	var (
		addr         = net.IP{192, 168, 42, 23}
		hardwareAddr = net.HardwareAddr{0x11, 0x22, 0x33, 0x44, 0x55, 0x66}
		hostname     = "xps"
	)
	handler, err := NewHandler(tmpdir)
	if err != nil {
		t.Fatal(err)
	}
	leasedCalled := false
	handler.Leases = func(leases []*Lease) {
		if got, want := len(leases), 1; got != want {
			t.Fatalf("unexpected number of leases: got %d, want %d", got, want)
		}
		l := leases[0]
		if got, want := l.Addr, addr; !bytes.Equal(got, want) {
			t.Fatalf("unexpected lease.Addr: got %v, want %v", got, want)
		}
		if got, want := l.HardwareAddr, hardwareAddr.String(); got != want {
			t.Fatalf("unexpected lease.HardwareAddr: got %q, want %q", got, want)
		}
		if got, want := l.Hostname, hostname; got != want {
			t.Fatalf("unexpected lease.Hostname: got %q, want %q", got, want)
		}
		leasedCalled = true
	}
	p := dhcp4.RequestPacket(
		dhcp4.Request,
		hardwareAddr, // MAC address
		addr,         // requested IP address
		[]byte{0xaa, 0xbb, 0xcc, 0xdd}, // transaction ID
		false, // broadcast,
		[]dhcp4.Option{
			{
				Code:  dhcp4.OptionHostName,
				Value: []byte(hostname),
			},
		},
	)
	handler.ServeDHCP(p, dhcp4.Request, p.ParseOptions())
	if !leasedCalled {
		t.Fatalf("leased callback not called")
	}
}
