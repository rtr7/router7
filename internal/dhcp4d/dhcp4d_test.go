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

package dhcp4d

import (
	"bytes"
	"io/ioutil"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/krolaw/dhcp4"
)

func messageType(p dhcp4.Packet) dhcp4.MessageType {
	opts := p.ParseOptions()
	return dhcp4.MessageType(opts[dhcp4.OptionDHCPMessageType][0])
}

func packet(mt dhcp4.MessageType, addr net.IP, hwaddr net.HardwareAddr, opts []dhcp4.Option) dhcp4.Packet {
	return dhcp4.RequestPacket(
		mt,
		hwaddr,                         // MAC address
		addr,                           // requested IP address
		[]byte{0xaa, 0xbb, 0xcc, 0xdd}, // transaction ID
		false,                          // broadcast,
		opts,
	)
}

func request(addr net.IP, hwaddr net.HardwareAddr, opts ...dhcp4.Option) dhcp4.Packet {
	return packet(dhcp4.Request, addr, hwaddr, opts)
}

func discover(addr net.IP, hwaddr net.HardwareAddr, opts ...dhcp4.Option) dhcp4.Packet {
	return packet(dhcp4.Discover, addr, hwaddr, opts)
}

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

type noopSink struct{}

func (*noopSink) LocalAddr() net.Addr                                { return nil }
func (*noopSink) Close() error                                       { return nil }
func (*noopSink) WriteTo(b []byte, addr net.Addr) (n int, err error) { return len(b), nil }
func (*noopSink) SetDeadline(t time.Time) error                      { return nil }
func (*noopSink) SetReadDeadline(t time.Time) error                  { return nil }
func (*noopSink) SetWriteDeadline(t time.Time) error                 { return nil }
func (*noopSink) ReadFrom(buf []byte) (int, net.Addr, error)         { return 0, nil, nil }

func testHandler(t *testing.T) (_ *Handler, cleanup func()) {
	tmpdir, err := ioutil.TempDir("", "dhcp4dtest")
	if err != nil {
		t.Fatal(err)
	}
	if err := ioutil.WriteFile(filepath.Join(tmpdir, "interfaces.json"), []byte(goldenInterfaces), 0644); err != nil {
		t.Fatal(err)
	}
	handler, err := NewHandler(
		tmpdir,
		&net.Interface{
			HardwareAddr: net.HardwareAddr([]byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66}),
		},
		&noopSink{},
	)
	if err != nil {
		t.Fatal(err)
	}
	return handler, func() { os.RemoveAll(tmpdir) }
}

func TestLease(t *testing.T) {
	handler, cleanup := testHandler(t)
	defer cleanup()
	var (
		addr         = net.IP{192, 168, 42, 23}
		hardwareAddr = net.HardwareAddr{0x11, 0x22, 0x33, 0x44, 0x55, 0x66}
		hostname     = "xps"
	)
	leasedCalled := false
	handler.Leases = func(leases []*Lease, latest *Lease) {
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
		hardwareAddr,                   // MAC address
		addr,                           // requested IP address
		[]byte{0xaa, 0xbb, 0xcc, 0xdd}, // transaction ID
		false,                          // broadcast,
		[]dhcp4.Option{
			{
				Code:  dhcp4.OptionHostName,
				Value: []byte(hostname),
			},
		},
	)
	handler.serveDHCP(p, dhcp4.Request, p.ParseOptions())
	if !leasedCalled {
		t.Fatalf("leased callback not called")
	}
}

func TestPreferredAddress(t *testing.T) {
	handler, cleanup := testHandler(t)
	defer cleanup()

	var (
		addr         = net.IP{192, 168, 42, 23}
		hardwareAddr = net.HardwareAddr{0x11, 0x22, 0x33, 0x44, 0x55, 0x66}
		hostname     = "xps"
	)

	t.Run("no requested IP", func(t *testing.T) {
		p := request(net.IPv4zero, hardwareAddr)
		resp := handler.serveDHCP(p, dhcp4.Discover, p.ParseOptions())
		if got, want := resp.YIAddr().To4(), addr.To4(); bytes.Equal(got, want) {
			t.Errorf("DHCPOFFER for wrong IP: got %v, want %v", got, want)
		}
	})

	t.Run("requested CIAddr", func(t *testing.T) {
		p := request(addr, hardwareAddr)
		resp := handler.serveDHCP(p, dhcp4.Discover, p.ParseOptions())
		if got, want := resp.YIAddr().To4(), addr.To4(); !bytes.Equal(got, want) {
			t.Errorf("DHCPOFFER for wrong IP: got %v, want %v", got, want)
		}
	})

	t.Run("requested option", func(t *testing.T) {
		//p := request(net.IPv4zero, hardwareAddr)
		p := dhcp4.RequestPacket(
			dhcp4.Discover,
			hardwareAddr,                   // MAC address
			net.IPv4zero,                   // requested IP address
			[]byte{0xaa, 0xbb, 0xcc, 0xdd}, // transaction ID
			false,                          // broadcast,
			[]dhcp4.Option{
				{
					Code:  dhcp4.OptionHostName,
					Value: []byte(hostname),
				},
				{
					Code:  dhcp4.OptionRequestedIPAddress,
					Value: addr,
				},
			},
		)
		resp := handler.serveDHCP(p, dhcp4.Discover, p.ParseOptions())
		if got, want := resp.YIAddr().To4(), addr.To4(); !bytes.Equal(got, want) {
			t.Errorf("DHCPOFFER for wrong IP: got %v, want %v", got, want)
		}
	})
}

func TestPoolBoundaries(t *testing.T) {
	handler, cleanup := testHandler(t)
	defer cleanup()

	var (
		addr         = net.IP{192, 168, 42, 23}
		hardwareAddr = net.HardwareAddr{0x11, 0x22, 0x33, 0x44, 0x55, 0x66}
	)

	for _, last := range []byte{1, 242} {
		addr[len(addr)-1] = last
		p := request(addr, hardwareAddr)
		resp := handler.serveDHCP(p, dhcp4.Request, p.ParseOptions())
		if got, want := messageType(resp), dhcp4.NAK; got != want {
			t.Errorf("DHCPREQUEST resulted in unexpected message type: got %v, want %v", got, want)
		}
	}

}

func TestPreviousLease(t *testing.T) {
	handler, cleanup := testHandler(t)
	defer cleanup()

	var (
		addr1         = net.IP{192, 168, 42, 23}
		addr2         = net.IP{192, 168, 42, 42}
		hardwareAddr1 = net.HardwareAddr{0x11, 0x22, 0x33, 0x44, 0x55, 0x66}
		hardwareAddr2 = net.HardwareAddr{0x11, 0x22, 0x33, 0x44, 0x55, 0x77}
	)

	p := request(addr1, hardwareAddr1)
	resp := handler.serveDHCP(p, dhcp4.Request, p.ParseOptions())
	if got, want := resp.YIAddr().To4(), addr1.To4(); !bytes.Equal(got, want) {
		t.Errorf("DHCPREQUEST resulted in wrong IP: got %v, want %v", got, want)
	}

	p = request(addr1, hardwareAddr2)
	resp = handler.serveDHCP(p, dhcp4.Request, p.ParseOptions())
	if got, want := messageType(resp), dhcp4.NAK; got != want {
		t.Errorf("DHCPREQUEST resulted in unexpected message type: got %v, want %v", got, want)
	}

	p = discover(net.IPv4zero, hardwareAddr1)
	resp = handler.serveDHCP(p, dhcp4.Discover, p.ParseOptions())
	if got, want := resp.YIAddr().To4(), addr1.To4(); !bytes.Equal(got, want) {
		t.Errorf("DHCPOFFER for wrong IP: got %v, want %v", got, want)
	}

	// Free addr1 by requesting addr2
	p = request(addr2, hardwareAddr1)
	resp = handler.serveDHCP(p, dhcp4.Request, p.ParseOptions())
	if got, want := resp.YIAddr().To4(), addr2.To4(); !bytes.Equal(got, want) {
		t.Errorf("DHCPREQUEST resulted in wrong IP: got %v, want %v", got, want)
	}

	// Verify addr1 is now available to other clients
	p = request(addr1, hardwareAddr2)
	resp = handler.serveDHCP(p, dhcp4.Request, p.ParseOptions())
	if got, want := resp.YIAddr().To4(), addr1.To4(); !bytes.Equal(got, want) {
		t.Errorf("DHCPREQUEST resulted in wrong IP: got %v, want %v", got, want)
	}
}

func TestPermanentLease(t *testing.T) {
	handler, cleanup := testHandler(t)
	defer cleanup()
	now := time.Now()
	handler.timeNow = func() time.Time { return now }

	var (
		addr         = net.IP{192, 168, 42, 23}
		hardwareAddr = net.HardwareAddr{0x11, 0x22, 0x33, 0x44, 0x55, 0x66}
	)

	handler.SetLeases([]*Lease{
		{
			Num:          2,
			Addr:         addr,
			HardwareAddr: hardwareAddr.String(),
		},
	})

	p := request(addr, hardwareAddr)
	resp := handler.serveDHCP(p, dhcp4.Request, p.ParseOptions())
	if got, want := resp.YIAddr().To4(), addr.To4(); !bytes.Equal(got, want) {
		t.Errorf("DHCPREQUEST resulted in wrong IP: got %v, want %v", got, want)
	}

	now = now.Add(3 * time.Hour)

	hardwareAddr[len(hardwareAddr)-1] = 0x77

	p = request(addr, hardwareAddr)
	resp = handler.serveDHCP(p, dhcp4.Request, p.ParseOptions())
	if got, want := messageType(resp), dhcp4.NAK; got != want {
		t.Errorf("DHCPREQUEST resulted in unexpected message type: got %v, want %v", got, want)
	}
}

func TestExpiration(t *testing.T) {
	handler, cleanup := testHandler(t)
	defer cleanup()
	now := time.Now()
	handler.timeNow = func() time.Time { return now }

	var (
		addr         = net.IP{192, 168, 42, 23}
		hardwareAddr = net.HardwareAddr{0x11, 0x22, 0x33, 0x44, 0x55, 0x66}
	)

	t.Run("allocate entire pool", func(t *testing.T) {
		// 1 is the DHCP server,
		for i := 1; i < 1+230; i++ {
			addr[len(addr)-1] = byte(1 + (i % 254)) // avoid .0 (net) and .255 (broadcast)
			hardwareAddr[len(hardwareAddr)-1] = addr[len(addr)-1]
			p := request(addr, hardwareAddr)
			resp := handler.serveDHCP(p, dhcp4.Request, p.ParseOptions())
			if got, want := resp.YIAddr().To4(), addr.To4(); !bytes.Equal(got, want) {
				t.Errorf("DHCPREQUEST resulted in wrong IP: got %v, want %v", got, want)
			}
		}
	})

	t.Run("re-allocate", func(t *testing.T) {
		// 1 is the DHCP server,
		for i := 1; i < 1+230; i++ {
			addr[len(addr)-1] = byte(1 + (i % 254)) // avoid .0 (net) and .255 (broadcast)
			hardwareAddr[len(hardwareAddr)-1] = addr[len(addr)-1]
			p := request(addr, hardwareAddr)
			resp := handler.serveDHCP(p, dhcp4.Request, p.ParseOptions())
			if got, want := resp.YIAddr().To4(), addr.To4(); !bytes.Equal(got, want) {
				t.Errorf("DHCPREQUEST resulted in wrong IP: got %v, want %v", got, want)
			}
		}
	})

	t.Run("full", func(t *testing.T) {
		// 1 is the DHCP server,
		for i := 1; i < 1+230; i++ {
			addr[len(addr)-1] = byte(1 + (i % 254)) // avoid .0 (net) and .255 (broadcast)
			hardwareAddr[len(hardwareAddr)-1] = addr[len(addr)-1] - 1
			p := request(addr, hardwareAddr)
			resp := handler.serveDHCP(p, dhcp4.Request, p.ParseOptions())
			if got, want := messageType(resp), dhcp4.NAK; got != want {
				t.Errorf("DHCPREQUEST resulted in unexpected message type: got %v, want %v", got, want)
			}
		}

		hardwareAddr[len(hardwareAddr)-1] = 0
		p := discover(addr, hardwareAddr)
		resp := handler.serveDHCP(p, dhcp4.Discover, p.ParseOptions())
		if resp != nil {
			t.Errorf("DHCPDISCOVER(%v) resulted in unexpected offer of %v", addr, resp.YIAddr())
		}
	})

	now = now.Add(3 * time.Hour)

	t.Run("re-allocate after expiration", func(t *testing.T) {
		// 1 is the DHCP server,
		for i := 1; i < 1+230; i++ {
			addr[len(addr)-1] = byte(1 + (i % 254)) // avoid .0 (net) and .255 (broadcast)
			p := request(addr, hardwareAddr)
			resp := handler.serveDHCP(p, dhcp4.Request, p.ParseOptions())
			if got, want := resp.YIAddr().To4(), addr.To4(); !bytes.Equal(got, want) {
				t.Errorf("DHCPREQUEST resulted in wrong IP: got %v, want %v", got, want)
			}
		}
	})
}

func TestRequestExpired(t *testing.T) {
	handler, cleanup := testHandler(t)
	defer cleanup()
	now := time.Now()
	handler.timeNow = func() time.Time { return now }

	addr := net.IP{192, 168, 42, 23}

	hardwareAddr := map[string]net.HardwareAddr{
		"xps": net.HardwareAddr{0x11, 0x22, 0x33, 0x44, 0x55, 0x66},
		"mbp": net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff},
	}

	t.Run("mbp grabs an address", func(t *testing.T) {
		p := request(addr, hardwareAddr["mbp"])
		resp := handler.serveDHCP(p, dhcp4.Request, p.ParseOptions())
		if got, want := messageType(resp), dhcp4.ACK; got != want {
			t.Errorf("DHCPREQUEST resulted in unexpected message type: got %v, want %v", got, want)
		}
	})

	now = now.Add(3 * time.Hour)

	t.Run("xps grabs the same address", func(t *testing.T) {
		p := request(addr, hardwareAddr["xps"])
		resp := handler.serveDHCP(p, dhcp4.Request, p.ParseOptions())
		if got, want := messageType(resp), dhcp4.ACK; got != want {
			t.Errorf("DHCPREQUEST resulted in unexpected message type: got %v, want %v", got, want)
		}
	})

	t.Run("mbp requests its old address", func(t *testing.T) {
		p := request(addr, hardwareAddr["mbp"])
		resp := handler.serveDHCP(p, dhcp4.Request, p.ParseOptions())
		if got, want := messageType(resp), dhcp4.NAK; got != want {
			t.Errorf("DHCPREQUEST resulted in unexpected message type: got %v, want %v", got, want)
		}
	})

	t.Run("mbp requests any", func(t *testing.T) {
		p := request(addr, hardwareAddr["mbp"])
		resp := handler.serveDHCP(p, dhcp4.Discover, p.ParseOptions())
		if got, want := resp.YIAddr().To4(), addr.To4(); bytes.Equal(got, want) {
			t.Errorf("DHCPOFFER for wrong IP: got offered %v (in use!)", got)
		}
	})
}

func TestServerID(t *testing.T) {
	handler, cleanup := testHandler(t)
	defer cleanup()

	var (
		addr         = net.IP{192, 168, 42, 23}
		hardwareAddr = net.HardwareAddr{0x11, 0x22, 0x33, 0x44, 0x55, 0x66}
	)

	p := request(addr, hardwareAddr, dhcp4.Option{
		Code:  dhcp4.OptionServerIdentifier,
		Value: net.IP{192, 168, 1, 1},
	})
	resp := handler.serveDHCP(p, dhcp4.Request, p.ParseOptions())
	if resp != nil {
		t.Errorf("DHCPDISCOVER(%v) resulted in unexpected offer of %v", addr, resp.YIAddr())
	}
}

func TestPersistentStorage(t *testing.T) {
	handler, cleanup := testHandler(t)
	defer cleanup()

	var (
		addr         = net.IP{192, 168, 42, 4}
		hardwareAddr = net.HardwareAddr{0x11, 0x22, 0x33, 0x44, 0x55, 0x66}
	)

	handler.SetLeases([]*Lease{
		{
			Num:          2,
			Addr:         addr,
			HardwareAddr: hardwareAddr.String(),
		},
	})

	p := request(net.IPv4zero, hardwareAddr)
	resp := handler.serveDHCP(p, dhcp4.Discover, p.ParseOptions())
	if got, want := resp.YIAddr().To4(), addr.To4(); !bytes.Equal(got, want) {
		t.Errorf("DHCPOFFER for wrong IP: got %v, want %v", got, want)
	}
}
