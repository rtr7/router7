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

package dhcp4

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

func (r *replayer) Close() error                         { return nil }
func (r *replayer) Write(b []byte) error                 { /*log.Printf("-> %v", b); */ return nil }
func (r *replayer) SetReadTimeout(t time.Duration) error { return nil }

func (r *replayer) ReadFrom() ([]byte, net.IP, error) {
	data, _, err := r.pcapr.ReadPacketData()
	if err != nil {
		return nil, nil, err
	}
	pkt := gopacket.NewPacket(data, layers.LayerTypeEthernet, gopacket.DecodeOptions{})
	// TODO: get source IP
	udp := pkt.Layer(layers.LayerTypeUDP)
	if udp == nil {
		return nil, nil, fmt.Errorf("pcap contained unexpected non-UDP packet")
	}

	//log.Printf("ReadFrom(): %v, %v, pkt = %+v", udp.LayerPayload(), err, pkt)
	return udp.LayerPayload(), net.ParseIP("192.168.23.1"), err
}

func TestDHCP4(t *testing.T) {
	f, err := os.Open("testdata/fiber7.pcap")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	pcapr, err := pcapgo.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}

	mac, err := net.ParseMAC("d8:58:d7:00:4e:df")
	if err != nil {
		t.Fatal(err)
	}

	now := time.Now()
	c := Client{
		hardwareAddr: mac,
		timeNow:      func() time.Time { return now },
		connection:   &replayer{pcapr: pcapr},
		generateXID: func(b []byte) {
			if got, want := len(b), 4; got != want {
				t.Fatalf("github.com/d2g/dhcp4client request unexpected amount of bytes: got %d, want %d", got, want)
			}
			// TODO: read the transaction ID from the pcap file
			copy(b, []byte{0x77, 0x08, 0xd7, 0x24})
		},
	}

	c.ObtainOrRenew()
	if err := c.Err(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	got := c.Config()
	want := Config{
		RenewAfter: now.Add(13*time.Minute + 24*time.Second),
		ClientIP:   "85.195.207.62",
		SubnetMask: "255.255.255.128",
		Router:     "85.195.207.1",
		DNS: []string{
			"77.109.128.2",
			"213.144.129.20",
		},
	}
	if diff := cmp.Diff(got, want); diff != "" {
		t.Fatalf("unexpected config: diff (-got +want):\n%s", diff)
	}
}
