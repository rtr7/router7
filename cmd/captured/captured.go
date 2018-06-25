// Binary captured streams network packets to wireshark via SSH, replaying
// buffered packets upon connection for retroactive debugging.
package main

import (
	"container/ring"
	"context"
	"flag"
	"log"
	"sync"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"

	"golang.org/x/sync/errgroup"

	_ "net/http/pprof"
)

var (
	hostKeyPath = flag.String("host_key",
		"/perm/breakglass.host_key",
		"path to a PEM-encoded RSA, DSA or ECDSA private key (create using e.g. ssh-keygen -f /perm/breakglass.host_key -N '' -t rsa)")
)

func capturePackets(ctx context.Context) (chan gopacket.Packet, error) {
	packets := make(chan gopacket.Packet)
	for _, ifname := range []string{"uplink0", "lan0"} {
		handle, err := pcapgo.OpenEthernet(ifname)
		if err != nil {
			return nil, err
		}

		if err := handle.SetBPF(instructions); err != nil {
			return nil, err
		}

		pkgsrc := gopacket.NewPacketSource(handle, layers.LayerTypeEthernet)
		go func() {
			defer handle.Close()
			for packet := range pkgsrc.Packets() {
				select {
				case packets <- packet:
				case <-ctx.Done():
					return
				}
			}
		}()
	}
	return packets, nil
}

type packetRingBuffer struct {
	sync.Mutex
	r *ring.Ring
}

func newPacketRingBuffer(size int) *packetRingBuffer {
	return &packetRingBuffer{
		r: ring.New(size),
	}
}

func (prb *packetRingBuffer) writePacket(p gopacket.Packet) {
	prb.Lock()
	defer prb.Unlock()
	prb.r.Value = p
	prb.r = prb.r.Next()
}

func (prb *packetRingBuffer) packetsLocked() []gopacket.Packet {
	packets := make([]gopacket.Packet, 0, prb.r.Len())
	prb.r.Do(func(x interface{}) {
		if x != nil {
			packets = append(packets, x.(gopacket.Packet))
		}
	})
	return packets
}

func logic() error {
	prb := newPacketRingBuffer(50000)

	var eg errgroup.Group
	eg.Go(func() error { return listenAndServe(prb) })
	eg.Go(func() error {
		packets, err := capturePackets(context.Background())
		if err != nil {
			return err
		}
		for packet := range packets {
			prb.writePacket(packet)
		}
		return nil
	})

	return eg.Wait()
}

func main() {
	flag.Parse()
	if err := logic(); err != nil {
		log.Fatal(err)
	}
}
