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

// Binary dhcp4 obtains a DHCPv4 lease, persists it to
// /perm/dhcp4/wire/lease.json and notifies netconfigd.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/renameio"
	"github.com/jpillora/backoff"
	"github.com/rtr7/router7/internal/dhcp4"
	"github.com/rtr7/router7/internal/netconfig"
	"github.com/rtr7/router7/internal/notify"
	"github.com/rtr7/router7/internal/teelogger"
)

var log = teelogger.NewConsole()

var (
	netInterface = flag.String("interface", "uplink0", "network interface to operate on")
	stateDir     = flag.String("state_dir", "/perm/dhcp4", "directory in which to store lease data (wire/lease.json) and last ACK (wire/ack)")
)

func healthy() error {
	req, err := http.NewRequest("GET", "http://localhost:7733/health.json", nil)
	if err != nil {
		return err
	}
	ctx, canc := context.WithTimeout(context.Background(), 5*time.Second)
	defer canc()
	req = req.WithContext(ctx)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	if got, want := resp.StatusCode, http.StatusOK; got != want {
		b, _ := ioutil.ReadAll(resp.Body)
		return fmt.Errorf("%v: got HTTP %v (%s), want HTTP status %v",
			req.URL.String(),
			resp.Status,
			string(b),
			want)
	}
	b, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	var reply struct {
		FirstError string `json:"first_error"`
	}
	if err := json.Unmarshal(b, &reply); err != nil {
		return err
	}

	if reply.FirstError != "" {
		return errors.New(reply.FirstError)
	}

	return nil
}

func logic() error {
	leasePath := filepath.Join(*stateDir, "wire/lease.json")
	if err := os.MkdirAll(filepath.Dir(leasePath), 0755); err != nil {
		return err
	}
	iface, err := net.InterfaceByName(*netInterface)
	if err != nil {
		return err
	}
	hwaddr := iface.HardwareAddr
	// The interface may not have been configured by netconfigd yet and might
	// still use the old hardware address. We overwrite it with the address that
	// netconfigd is going to use to fix this issue without additional
	// synchronization.
	details, err := netconfig.Interface("/perm", *netInterface)
	if err == nil {
		if spoof := details.SpoofHardwareAddr; spoof != "" {
			if addr, err := net.ParseMAC(spoof); err == nil {
				hwaddr = addr
			}
		}
	}
	ackFn := filepath.Join(*stateDir, "wire/ack")
	var ack *layers.DHCPv4
	ackB, err := ioutil.ReadFile(ackFn)
	if err != nil && !os.IsNotExist(err) {
		log.Printf("Loading previous DHCPACK packet from %s: %v", ackFn, err)
	} else {
		pkt := gopacket.NewPacket(ackB, layers.LayerTypeDHCPv4, gopacket.DecodeOptions{})
		if dhcp, ok := pkt.Layer(layers.LayerTypeDHCPv4).(*layers.DHCPv4); ok {
			ack = dhcp
		}
	}
	c := dhcp4.Client{
		Interface: iface,
		HWAddr:    hwaddr,
		Ack:       ack,
	}
	usr2 := make(chan os.Signal, 1)
	signal.Notify(usr2, syscall.SIGUSR2)
	backoff := backoff.Backoff{
		Factor: 2,
		Jitter: true,
		Min:    10 * time.Second,
		Max:    1 * time.Minute,
	}
ObtainOrRenew:
	for c.ObtainOrRenew() {
		if err := c.Err(); err != nil {
			dur := backoff.Duration()
			log.Printf("Temporary error: %v (waiting %v)", err, dur)
			time.Sleep(dur)
			continue
		}
		backoff.Reset()
		log.Printf("lease: %+v", c.Config())
		b, err := json.Marshal(c.Config())
		if err != nil {
			return err
		}
		if err := renameio.WriteFile(leasePath, b, 0644); err != nil {
			return fmt.Errorf("persisting lease to %s: %v", leasePath, err)
		}
		buf := gopacket.NewSerializeBuffer()
		gopacket.SerializeLayers(buf,
			gopacket.SerializeOptions{
				FixLengths:       true,
				ComputeChecksums: true,
			},
			c.Ack,
		)
		if err := renameio.WriteFile(ackFn, buf.Bytes(), 0644); err != nil {
			return fmt.Errorf("persisting DHCPACK to %s: %v", ackFn, err)
		}
		if err := notify.Process("/user/netconfigd", syscall.SIGUSR1); err != nil {
			log.Printf("notifying netconfig: %v", err)
		}

		unhealthyCycles := 0
		for {
			select {
			case <-time.After(time.Until(c.Config().RenewAfter)):
				// fallthrough and renew the DHCP lease
				continue ObtainOrRenew

			case <-time.After(1 * time.Minute):
				if err := healthy(); err == nil {
					unhealthyCycles = 0
					continue // wait another minute
				} else {
					unhealthyCycles++
					log.Printf("router unhealthy (cycle %d of 5): %v", unhealthyCycles, err)
					if unhealthyCycles < 5 {
						continue // wait until unhealthy for longer
					}
					// fallthrough
				}
				// Still not healthy? Drop DHCP lease and start from scratch.
				log.Printf("unhealthy for 5 cycles, starting over without lease")
				c.Ack = nil

			case <-usr2:
				log.Printf("SIGUSR2 received, sending DHCPRELEASE")
				if err := c.Release(); err != nil {
					return err
				}
				// Ensure dhcp4 does start from scratch next time
				// by deleting the DHCPACK file:
				if err := os.Remove(ackFn); err != nil && !os.IsNotExist(err) {
					return err
				}
				os.Exit(125) // quit supervision by gokrazy
			}
		}
	}
	return c.Err() // permanent error
}

func main() {
	// TODO: drop privileges, run as separate uid?
	flag.Parse()
	if err := logic(); err != nil {
		log.Fatal(err)
	}
}
