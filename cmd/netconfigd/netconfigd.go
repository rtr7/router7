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

// Binary netconfigd reads state from dhcp4, dhcp6, … and applies it.
package main

import (
	"flag"
	"net"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"

	"github.com/gokrazy/gokrazy"
	"github.com/google/nftables"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/rtr7/router7/internal/multilisten"
	"github.com/rtr7/router7/internal/netconfig"
	"github.com/rtr7/router7/internal/teelogger"
)

var log = teelogger.NewConsole()

var (
	linger = flag.Bool("linger", true, "linger around after applying the configuration (until killed)")
)

func init() {
	var c nftables.Conn
	for _, metric := range []struct {
		name           string
		labels         prometheus.Labels
		obj            *nftables.CounterObj
		packets, bytes uint64
	}{
		{
			name:   "filter_forward",
			labels: prometheus.Labels{"family": "ipv4"},
			obj: &nftables.CounterObj{
				Table: &nftables.Table{Family: nftables.TableFamilyIPv4, Name: "filter"},
				Name:  "fwded",
			},
		},
		{
			name:   "filter_forward",
			labels: prometheus.Labels{"family": "ipv6"},
			obj: &nftables.CounterObj{
				Table: &nftables.Table{Family: nftables.TableFamilyIPv6, Name: "filter"},
				Name:  "fwded",
			},
		},
	} {
		metric := metric // copy
		var mu sync.Mutex
		updateCounter := func() {
			mu.Lock()
			defer mu.Unlock()
			objs, err := c.GetObjReset(metric.obj)
			if err != nil ||
				len(objs) != 1 {
				return
			}
			if co, ok := objs[0].(*nftables.CounterObj); ok {
				metric.packets += co.Packets
				metric.bytes += co.Bytes
			}
		}
		promauto.NewCounterFunc(
			prometheus.CounterOpts{
				Subsystem:   "nftables",
				Name:        metric.name + "_packets",
				Help:        "packet count",
				ConstLabels: metric.labels,
			},
			func() float64 {
				updateCounter()
				return float64(metric.packets)
			})
		promauto.NewCounterFunc(
			prometheus.CounterOpts{
				Subsystem:   "nftables",
				Name:        metric.name + "_bytes",
				Help:        "bytes count",
				ConstLabels: metric.labels,
			},
			func() float64 {
				updateCounter()
				return float64(metric.bytes)
			})
	}
}

var httpListeners = multilisten.NewPool()

func updateListeners() error {
	hosts, err := gokrazy.PrivateInterfaceAddrs()
	if err != nil {
		return err
	}
	if net1, err := multilisten.IPv6Net1("/perm"); err == nil {
		hosts = append(hosts, net1)
	}

	httpListeners.ListenAndServe(hosts, func(host string) multilisten.Listener {
		return &http.Server{Addr: net.JoinHostPort(host, "8066")}
	})
	return nil
}

func logic() error {
	if *linger {
		http.Handle("/metrics", promhttp.Handler())
		if err := updateListeners(); err != nil {
			return err
		}
	}
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGUSR1)
	for {
		err := netconfig.Apply("/perm/", "/")
		// Notify gokrazy about new addresses (netconfig.Apply might have
		// modified state before returning an error) so that listeners can be
		// updated.
		p, _ := os.FindProcess(1)
		if err := p.Signal(syscall.SIGHUP); err != nil {
			log.Printf("kill -HUP 1: %v", err)
		}
		if err != nil {
			return err
		}
		if !*linger {
			break
		}
		<-ch
		if err := updateListeners(); err != nil {
			log.Printf("updateListeners: %v", err)
		}
	}
	return nil
}

func main() {
	flag.Parse()
	if err := logic(); err != nil {
		log.Fatal(err)
	}
}
