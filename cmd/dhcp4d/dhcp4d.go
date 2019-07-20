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

// Binary dhcp4d hands out DHCPv4 leases to clients.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gokrazy/gokrazy"
	"github.com/google/renameio"
	"github.com/krolaw/dhcp4"
	"github.com/krolaw/dhcp4/conn"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/rtr7/router7/internal/dhcp4d"
	"github.com/rtr7/router7/internal/multilisten"
	"github.com/rtr7/router7/internal/notify"
	"github.com/rtr7/router7/internal/oui"
	"github.com/rtr7/router7/internal/teelogger"
)

var log = teelogger.NewConsole()

var nonExpiredLeases = promauto.NewGauge(prometheus.GaugeOpts{
	Name: "non_expired_leases",
	Help: "Number of non-expired DHCP leases",
})

func updateNonExpired(leases []*dhcp4d.Lease) {
	now := time.Now()
	nonExpired := 0
	for _, l := range leases {
		if l.Expired(now) {
			continue
		}
		nonExpired++
	}
	nonExpiredLeases.Set(float64(nonExpired))
}

var ouiDB = oui.NewDB("/perm/dhcp4d/oui")

func loadLeases(h *dhcp4d.Handler, fn string) error {
	b, err := ioutil.ReadFile(fn)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	var leases []*dhcp4d.Lease
	if err := json.Unmarshal(b, &leases); err != nil {
		return err
	}
	h.SetLeases(leases)
	updateNonExpired(leases)

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		host, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		ip := net.ParseIP(host)
		if xff := r.Header.Get("X-Forwarded-For"); ip.IsLoopback() && xff != "" {
			ip = net.ParseIP(xff)
		}
		if !gokrazy.IsInPrivateNet(ip) {
			http.Error(w, fmt.Sprintf("access from %v forbidden", ip), http.StatusForbidden)
			return
		}
		// TODO: html template
		for _, l := range leases {
			fmt.Fprintf(w, "• %+v (vendor %v)\n", l, ouiDB.Lookup(l.HardwareAddr[:8]))
		}
	})

	return nil
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
		return &http.Server{Addr: net.JoinHostPort(host, "8067")}
	})
	return nil
}

func logic() error {
	http.Handle("/metrics", promhttp.Handler())
	if err := updateListeners(); err != nil {
		return err
	}
	go func() {
		ch := make(chan os.Signal, 1)
		signal.Notify(ch, syscall.SIGUSR1)
		for range ch {
			if err := updateListeners(); err != nil {
				log.Printf("updateListeners: %v", err)
			}
		}
	}()

	if err := os.MkdirAll("/perm/dhcp4d", 0755); err != nil {
		return err
	}
	errs := make(chan error)
	handler, err := dhcp4d.NewHandler("/perm", nil, nil)
	if err != nil {
		return err
	}
	if err := loadLeases(handler, "/perm/dhcp4d/leases.json"); err != nil {
		return err
	}
	handler.Leases = func(leases []*dhcp4d.Lease, latest *dhcp4d.Lease) {
		log.Printf("DHCPACK %+v", latest)
		b, err := json.Marshal(leases)
		if err != nil {
			errs <- err
			return
		}
		var out bytes.Buffer
		if err := json.Indent(&out, b, "", "\t"); err == nil {
			b = out.Bytes()
		}
		if err := renameio.WriteFile("/perm/dhcp4d/leases.json", out.Bytes(), 0644); err != nil {
			errs <- err
		}
		updateNonExpired(leases)
		if err := notify.Process("/user/dnsd", syscall.SIGUSR1); err != nil {
			log.Printf("notifying dnsd: %v", err)
		}
	}
	conn, err := conn.NewUDP4BoundListener("lan0", ":67") // TODO: customizeable
	if err != nil {
		return err
	}
	go func() {
		errs <- dhcp4.Serve(conn, handler)
	}()
	return <-errs
}

func main() {
	// TODO: drop privileges, run as separate uid?
	flag.Parse()
	if err := logic(); err != nil {
		log.Fatal(err)
	}
}
