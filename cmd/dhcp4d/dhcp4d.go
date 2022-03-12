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
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"html/template"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"
	"unicode"

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

var iface = flag.String("interface", "lan0", "ethernet interface to listen for DHCPv4 requests on")

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

var (
	leasesMu sync.Mutex
	leases   []*dhcp4d.Lease
)

var (
	timefmt = func(t time.Time) string {
		return t.Format("2006-01-02 15:04")
	}
	leasesTmpl = template.Must(template.New("").Funcs(template.FuncMap{
		"timefmt": timefmt,
		"since": func(t time.Time) string {
			dur := time.Since(t)
			if dur.Hours() > 24 {
				return timefmt(t)
			}
			return dur.Truncate(1 * time.Second).String()
		},
		"zero": func(t time.Time) bool {
			return t.IsZero()
		},
	}).Parse(`<!DOCTYPE html>
<head>
<meta charset="utf-8">
<title>DHCPv4 status</title>
<style type="text/css">
body {
  margin-left: 1em;
}
td, th {
  padding-left: 1em;
  padding-right: 1em;
  padding-bottom: .25em;
}
td:first-child, th:first-child {
  padding-left: .25em;
}
td:last-child, th:last-child {
  padding-right: .25em;
}
th {
  padding-top: 1em;
  text-align: left;
}
span.active, span.expired, span.static, span.hostname-override {
  min-width: 5em;
  display: inline-block;
  text-align: center;
  border: 1px solid grey;
  border-radius: 5px;
}
span.active {
  background-color: #00f000;
}
span.expired {
  background-color: #f00000;
}
span.hostname-override {
  min-width: 1em;
  background-color: orange;
}
.ipaddr, .hwaddr {
  font-family: monospace;
}
tr:nth-child(even) {
  background: #eee;
}
form {
  display: inline;
}
</style>
</head>
<body>
{{ define "table" }}
<tr>
<th>IP address</th>
<th>Hostname</th>
<th>MAC address</th>
<th>Vendor</th>
<th>Last ACK</th>
</tr>
{{ range $idx, $l := . }}
<tr>
<td class="ipaddr">{{$l.Addr}}</td>
<td>
<form action="/sethostname" method="post">
<input type="hidden" name="hardwareaddr" value="{{$l.HardwareAddr}}">
<input type="text" name="hostname" value="{{$l.Hostname}}">
</form>
{{ if (ne $l.HostnameOverride "") }}
<span class="hostname-override">!</span>
{{ end }}
</td>
<td class="hwaddr">{{$l.HardwareAddr}}</td>
<td>{{$l.Vendor}}</td>
<td>
{{ if (not (zero $l.LastACK)) }}
{{ timefmt $l.LastACK }}
{{ if $l.Active }}
<span class="active">active</span>
{{ end }}
{{ if $l.Expired }}
<span class="expired">expired</span>
{{ end }}
{{ end }}
</td>
</tr>
{{ end }}
{{ end }}

<h1>Static Leases</h1>
<table cellpadding="0" cellspacing="0">
{{ template "table" .StaticLeases }}
</table>

<h1>Dynamic Leases</h1>
<table cellpadding="0" cellspacing="0">
{{ template "table" .DynamicLeases }}
</table>

</body>
</html>
`))
)

func loadLeases(h *dhcp4d.Handler, fn string) error {
	b, err := ioutil.ReadFile(fn)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}

	leasesMu.Lock()
	defer leasesMu.Unlock()
	if err := json.Unmarshal(b, &leases); err != nil {
		return err
	}
	h.SetLeases(leases)
	updateNonExpired(leases)

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

type srv struct {
	errs   chan error
	leases func(newLeases []*dhcp4d.Lease, latest *dhcp4d.Lease)
}

func newSrv(permDir string) (*srv, error) {
	mayqtt := MQTT()

	http.Handle("/metrics", promhttp.Handler())
	if err := updateListeners(); err != nil {
		return nil, err
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

	if err := os.MkdirAll(filepath.Join(permDir, "dhcp4d"), 0755); err != nil {
		return nil, err
	}
	errs := make(chan error)
	ifc, err := net.InterfaceByName(*iface)
	if err != nil {
		return nil, err
	}
	handler, err := dhcp4d.NewHandler(permDir, ifc, *iface, nil)
	if err != nil {
		return nil, err
	}
	if err := loadLeases(handler, filepath.Join(permDir, "dhcp4d/leases.json")); err != nil {
		return nil, err
	}

	http.HandleFunc("/sethostname", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			http.Error(w, "want POST", http.StatusMethodNotAllowed)
			return
		}
		hwaddr := r.FormValue("hardwareaddr")
		if hwaddr == "" {
			http.Error(w, "missing hardwareaddr parameter", http.StatusBadRequest)
			return
		}
		hostname := r.FormValue("hostname")
		if hostname == "" {
			http.Error(w, "missing hostname parameter", http.StatusBadRequest)
			return
		}
		if err := handler.SetHostname(hwaddr, hostname); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		http.Redirect(w, r, "/", http.StatusFound)
	})

	http.HandleFunc("/lease/", func(w http.ResponseWriter, r *http.Request) {
		hostname := strings.TrimPrefix(r.URL.Path, "/lease/")
		if hostname == "" {
			http.Error(w, "syntax: /lease/<hostname>", http.StatusBadRequest)
			return
		}
		leasesMu.Lock()
		defer leasesMu.Unlock()
		var lease *dhcp4d.Lease
		for _, l := range leases {
			if l.Hostname != hostname {
				continue
			}
			lease = l
			break
		}
		if lease == nil {
			http.Error(w, "no lease found", http.StatusNotFound)
			return
		}
		b, err := json.Marshal(lease)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("X-Lease-Active", fmt.Sprint(lease.Expiry.After(time.Now().Add(handler.LeasePeriod*2/3))))
		if _, err := io.Copy(w, bytes.NewReader(b)); err != nil {
			log.Printf("/lease/%s: %v", hostname, err)
		}
	})

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

		type tmplLease struct {
			dhcp4d.Lease

			Vendor  string
			Expired bool
			Static  bool
			Active  bool
		}

		leasesMu.Lock()
		defer leasesMu.Unlock()
		static := make([]tmplLease, 0, len(leases))
		dynamic := make([]tmplLease, 0, len(leases))
		now := time.Now()
		tl := func(l *dhcp4d.Lease) tmplLease {
			return tmplLease{
				Lease:   *l,
				Vendor:  ouiDB.Lookup(l.HardwareAddr[:8]),
				Expired: l.Expired(now),
				Active:  l.Active(now),
				Static:  l.Expiry.IsZero(),
			}
		}
		for _, l := range leases {
			if l.Expiry.IsZero() {
				static = append(static, tl(l))
			} else {
				dynamic = append(dynamic, tl(l))
			}
		}
		sort.Slice(static, func(i, j int) bool {
			return static[i].Num < static[j].Num
		})
		sort.Slice(dynamic, func(i, j int) bool {
			return !dynamic[i].Expiry.Before(dynamic[j].Expiry)
		})

		if err := leasesTmpl.Execute(w, struct {
			StaticLeases  []tmplLease
			DynamicLeases []tmplLease
		}{
			StaticLeases:  static,
			DynamicLeases: dynamic,
		}); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	})

	handler.Leases = func(newLeases []*dhcp4d.Lease, latest *dhcp4d.Lease) {
		leasesMu.Lock()
		defer leasesMu.Unlock()
		leases = newLeases
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
		if err := renameio.WriteFile(filepath.Join(permDir, "dhcp4d/leases.json"), b, 0644); err != nil {
			errs <- err
		}
		updateNonExpired(leases)
		if err := notify.Process("/user/dnsd", syscall.SIGUSR1); err != nil {
			log.Printf("notifying dnsd: %v", err)
		}

		// Publish the DHCP lease as JSON to MQTT, if configured:
		leaseVal := struct {
			Addr         string    `json:"addr"`
			HardwareAddr string    `json:"hardware_addr"`
			Expiration   time.Time `json:"expiration"`
		}{
			Addr:         latest.Addr.String(),
			HardwareAddr: latest.HardwareAddr,
			Expiration:   latest.Expiry.In(time.UTC),
		}
		leaseJSON, err := json.Marshal(leaseVal)
		if err != nil {
			log.Fatal(err)
		}
		// MQTT requires valid UTF-8 and some brokers don’t cope well with
		// invalid UTF-8: https://github.com/fhmq/hmq/issues/104
		identifier := strings.ToValidUTF8(latest.Hostname, "")
		// Some MQTT clients (e.g. mosquitto_pub) don’t cope well with topic
		// names containing non-printable characters (see also
		// https://twitter.com/zekjur/status/1347295676909158400):
		identifier = strings.Map(func(r rune) rune {
			if unicode.IsPrint(r) {
				return r
			}
			return -1
		}, identifier)
		if identifier == "" {
			identifier = latest.HardwareAddr
		}
		select {
		case mayqtt <- PublishRequest{
			Topic:    "router7/dhcp4d/lease/" + identifier,
			Retained: true,
			Payload:  leaseJSON,
		}:
		default:
			// Channel not ready? skip publishing this lease (best-effort).
			// This is an easy way of breaking circular dependencies between
			// MQTT broker and DHCP server, and avoiding deadlocks.
		}
	}
	conn, err := conn.NewUDP4BoundListener(*iface, ":67")
	if err != nil {
		return nil, err
	}
	go func() {
		errs <- dhcp4.Serve(conn, handler)
	}()
	return &srv{
		errs,
		handler.Leases,
	}, nil
}

func (s *srv) run(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case err := <-s.errs:
		return err
	}
}

func main() {
	// TODO: drop privileges, run as separate uid?
	flag.Parse()
	srv, err := newSrv("/perm")
	if err != nil {
		log.Fatal(err)
	}
	if err := srv.run(context.Background()); err != nil {
		log.Fatal(err)
	}
}
