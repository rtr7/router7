// Binary dnsd answers DNS requests by forwarding or consulting DHCP leases.
package main

import (
	"encoding/json"
	"flag"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/gokrazy/gokrazy"
	miekgdns "github.com/miekg/dns"

	"router7/internal/dhcp4d"
	"router7/internal/dns"
	"router7/internal/multilisten"
	"router7/internal/netconfig"

	_ "net/http/pprof"
)

var (
	httpListeners = multilisten.NewPool()
	dnsListeners  = multilisten.NewPool()
)

func updateListeners(mux *miekgdns.ServeMux) error {
	hosts, err := gokrazy.PrivateInterfaceAddrs()
	if err != nil {
		return err
	}

	dnsListeners.ListenAndServe(hosts, func(host string) multilisten.Listener {
		return &listenerAdapter{&miekgdns.Server{
			Addr:    net.JoinHostPort(host, "53"),
			Net:     "udp",
			Handler: mux,
		}}
	})

	if net1, err := multilisten.IPv6Net1("/perm"); err == nil {
		hosts = append(hosts, net1)
	}

	httpListeners.ListenAndServe(hosts, func(host string) multilisten.Listener {
		return &http.Server{Addr: net.JoinHostPort(host, "8053")}
	})

	return nil
}

type listenerAdapter struct {
	*miekgdns.Server
}

func (a *listenerAdapter) Close() error { return a.Shutdown() }

func logic() error {
	// TODO: set correct upstream DNS resolver(s)
	ip, err := netconfig.LinkAddress("/perm", "lan0")
	if err != nil {
		return err
	}
	srv := dns.NewServer(ip.String()+":53", "lan")
	readLeases := func() error {
		b, err := ioutil.ReadFile("/perm/dhcp4d/leases.json")
		if err != nil {
			return err
		}
		var leases []dhcp4d.Lease
		if err := json.Unmarshal(b, &leases); err != nil {
			return err
		}
		srv.SetLeases(leases)
		return nil
	}
	if err := readLeases(); err != nil {
		log.Printf("cannot resolve DHCP hostnames: %v", err)
	}
	http.Handle("/metrics", srv.PrometheusHandler())
	updateListeners(srv.Mux)
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGUSR1)
	for range ch {
		if err := updateListeners(srv.Mux); err != nil {
			log.Printf("updateListeners: %v", err)
		}
		if err := readLeases(); err != nil {
			log.Printf("readLeases: %v", err)
		}
	}
	return nil
}

func main() {
	// TODO: drop privileges, run as separate uid?
	flag.Parse()
	if err := logic(); err != nil {
		log.Fatal(err)
	}
}
