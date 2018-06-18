// Binary dnsd answers DNS requests by forwarding or consulting DHCP leases.
package main

import (
	"encoding/json"
	"flag"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/gokrazy/gokrazy"

	"router7/internal/dhcp4d"
	"router7/internal/dns"
	"router7/internal/multilisten"
	"router7/internal/netconfig"

	_ "net/http/pprof"
)

func updateListeners() error {
	hosts, err := gokrazy.PrivateInterfaceAddrs()
	if err != nil {
		return err
	}
	if net1, err := multilisten.IPv6Net1("/perm"); err == nil {
		hosts = append(hosts, net1)
	}

	return multilisten.ListenAndServe(hosts, "8053", http.DefaultServeMux)
}

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
	updateListeners()
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGUSR1)
	go func() {
		for range ch {
			if err := updateListeners(); err != nil {
				log.Printf("updateListeners: %v", err)
			}
			if err := readLeases(); err != nil {
				log.Printf("readLeases: %v", err)
			}
		}
	}()
	return srv.ListenAndServe()
}

func main() {
	// TODO: drop privileges, run as separate uid?
	flag.Parse()
	if err := logic(); err != nil {
		log.Fatal(err)
	}
}
