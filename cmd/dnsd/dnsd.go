// Binary dnsd answers DNS requests by forwarding or consulting DHCP leases.
package main

import (
	"encoding/json"
	"flag"
	"io/ioutil"
	"log"
	"os"
	"os/signal"
	"syscall"

	"router7/internal/dhcp4d"
	"router7/internal/dns"
	"router7/internal/netconfig"
)

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
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGUSR1)
	go func() {
		for range ch {
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
