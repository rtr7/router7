// Binary dhcp4 obtains a DHCPv4 lease, persists it to
// /perm/dhcp4/wire/lease.json and notifies netconfigd.
package main

import (
	"encoding/json"
	"flag"
	"io/ioutil"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"router7/internal/dhcp4"
	"router7/internal/notify"
	"router7/internal/teelogger"
)

var log = teelogger.NewConsole()

func logic() error {
	const configPath = "/perm/dhcp4/wire/lease.json"
	if err := os.MkdirAll(filepath.Dir(configPath), 0755); err != nil {
		return err
	}
	iface, err := net.InterfaceByName("uplink0")
	if err != nil {
		return err
	}
	c := dhcp4.Client{
		Interface: iface,
	}
	usr2 := make(chan os.Signal, 1)
	signal.Notify(usr2, syscall.SIGUSR2)
	for c.ObtainOrRenew() {
		if err := c.Err(); err != nil {
			log.Printf("Temporary error: %v", err)
			time.Sleep(1 * time.Second)
			continue
		}
		log.Printf("lease: %+v", c.Config())
		b, err := json.Marshal(c.Config())
		if err != nil {
			return err
		}
		if err := ioutil.WriteFile(configPath, b, 0644); err != nil {
			return err
		}
		if err := notify.Process("/user/netconfi", syscall.SIGUSR1); err != nil {
			log.Printf("notifying netconfig: %v", err)
		}
		select {
		case <-time.After(time.Until(c.Config().RenewAfter)):
			// fallthrough and renew the DHCP lease
		case <-usr2:
			if err := c.Release(); err != nil {
				return err
			}
			os.Exit(125) // quit supervision by gokrazy
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
