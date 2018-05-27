// Binary dhcp4 obtains a DHCPv4 lease, persists its contents to
// /perm/dhcp4/wire/lease.json and notifies netconfigd.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"router7/internal/dhcp4"
	"router7/internal/notify"
)

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
	for c.ObtainOrRenew() {
		if err := c.Err(); err != nil {
			log.Printf("Temporary error: %v", err)
			continue
		}
		// TODO: use a logger which writes to /dev/console
		log.Printf("lease: %+v", c.Config())
		ioutil.WriteFile("/dev/console", []byte(fmt.Sprintf("lease: %+v\n", c.Config())), 0600)
		b, err := json.Marshal(c.Config())
		if err != nil {
			return err
		}
		if err := ioutil.WriteFile(configPath, b, 0644); err != nil {
			return err
		}
		if err := notify.Process("/user/netconfi", syscall.SIGUSR1); err != nil {
			log.Printf("notifying netconfig: %v", err)
			ioutil.WriteFile("/dev/console", []byte(fmt.Sprintf("notifying netconfigd: %+v\n", err)), 0600)
		}
		time.Sleep(time.Until(c.Config().RenewAfter))
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
