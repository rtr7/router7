// Binary dhcp6 obtains a DHCPv6 lease, persists it to
// /perm/dhcp6/wire/lease.json and notifies netconfigd.
package main

import (
	"encoding/json"
	"flag"
	"io/ioutil"
	"os"
	"os/signal"
	"path/filepath"
	"router7/internal/dhcp6"
	"router7/internal/notify"
	"router7/internal/teelogger"
	"syscall"
	"time"
)

var log = teelogger.NewConsole()

func logic() error {
	const configPath = "/perm/dhcp6/wire/lease.json"
	if err := os.MkdirAll(filepath.Dir(configPath), 0755); err != nil {
		return err
	}

	duid, err := ioutil.ReadFile("/perm/dhcp6/duid")
	if err != nil {
		log.Printf("could not read /perm/dhcp6/duid (%v), proceeding with DUID-LLT")
	}

	c, err := dhcp6.NewClient(dhcp6.ClientConfig{
		InterfaceName: "uplink0",
		DUID:          duid,
	})
	if err != nil {
		return err
	}
	usr2 := make(chan os.Signal, 1)
	signal.Notify(usr2, syscall.SIGUSR2)
	for c.ObtainOrRenew() {
		if err := c.Err(); err != nil {
			log.Printf("Temporary error: %v", err)
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
		if err := notify.Process("/user/netconfigd", syscall.SIGUSR1); err != nil {
			log.Printf("notifying netconfig: %v", err)
		}
		if err := notify.Process("/user/radvd", syscall.SIGUSR1); err != nil {
			log.Printf("notifying radvd: %v", err)
		}
		select {
		case <-time.After(time.Until(c.Config().RenewAfter)):
			// fallthrough and renew the DHCP lease
		case <-usr2:
			log.Printf("SIGUSR2 received, sending DHCPRELEASE")
			if _, _, err := c.Release(); err != nil {
				return err
			}
			os.Exit(125) // quit supervision by gokrazy
		}
	}
	return c.Err() // permanent error
}

func main() {
	flag.Parse()
	if err := logic(); err != nil {
		log.Fatal(err)
	}
}
