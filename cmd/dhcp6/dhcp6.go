// Binary dhcp6 obtains a DHCPv6 lease, persists it to
// /perm/dhcp6/wire/lease.json and notifies netconfigd.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"router7/internal/dhcp6"
	"router7/internal/notify"
	"syscall"
	"time"
)

func logic() error {
	const configPath = "/perm/dhcp6/wire/lease.json"
	if err := os.MkdirAll(filepath.Dir(configPath), 0755); err != nil {
		return err
	}

	c, err := dhcp6.NewClient(dhcp6.ClientConfig{
		InterfaceName: "uplink0",
	})
	if err != nil {
		return err
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
	flag.Parse()
	if err := logic(); err != nil {
		log.Fatal(err)
	}
}
