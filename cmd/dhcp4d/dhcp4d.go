// Binary dhcp4d hands out DHCPv4 leases to clients.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"syscall"

	"router7/internal/dhcp4d"
	"router7/internal/notify"

	"github.com/krolaw/dhcp4"
	"github.com/krolaw/dhcp4/conn"
)

func logic() error {
	if err := os.MkdirAll("/perm/dhcp4d", 0755); err != nil {
		return err
	}
	errs := make(chan error)
	handler, err := dhcp4d.NewHandler("/perm")
	if err != nil {
		return err
	}
	handler.Leases = func(leases []*dhcp4d.Lease) {
		b, err := json.Marshal(leases)
		if err != nil {
			errs <- err
			return
		}
		// TODO: write atomically
		if err := ioutil.WriteFile("/perm/dhcp4d/leases.json", b, 0644); err != nil {
			errs <- err
		}
		if err := notify.Process("/user/dnsd", syscall.SIGUSR1); err != nil {
			log.Printf("notifying dnsd: %v", err)
			ioutil.WriteFile("/dev/console", []byte(fmt.Sprintf("notifying dnsd: %+v\n", err)), 0600)
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
