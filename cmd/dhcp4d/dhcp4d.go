// Binary dhcp4d hands out DHCPv4 leases to clients.
package main

import (
	"encoding/json"
	"flag"
	"io/ioutil"
	"os"
	"syscall"

	"router7/internal/dhcp4d"
	"router7/internal/notify"
	"router7/internal/teelogger"

	"github.com/krolaw/dhcp4"
	"github.com/krolaw/dhcp4/conn"
)

var log = teelogger.NewConsole()

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
	return nil
}

func logic() error {
	if err := os.MkdirAll("/perm/dhcp4d", 0755); err != nil {
		return err
	}
	errs := make(chan error)
	handler, err := dhcp4d.NewHandler("/perm")
	if err != nil {
		return err
	}
	if err := loadLeases(handler, "/perm/dhcp4d/leases.json"); err != nil {
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
