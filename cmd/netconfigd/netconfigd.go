// Binary netconfigd reads state from dhcp4, dhcp6, … and applies it.
package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"os/signal"
	"syscall"

	"router7/internal/netconfig"
)

var (
	linger = flag.Bool("linger", true, "linger around after applying the configuration (until killed)")
)

func logic() error {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGUSR1)
	for {
		err := netconfig.Apply("uplink0", "/perm/")
		// Notify gokrazy about new addresses (netconfig.Apply might have
		// modified state before returning an error) so that listeners can be
		// updated.
		p, _ := os.FindProcess(1)
		if err := p.Signal(syscall.SIGHUP); err != nil {
			log.Printf("kill -HUP 1: %v", err)
		}
		if err != nil {
			return err
		}
		if !*linger {
			break
		}
		<-ch
	}
	return nil
}

func main() {
	flag.Parse()
	if err := logic(); err != nil {
		// TODO: use a logger which writes to /dev/console
		ioutil.WriteFile("/dev/console", []byte(fmt.Sprintf("netconfig: %v\n", err)), 0600)
		log.Fatal(err)
	}
}
