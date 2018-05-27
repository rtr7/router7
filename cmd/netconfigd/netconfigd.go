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
		if err := netconfig.Apply("uplink0", "/perm/"); err != nil {
			return err
		}
		if *linger {
			<-ch
		}
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
