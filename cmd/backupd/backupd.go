// Binary backupd provides tarballs of /perm.
package main

import (
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/gokrazy/gokrazy"

	"router7/internal/backup"
	"router7/internal/multilisten"
	"router7/internal/teelogger"
)

var log = teelogger.NewConsole()

var httpListeners = multilisten.NewPool()

func updateListeners() error {
	hosts, err := gokrazy.PrivateInterfaceAddrs()
	if err != nil {
		return err
	}

	httpListeners.ListenAndServe(hosts, func(host string) multilisten.Listener {
		return &http.Server{Addr: net.JoinHostPort(host, "8077")}
	})
	return nil
}

func logic() error {
	http.HandleFunc("/backup.tar.gz", func(w http.ResponseWriter, r *http.Request) {
		if err := backup.Archive(w, "/perm"); err != nil {
			log.Printf("backup.tar.gz: %v", err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	})
	updateListeners()
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGUSR1)
	for range ch {
		if err := updateListeners(); err != nil {
			log.Printf("updateListeners: %v", err)
		}
	}
	return nil
}

func main() {
	if err := logic(); err != nil {
		log.Fatal(err)
	}
}
