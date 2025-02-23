// Copyright 2018 Google Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Binary backupd provides tarballs of /perm.
package main

import (
	"context"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/gokrazy/gokrazy"
	"github.com/gokrazy/rsync/rsyncd"

	"github.com/rtr7/router7/internal/backup"
	"github.com/rtr7/router7/internal/multilisten"
	"github.com/rtr7/router7/internal/teelogger"
)

var log = teelogger.NewConsole()

var httpListeners = multilisten.NewPool()

var rsyncListeners = multilisten.NewPool()

type rsyncListener struct {
	addr     string
	listener net.Listener
	cancel   context.CancelFunc
}

func (r *rsyncListener) ListenAndServe() error {
	ln, err := net.Listen("tcp", r.addr)
	if err != nil {
		return err
	}
	r.listener = ln
	ctx, cancel := context.WithCancel(context.Background())
	r.cancel = cancel
	rsyncServer, err := rsyncd.NewServer([]rsyncd.Module{
		{
			Name: "perm",
			Path: "/perm",
		},
	})
	if err != nil {
		return err
	}

	go func() {
		if err := rsyncServer.Serve(ctx, ln); err != nil {
			log.Print(err)
		}
	}()

	return nil
}

func (r *rsyncListener) Close() error {
	if r.cancel != nil {
		r.cancel()
		r.cancel = nil
		r.listener.Close()
		r.listener = nil
	}
	return nil
}

func updateListeners() error {
	hosts, err := gokrazy.PrivateInterfaceAddrs()
	if err != nil {
		return err
	}

	httpListeners.ListenAndServe(hosts, func(host string) multilisten.Listener {
		return &http.Server{Addr: net.JoinHostPort(host, "8077")}
	})

	rsyncListeners.ListenAndServe(hosts, func(host string) multilisten.Listener {
		return &rsyncListener{addr: net.JoinHostPort(host, "8873")} // unprivileged rsync
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
