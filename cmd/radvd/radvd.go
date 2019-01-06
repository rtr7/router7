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

// Binary radvd sends IPv6 router advertisments.
package main

import (
	"encoding/json"
	"flag"
	"io/ioutil"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/rtr7/router7/internal/dhcp6"
	"github.com/rtr7/router7/internal/radvd"
)

func logic() error {
	srv, err := radvd.NewServer()
	if err != nil {
		return err
	}
	readConfig := func() error {
		b, err := ioutil.ReadFile("/perm/dhcp6/wire/lease.json")
		if err != nil {
			return err
		}
		var cfg dhcp6.Config
		if err := json.Unmarshal(b, &cfg); err != nil {
			return err
		}

		var additional []net.IPNet
		if b, err := ioutil.ReadFile("/perm/radvd/prefixes.json"); err == nil {
			if err := json.Unmarshal(b, &additional); err != nil {
				return err
			}
		}

		srv.SetPrefixes(append(cfg.Prefixes, additional...))
		return nil
	}
	if err := readConfig(); err != nil {
		log.Printf("cannot announce IPv6 prefixes: %v", err)
	}
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGUSR1)
	go func() {
		for range ch {
			if err := readConfig(); err != nil {
				log.Printf("readConfig: %v", err)
			}
		}
	}()
	return srv.ListenAndServe("lan0")
}

func main() {
	// TODO: drop privileges, run as separate uid?
	flag.Parse()
	if err := logic(); err != nil {
		log.Fatal(err)
	}
}
