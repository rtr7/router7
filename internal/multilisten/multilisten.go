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

// Package multilisten implements listening on multiple addresses at once.
package multilisten

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"path/filepath"
	"router7/internal/dhcp6"
	"sync"
)

type Listener interface {
	ListenAndServe() error
	Close() error
}

type Pool struct {
	mu        sync.Mutex
	listeners map[string]Listener
}

func NewPool() *Pool {
	return &Pool{
		listeners: make(map[string]Listener),
	}
}

func (p *Pool) ListenAndServe(hosts []string, listenerFor func(host string) Listener) {
	p.mu.Lock()
	defer p.mu.Unlock()
	vanished := make(map[string]bool)
	for host := range p.listeners {
		vanished[host] = false
	}
	for _, host := range hosts {
		if _, ok := p.listeners[host]; ok {
			// confirm found
			delete(vanished, host)
		} else {
			log.Printf("now listening on %s", host)
			// add a new listener
			ln := listenerFor(host)
			p.listeners[host] = ln
			go func(host string, ln Listener) {
				err := ln.ListenAndServe()
				log.Printf("listener for %q died: %v", host, err)
				p.mu.Lock()
				defer p.mu.Unlock()
				delete(p.listeners, host)
			}(host, ln)
		}
	}
	for host := range vanished {
		log.Printf("no longer listening on %s", host)
		p.listeners[host].Close()
		delete(p.listeners, host)
	}
}

// IPv6Net1 returns the IP address which router7 picks from the IPv6 prefix for
// itself, e.g. address 2a02:168:4a00::1 for prefix 2a02:168:4a00::/48.
func IPv6Net1(dir string) (string, error) {
	b, err := ioutil.ReadFile(filepath.Join(dir, "dhcp6/wire/lease.json"))
	if err != nil {
		return "", err
	}
	var got dhcp6.Config
	if err := json.Unmarshal(b, &got); err != nil {
		return "", err
	}

	for _, prefix := range got.Prefixes {
		// pick the first address of the prefix, e.g. address 2a02:168:4a00::1
		// for prefix 2a02:168:4a00::/48
		prefix.IP[len(prefix.IP)-1] = 1
		return prefix.IP.String(), nil
	}
	return "", fmt.Errorf("no DHCPv6 prefix obtained")
}
