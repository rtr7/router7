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

// Binary dyndns updates configured DNS records with the
// current public IPv4 address (of network interface uplink0).
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"os"
	"time"

	"github.com/gokrazy/gokrazy"
	"github.com/libdns/cloudflare"
	"github.com/libdns/libdns"
	"github.com/rtr7/router7/internal/dyndns"
)

var update = dyndns.Update

type DynDNSRecord struct {
	// TODO: multiple providers support
	Cloudflare struct {
		APIToken string `json:"api_token"`
	} `json:"cloudflare"`
	Zone       string `json:"zone"`
	RecordName string `json:"record_name"`
	// TODO: make RecordType customizable if non-A is ever desired
	RecordTTLSeconds int `json:"record_ttl_seconds"`
}

func getIPv4Address(ifname string) (string, error) {
	iface, err := net.InterfaceByName(ifname)
	if err != nil {
		return "", err
	}
	addrs, err := iface.Addrs()
	if err != nil {
		return "", err
	}
	for _, a := range addrs {
		ipnet, ok := a.(*net.IPNet)
		if !ok {
			continue
		}
		if ipnet.IP.To4() == nil {
			continue // not IPv4
		}
		return ipnet.IP.String(), nil
	}
	return "", fmt.Errorf("no IPv4 address found on interface %s", ifname)
}

func logic(ifname string, records []DynDNSRecord) error {
	if len(records) == 0 {
		return nil // exit early
	}

	addr, err := getIPv4Address(ifname)
	if err != nil {
		return err
	}

	for _, r := range records {
		apiToken := r.Cloudflare.APIToken
		if t, ok := os.LookupEnv("ROUTER7_CLOUDFLARE_API_KEY"); ok {
			apiToken = t
		}
		provider := &cloudflare.Provider{
			APIToken: apiToken,
		}

		ctx := context.Background()
		record := libdns.Record{
			Name:  r.RecordName,
			Type:  "A",
			Value: addr,
			TTL:   time.Duration(r.RecordTTLSeconds) * time.Second,
		}
		if err := update(ctx, r.Zone, record, provider); err != nil {
			return err
		}
	}
	return nil
}

func main() {
	var (
		configFile = flag.String(
			"config_file",
			"/perm/dyndns.json",
			"Path to the JSON configuration",
		)

		ifname = flag.String(
			"interface_name",
			"uplink0",
			"Network interface name to take the first IPv4 address from",
		)

		oneoff = flag.Bool(
			"oneoff",
			false,
			"run once (as opposed to continuously, in a loop)",
		)
	)
	flag.Parse()
	var config struct {
		Records []DynDNSRecord `json:"records"`
	}
	b, err := ioutil.ReadFile(*configFile)
	if err != nil {
		if os.IsNotExist(err) {
			gokrazy.DontStartOnBoot()
		}
		log.Fatal(err)
	}
	if err := json.Unmarshal(b, &config); err != nil {
		log.Fatal(err)
	}
	for {
		if err := logic(*ifname, config.Records); err != nil {
			log.Fatal(err)
		}
		if *oneoff {
			break
		}
		time.Sleep(1 * time.Minute)
	}
}
