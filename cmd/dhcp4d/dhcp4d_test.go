// Copyright 2019 Google Inc.
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

package main

import (
	"context"
	"encoding/json"
	"flag"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/rtr7/router7/internal/dhcp4d"
	"golang.org/x/sync/errgroup"
)

const interfacesJson = `
{
    "interfaces": [
        {
            "name": "lo",
            "addr": "192.0.2.1/24"
        }
    ]
}
`

func TestLeaseHandler(t *testing.T) {
	flag.Set("interface", "lo")
	ctx, canc := context.WithCancel(context.Background())
	defer canc()
	tmp, err := ioutil.TempDir("", "dhcp4dtest")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmp)
	if err := ioutil.WriteFile(filepath.Join(tmp, "interfaces.json"), []byte(interfacesJson), 0644); err != nil {
		t.Fatal(err)
	}
	srv, err := newSrv(tmp)
	if err != nil {
		t.Fatal(err)
	}
	var eg errgroup.Group
	eg.Go(func() error { return srv.run(ctx) })
	lease := dhcp4d.Lease{
		Num:          74,
		Addr:         net.ParseIP("10.0.0.76"),
		HardwareAddr: "02:73:53:00:ca:fe",
		Hostname:     "midna",
		Expiry:       time.Now().Add(20 * time.Minute),
	}
	srv.leases([]*dhcp4d.Lease{&lease}, &lease)
	req, err := http.NewRequest("GET", "http://localhost:8067/lease/midna", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := resp.StatusCode, http.StatusOK; got != want {
		b, _ := ioutil.ReadAll(resp.Body)
		t.Fatalf("unexpected HTTP response code: got %v (%s), want %v", resp.Status, strings.TrimSpace(string(b)), want)
	}
	b, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	var got dhcp4d.Lease
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatal(err)
	}
	if diff := cmp.Diff(lease, got); diff != "" {
		t.Fatalf("/lease/midna: unexpected lease: diff (-want +got):\n%s", diff)
	}

	if got, want := resp.Header.Get("X-Lease-Active"), "true"; got != want {
		t.Fatalf("Unexpected X-Lease-Active header: got %q, want %s", got, want)
	}
	lease.Expiry = time.Now().Add(-1 * time.Minute)
	srv.leases([]*dhcp4d.Lease{&lease}, &lease)
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := resp.StatusCode, http.StatusOK; got != want {
		b, _ := ioutil.ReadAll(resp.Body)
		t.Fatalf("unexpected HTTP response code: got %v (%s), want %v", resp.Status, strings.TrimSpace(string(b)), want)
	}
	if got, want := resp.Header.Get("X-Lease-Active"), "false"; got != want {
		t.Fatalf("Unexpected X-Lease-Active header: got %q, want %s", got, want)
	}

	canc()
	if err := eg.Wait(); err != nil && err != context.Canceled {
		t.Fatal(err)
	}
}
