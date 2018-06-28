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

package integration_test

import (
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"

	"router7/internal/dns"

	miekgdns "github.com/miekg/dns"
)

func TestDNS(t *testing.T) {
	srv := dns.NewServer("localhost:4453", "lan")
	s := &miekgdns.Server{Addr: "localhost:4453", Net: "udp", Handler: srv.Mux}
	go s.ListenAndServe()
	const port = 4453
	dig := exec.Command("dig", "-p", strconv.Itoa(port), "+timeout=1", "+short", "-x", "8.8.8.8", "@127.0.0.1")
	dig.Stderr = os.Stderr
	out, err := dig.Output()
	if err != nil {
		t.Fatal(err)
	}
	if got, want := strings.TrimSpace(string(out)), "google-public-dns-a.google.com."; got != want {
		t.Fatalf("dig -x 8.8.8.8: unexpected reply: got %q, want %q", got, want)
	}
}
