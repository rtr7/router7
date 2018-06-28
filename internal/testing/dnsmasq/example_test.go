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

package dnsmasq_test

import (
	"router7/internal/testing/dnsmasq"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func Example(t *testing.T) {
	dnsmasq := dnsmasq.Run(t, "veth0b", "ns0")
	defer dnsmasq.Kill()
	// test code here

	// optionally introspect the dnsmasq log:
	dnsmasq.Kill()
	got := dnsmasq.Actions()
	want := []string{
		"DHCPDISCOVER(veth0b)",
		"DHCPOFFER(veth0b)",
		"DHCPREQUEST(veth0b)",
		"DHCPACK(veth0b)",
		"DHCPRELEASE(veth0b)",
	}
	actionOnly := func(line string) string {
		result := line
		if idx := strings.Index(result, " "); idx > -1 {
			return result[:idx]
		}
		return result
	}
	if diff := cmp.Diff(got, want, cmp.Transformer("ActionOnly", actionOnly)); diff != "" {
		t.Errorf("dnsmasq log does not contain expected DHCP sequence: diff (-got +want):\n%s", diff)
	}
}
