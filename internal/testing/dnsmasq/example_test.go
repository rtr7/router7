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
