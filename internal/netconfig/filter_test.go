// Copyright 2026 The router7 Authors
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

package netconfig

import (
	"bytes"
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/nftables"
	"github.com/google/nftables/binaryutil"
	"github.com/google/nftables/expr"
	"golang.org/x/sys/unix"
)

func TestParseRuleString(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    InputFilterRule
		wantErr bool
	}{
		{
			name:  "issue 91 example with command prefix",
			input: "root# nft add rule ip6 filter input position 7 udp dport 53 ip6 saddr != 2a0a:c980::53 drop",
			want: InputFilterRule{
				Family:       "ip6",
				Proto:        "udp",
				Port:         "53",
				Source:       "2a0a:c980::53",
				InvertSource: true,
				Action:       "drop",
			},
		},
		{
			name:  "udp dport with != saddr",
			input: "udp dport 53 ip6 saddr != 2a0a:c980::53 drop",
			want: InputFilterRule{
				Family:       "ip6",
				Proto:        "udp",
				Port:         "53",
				Source:       "2a0a:c980::53",
				InvertSource: true,
				Action:       "drop",
			},
		},
		{
			name:  "tcp with interface and accept",
			input: "iifname \"uplink0\" tcp dport 80 ip saddr 192.168.1.100 accept",
			want: InputFilterRule{
				Family:  "ip4",
				Proto:   "tcp",
				Port:    "80",
				Source:  "192.168.1.100",
				IIFName: "uplink0",
				Action:  "accept",
			},
		},
		{
			name:  "sport and dport with reject",
			input: "udp sport 1234 dport 53 reject",
			want: InputFilterRule{
				Proto:  "udp",
				SPort:  "1234",
				Port:   "53",
				Action: "reject",
			},
		},
		{
			name:  "daddr with inversion prefix",
			input: "ip daddr != 10.0.0.1 drop",
			want: InputFilterRule{
				Family:     "ip4",
				Dest:       "10.0.0.1",
				InvertDest: true,
				Action:     "drop",
			},
		},
		{
			name:    "dport missing argument",
			input:   "udp dport",
			wantErr: true,
		},
		{
			name:    "saddr missing argument",
			input:   "udp saddr",
			wantErr: true,
		},
		{
			name:    "saddr != missing argument",
			input:   "udp saddr !=",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseRuleString(tt.input)
			if (err != nil) != tt.wantErr {
				t.Fatalf("ParseRuleString(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
			}
			if !tt.wantErr {
				if got.Family != tt.want.Family {
					t.Errorf("Family: got %q, want %q", got.Family, tt.want.Family)
				}
				if got.Proto != tt.want.Proto {
					t.Errorf("Proto: got %q, want %q", got.Proto, tt.want.Proto)
				}
				if got.Port != tt.want.Port {
					t.Errorf("Port: got %q, want %q", got.Port, tt.want.Port)
				}
				if got.SPort != tt.want.SPort {
					t.Errorf("SPort: got %q, want %q", got.SPort, tt.want.SPort)
				}
				if got.Source != tt.want.Source {
					t.Errorf("Source: got %q, want %q", got.Source, tt.want.Source)
				}
				if got.InvertSource != tt.want.InvertSource {
					t.Errorf("InvertSource: got %v, want %v", got.InvertSource, tt.want.InvertSource)
				}
				if got.Dest != tt.want.Dest {
					t.Errorf("Dest: got %q, want %q", got.Dest, tt.want.Dest)
				}
				if got.InvertDest != tt.want.InvertDest {
					t.Errorf("InvertDest: got %v, want %v", got.InvertDest, tt.want.InvertDest)
				}
				if got.IIFName != tt.want.IIFName {
					t.Errorf("IIFName: got %q, want %q", got.IIFName, tt.want.IIFName)
				}
				if got.Action != tt.want.Action {
					t.Errorf("Action: got %q, want %q", got.Action, tt.want.Action)
				}
			}
		})
	}
}

func TestParseInputFilterConfig(t *testing.T) {
	t.Run("input_filter_rules key", func(t *testing.T) {
		raw := []byte(`{
			"input_filter_rules": [
				{
					"proto": "udp",
					"port": 53,
					"saddr": "!= 2a0a:c980::53",
					"action": "drop"
				}
			]
		}`)
		rules, err := parseInputFilterConfig(raw)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(rules) != 1 {
			t.Fatalf("got %d rules, want 1", len(rules))
		}
		r := rules[0]
		if r.Proto != "udp" || r.Port != "53" || r.SAddr != "!= 2a0a:c980::53" || r.Action != "drop" {
			t.Errorf("unexpected parsed rule: %+v", r)
		}
	})

	t.Run("rules key with string rule", func(t *testing.T) {
		raw := []byte(`{
			"rules": [
				"udp dport 53 ip6 saddr != 2a0a:c980::53 drop"
			]
		}`)
		rules, err := parseInputFilterConfig(raw)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(rules) != 1 {
			t.Fatalf("got %d rules, want 1", len(rules))
		}
		r := rules[0]
		if r.Proto != "udp" || r.Port != "53" || r.Source != "2a0a:c980::53" || !r.InvertSource {
			t.Errorf("unexpected parsed rule: %+v", r)
		}
	})

	t.Run("top level array of objects", func(t *testing.T) {
		raw := []byte(`[
			{
				"proto": "tcp",
				"port": "8080",
				"source": "192.168.1.1",
				"action": "accept"
			}
		]`)
		rules, err := parseInputFilterConfig(raw)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(rules) != 1 {
			t.Fatalf("got %d rules, want 1", len(rules))
		}
		r := rules[0]
		if r.Proto != "tcp" || r.Port != "8080" || r.Source != "192.168.1.1" || r.Action != "accept" {
			t.Errorf("unexpected parsed rule: %+v", r)
		}
	})

	t.Run("single object", func(t *testing.T) {
		raw := []byte(`{
			"proto": "icmp",
			"action": "accept"
		}`)
		rules, err := parseInputFilterConfig(raw)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(rules) != 1 {
			t.Fatalf("got %d rules, want 1", len(rules))
		}
		if rules[0].Proto != "icmp" {
			t.Errorf("got %q, want icmp", rules[0].Proto)
		}
	})
}

func TestBuildInputFilterRule_Issue91(t *testing.T) {
	rule := InputFilterRule{
		Proto:        "udp",
		Port:         "53",
		Source:       "2a0a:c980::53",
		InvertSource: true,
		Action:       "drop",
	}

	// Should not match IPv4 filter table
	exprs4, match4, err := buildInputFilterRule(rule, nftables.TableFamilyIPv4)
	if err != nil {
		t.Fatalf("buildInputFilterRule(IPv4) error: %v", err)
	}
	if match4 {
		t.Errorf("IPv6 rule should not match IPv4 filter table")
	}
	if len(exprs4) != 0 {
		t.Errorf("expected 0 rules for IPv4, got %d", len(exprs4))
	}

	// Should match IPv6 filter table
	exprs6, match6, err := buildInputFilterRule(rule, nftables.TableFamilyIPv6)
	if err != nil {
		t.Fatalf("buildInputFilterRule(IPv6) error: %v", err)
	}
	if !match6 {
		t.Fatalf("IPv6 rule should match IPv6 filter table")
	}
	if len(exprs6) != 1 {
		t.Fatalf("expected 1 rule for IPv6, got %d", len(exprs6))
	}

	ruleExprs := exprs6[0]

	// Expected expressions:
	// 1. MetaKeyL4PROTO == unix.IPPROTO_UDP
	// 2. Transport Header Offset 2 Len 2 (dport) == 53
	// 3. Network Header Offset 8 Len 16 (saddr) != 2a0a:c980::53
	// 4. VerdictDrop
	var foundProto, foundDPort, foundSAddr, foundVerdict bool
	wantIP := net.ParseIP("2a0a:c980::53").To16()

	for _, e := range ruleExprs {
		switch ex := e.(type) {
		case *expr.Cmp:
			if ex.Op == expr.CmpOpEq && len(ex.Data) == 1 && ex.Data[0] == unix.IPPROTO_UDP {
				foundProto = true
			}
			if ex.Op == expr.CmpOpEq && len(ex.Data) == 2 && bytes.Equal(ex.Data, binaryutil.BigEndian.PutUint16(53)) {
				foundDPort = true
			}
			if ex.Op == expr.CmpOpNeq && len(ex.Data) == 16 && bytes.Equal(ex.Data, wantIP) {
				foundSAddr = true
			}
		case *expr.Verdict:
			if ex.Kind == expr.VerdictDrop {
				foundVerdict = true
			}
		}
	}

	if !foundProto {
		t.Errorf("l4proto udp check not found in expressions")
	}
	if !foundDPort {
		t.Errorf("dport 53 check not found in expressions")
	}
	if !foundSAddr {
		t.Errorf("saddr != 2a0a:c980::53 check not found in expressions")
	}
	if !foundVerdict {
		t.Errorf("drop verdict not found in expressions")
	}
}

func TestBuildInputFilterRule_IPv4(t *testing.T) {
	rule := InputFilterRule{
		Family:  "ipv4",
		Proto:   "tcp",
		Port:    "80",
		Source:  "192.168.1.100",
		IIFName: "uplink0",
		Action:  "accept",
	}

	// Should not match IPv6
	_, match6, err := buildInputFilterRule(rule, nftables.TableFamilyIPv6)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if match6 {
		t.Errorf("IPv4 rule matched IPv6 table")
	}

	// Should match IPv4
	exprs, match4, err := buildInputFilterRule(rule, nftables.TableFamilyIPv4)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !match4 {
		t.Fatalf("IPv4 rule did not match IPv4 table")
	}
	if len(exprs) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(exprs))
	}

	wantIP := net.ParseIP("192.168.1.100").To4()
	var foundIIFName, foundProto, foundPort, foundIP, foundVerdict bool

	for _, e := range exprs[0] {
		switch ex := e.(type) {
		case *expr.Cmp:
			if ex.Op == expr.CmpOpEq && bytes.Equal(ex.Data, nfifname("uplink0")) {
				foundIIFName = true
			}
			if ex.Op == expr.CmpOpEq && len(ex.Data) == 1 && ex.Data[0] == unix.IPPROTO_TCP {
				foundProto = true
			}
			if ex.Op == expr.CmpOpEq && bytes.Equal(ex.Data, binaryutil.BigEndian.PutUint16(80)) {
				foundPort = true
			}
			if ex.Op == expr.CmpOpEq && bytes.Equal(ex.Data, wantIP) {
				foundIP = true
			}
		case *expr.Verdict:
			if ex.Kind == expr.VerdictAccept {
				foundVerdict = true
			}
		}
	}

	if !foundIIFName || !foundProto || !foundPort || !foundIP || !foundVerdict {
		t.Errorf("expression check failed: iif=%v proto=%v port=%v ip=%v verdict=%v",
			foundIIFName, foundProto, foundPort, foundIP, foundVerdict)
	}
}

func TestBuildInputFilterRule_CIDR(t *testing.T) {
	rule := InputFilterRule{
		Proto:        "tcp",
		Port:         "443",
		Source:       "10.0.0.0/8",
		InvertSource: true,
		Action:       "drop",
	}

	exprs, match, err := buildInputFilterRule(rule, nftables.TableFamilyIPv4)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !match {
		t.Fatalf("expected rule to match IPv4 table")
	}

	var foundBitwise, foundNeq bool
	wantMask := []byte{0xff, 0x00, 0x00, 0x00}
	wantNet := []byte{10, 0, 0, 0}

	for _, e := range exprs[0] {
		switch ex := e.(type) {
		case *expr.Bitwise:
			if bytes.Equal(ex.Mask, wantMask) {
				foundBitwise = true
			}
		case *expr.Cmp:
			if ex.Op == expr.CmpOpNeq && bytes.Equal(ex.Data, wantNet) {
				foundNeq = true
			}
		}
	}

	if !foundBitwise {
		t.Errorf("bitwise mask for 10.0.0.0/8 not found")
	}
	if !foundNeq {
		t.Errorf("cmp neq for 10.0.0.0 not found")
	}
}

func TestBuildInputFilterRule_PortRange(t *testing.T) {
	rule := InputFilterRule{
		Family: "ip4",
		Proto:  "tcp",
		Port:   "8000-8080",
		Action: "drop",
	}

	exprs, match, err := buildInputFilterRule(rule, nftables.TableFamilyIPv4)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !match {
		t.Fatalf("expected rule to match IPv4 table")
	}

	var foundGte, foundLte bool
	for _, e := range exprs[0] {
		if cmp, ok := e.(*expr.Cmp); ok {
			if cmp.Op == expr.CmpOpGte && bytes.Equal(cmp.Data, binaryutil.BigEndian.PutUint16(8000)) {
				foundGte = true
			}
			if cmp.Op == expr.CmpOpLte && bytes.Equal(cmp.Data, binaryutil.BigEndian.PutUint16(8080)) {
				foundLte = true
			}
		}
	}

	if !foundGte || !foundLte {
		t.Errorf("expected Gte and Lte port checks, got gte=%v lte=%v", foundGte, foundLte)
	}
}

func TestBuildInputFilterRule_MultiProto(t *testing.T) {
	rule := InputFilterRule{
		Family: "ip4",
		Proto:  "tcp,udp",
		Port:   "53",
		Action: "accept",
	}

	exprs, match, err := buildInputFilterRule(rule, nftables.TableFamilyIPv4)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !match {
		t.Fatalf("expected rule to match IPv4 table")
	}
	if len(exprs) != 2 {
		t.Fatalf("expected 2 rules for multi proto, got %d", len(exprs))
	}
}

func TestBuildInputFilterRule_Errors(t *testing.T) {
	tests := []struct {
		name string
		rule InputFilterRule
	}{
		{
			name: "invalid family",
			rule: InputFilterRule{Family: "ip99"},
		},
		{
			name: "invalid protocol",
			rule: InputFilterRule{Proto: "sctp"},
		},
		{
			name: "invalid port",
			rule: InputFilterRule{Port: "999999"},
		},
		{
			name: "invalid source IP",
			rule: InputFilterRule{Source: "not-an-ip"},
		},
		{
			name: "invalid action",
			rule: InputFilterRule{Action: "mangle"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, err := buildInputFilterRule(tt.rule, nftables.TableFamilyIPv4)
			if err == nil {
				t.Fatalf("expected error for %s, got nil", tt.name)
			}
		})
	}
}

func TestLoadInputFilterRules(t *testing.T) {
	tmp, err := os.MkdirTemp("", "filtertest-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmp)

	// Non-existent directory returns nil, nil
	rules, err := loadInputFilterRules(filepath.Join(tmp, "nonexistent"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(rules) != 0 {
		t.Errorf("expected 0 rules, got %d", len(rules))
	}

	// Writing config.json
	cfgContent := `{
		"input_filter_rules": [
			{
				"proto": "udp",
				"port": "53",
				"source": "!= 2a0a:c980::53",
				"action": "drop"
			}
		]
	}`
	if err := os.WriteFile(filepath.Join(tmp, "config.json"), []byte(cfgContent), 0644); err != nil {
		t.Fatal(err)
	}

	rules, err = loadInputFilterRules(tmp)
	if err != nil {
		t.Fatalf("unexpected error loading config.json: %v", err)
	}
	if len(rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(rules))
	}
	if rules[0].Proto != "udp" || rules[0].Port != "53" {
		t.Errorf("unexpected rule: %+v", rules[0])
	}

	// Remove config.json and test fallback to inputfilter.json
	os.Remove(filepath.Join(tmp, "config.json"))
	if err := os.WriteFile(filepath.Join(tmp, "inputfilter.json"), []byte(cfgContent), 0644); err != nil {
		t.Fatal(err)
	}
	rules, err = loadInputFilterRules(tmp)
	if err != nil {
		t.Fatalf("unexpected error loading inputfilter.json: %v", err)
	}
	if len(rules) != 1 {
		t.Fatalf("expected 1 rule from inputfilter.json, got %d", len(rules))
	}
}

func TestInputFilterRule_UnmarshalJSON(t *testing.T) {
	t.Run("port as integer", func(t *testing.T) {
		raw := []byte(`{"proto": "udp", "port": 53, "action": "drop"}`)
		var r InputFilterRule
		if err := r.UnmarshalJSON(raw); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if r.Port != "53" {
			t.Errorf("expected Port 53, got %q", r.Port)
		}
	})

	t.Run("plain string rule", func(t *testing.T) {
		raw := []byte(`"udp dport 53 ip6 saddr != 2a0a:c980::53 drop"`)
		var r InputFilterRule
		if err := r.UnmarshalJSON(raw); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if r.Proto != "udp" || r.Port != "53" || r.Source != "2a0a:c980::53" || !r.InvertSource {
			t.Errorf("unexpected parsed rule: %+v", r)
		}
	})
}
