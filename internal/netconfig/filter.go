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
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/google/nftables"
	"github.com/google/nftables/binaryutil"
	"github.com/google/nftables/expr"
	"golang.org/x/sys/unix"
)

// InputFilterRule represents a custom firewall rule applied to the input filter chain.
type InputFilterRule struct {
	Family       string `json:"family,omitempty"`        // "ip", "ip4", "ipv4", "ip6", "ipv6", or "" (auto)
	Proto        string `json:"proto,omitempty"`         // "udp", "tcp", "icmp", "icmpv6"
	Port         string `json:"port,omitempty"`          // destination port or port range, e.g. "53", "8040-8060"
	DPort        string `json:"dport,omitempty"`         // alias for port
	SPort        string `json:"sport,omitempty"`         // source port or port range
	Source       string `json:"source,omitempty"`        // source IP or CIDR, e.g. "2a0a:c980::53", "192.168.1.0/24"
	SAddr        string `json:"saddr,omitempty"`         // alias for source, supports "!=" or "!" prefix
	Dest         string `json:"dest,omitempty"`          // destination IP or CIDR
	DAddr        string `json:"daddr,omitempty"`         // alias for dest
	InvertSource bool   `json:"invert_source,omitempty"` // true to invert source match (!=)
	InvertDest   bool   `json:"invert_dest,omitempty"`   // true to invert destination match (!=)
	IIFName      string `json:"iifname,omitempty"`       // incoming interface name, e.g. "uplink0"
	Action       string `json:"action,omitempty"`        // "drop", "accept", "reject" (default "drop")
	Rule         string `json:"rule,omitempty"`          // raw rule string, e.g. "udp dport 53 ip6 saddr != 2a0a:c980::53 drop"
}

// UnmarshalJSON unmarshals an InputFilterRule from either a JSON object or string.
func (r *InputFilterRule) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err == nil {
		parsed, err := ParseRuleString(s)
		if err != nil {
			return err
		}
		*r = parsed
		return nil
	}

	type alias InputFilterRule
	var raw struct {
		alias
		PortAny  interface{} `json:"port"`
		DPortAny interface{} `json:"dport"`
		SPortAny interface{} `json:"sport"`
	}
	if err := json.Unmarshal(b, &raw); err != nil {
		return err
	}
	*r = InputFilterRule(raw.alias)
	if raw.PortAny != nil {
		r.Port = parsePortAny(raw.PortAny)
	}
	if raw.DPortAny != nil {
		r.DPort = parsePortAny(raw.DPortAny)
	}
	if raw.SPortAny != nil {
		r.SPort = parsePortAny(raw.SPortAny)
	}

	if r.Rule != "" {
		parsed, err := ParseRuleString(r.Rule)
		if err != nil {
			return err
		}
		if r.Family == "" {
			r.Family = parsed.Family
		}
		if r.Proto == "" {
			r.Proto = parsed.Proto
		}
		if r.Port == "" {
			r.Port = parsed.Port
		}
		if r.DPort == "" {
			r.DPort = parsed.DPort
		}
		if r.SPort == "" {
			r.SPort = parsed.SPort
		}
		if r.Source == "" && r.SAddr == "" {
			r.Source = parsed.Source
			r.InvertSource = parsed.InvertSource
		}
		if r.Dest == "" && r.DAddr == "" {
			r.Dest = parsed.Dest
			r.InvertDest = parsed.InvertDest
		}
		if r.IIFName == "" {
			r.IIFName = parsed.IIFName
		}
		if r.Action == "" {
			r.Action = parsed.Action
		}
	}
	return nil
}

// ParseRuleString parses an nftables input rule specification string into an InputFilterRule.
func ParseRuleString(s string) (InputFilterRule, error) {
	var r InputFilterRule
	tokens := strings.Fields(s)
	for i := 0; i < len(tokens); i++ {
		tok := tokens[i]
		switch strings.ToLower(tok) {
		case "root#", "nft", "add", "rule", "filter", "input":
			continue
		case "position":
			if i+1 < len(tokens) {
				i++
			}
			continue
		case "ip", "ipv4":
			r.Family = "ip4"
		case "ip6", "ipv6":
			r.Family = "ip6"
		case "tcp", "udp", "icmp", "icmpv6":
			r.Proto = strings.ToLower(tok)
		case "dport":
			if i+1 >= len(tokens) {
				return r, fmt.Errorf("dport missing value in %q", s)
			}
			i++
			r.Port = tokens[i]
		case "sport":
			if i+1 >= len(tokens) {
				return r, fmt.Errorf("sport missing value in %q", s)
			}
			i++
			r.SPort = tokens[i]
		case "saddr":
			if i+1 >= len(tokens) {
				return r, fmt.Errorf("saddr missing value in %q", s)
			}
			i++
			if tokens[i] == "!=" {
				r.InvertSource = true
				if i+1 >= len(tokens) {
					return r, fmt.Errorf("saddr != missing value in %q", s)
				}
				i++
				r.Source = tokens[i]
			} else if tokens[i] == "!" {
				r.InvertSource = true
				if i+1 >= len(tokens) {
					return r, fmt.Errorf("saddr ! missing value in %q", s)
				}
				i++
				r.Source = tokens[i]
			} else if strings.HasPrefix(tokens[i], "!=") {
				r.InvertSource = true
				r.Source = strings.TrimPrefix(tokens[i], "!=")
			} else if strings.HasPrefix(tokens[i], "!") {
				r.InvertSource = true
				r.Source = strings.TrimPrefix(tokens[i], "!")
			} else {
				r.Source = tokens[i]
			}
		case "daddr":
			if i+1 >= len(tokens) {
				return r, fmt.Errorf("daddr missing value in %q", s)
			}
			i++
			if tokens[i] == "!=" {
				r.InvertDest = true
				if i+1 >= len(tokens) {
					return r, fmt.Errorf("daddr != missing value in %q", s)
				}
				i++
				r.Dest = tokens[i]
			} else if tokens[i] == "!" {
				r.InvertDest = true
				if i+1 >= len(tokens) {
					return r, fmt.Errorf("daddr ! missing value in %q", s)
				}
				i++
				r.Dest = tokens[i]
			} else if strings.HasPrefix(tokens[i], "!=") {
				r.InvertDest = true
				r.Dest = strings.TrimPrefix(tokens[i], "!=")
			} else if strings.HasPrefix(tokens[i], "!") {
				r.InvertDest = true
				r.Dest = strings.TrimPrefix(tokens[i], "!")
			} else {
				r.Dest = tokens[i]
			}
		case "iifname":
			if i+1 >= len(tokens) {
				return r, fmt.Errorf("iifname missing value in %q", s)
			}
			i++
			r.IIFName = strings.Trim(tokens[i], `"`)
		case "drop", "accept", "reject":
			r.Action = strings.ToLower(tok)
		}
	}
	return r, nil
}

type inputFilterConfig struct {
	InputFilterRules []InputFilterRule `json:"input_filter_rules"`
	InputFilters     []InputFilterRule `json:"input_filters"`
	FilterRules      []InputFilterRule `json:"filter_rules"`
	Rules            []InputFilterRule `json:"rules"`
	InputRules       []InputFilterRule `json:"input_rules"`
}

func parsePortAny(val interface{}) string {
	if val == nil {
		return ""
	}
	switch v := val.(type) {
	case string:
		return v
	case float64:
		return strconv.Itoa(int(v))
	case int:
		return strconv.Itoa(v)
	case json.Number:
		return v.String()
	default:
		return fmt.Sprintf("%v", v)
	}
}

func (r InputFilterRule) isEmpty() bool {
	return r.Rule == "" && r.Proto == "" && r.Family == "" &&
		r.Port == "" && r.DPort == "" && r.SPort == "" &&
		r.Source == "" && r.SAddr == "" && r.Dest == "" && r.DAddr == "" &&
		r.IIFName == "" && r.Action == ""
}

func parseInputFilterConfig(b []byte) ([]InputFilterRule, error) {
	var cfg inputFilterConfig
	if err := json.Unmarshal(b, &cfg); err == nil {
		if len(cfg.InputFilterRules) > 0 {
			return cfg.InputFilterRules, nil
		}
		if len(cfg.InputFilters) > 0 {
			return cfg.InputFilters, nil
		}
		if len(cfg.FilterRules) > 0 {
			return cfg.FilterRules, nil
		}
		if len(cfg.Rules) > 0 {
			return cfg.Rules, nil
		}
		if len(cfg.InputRules) > 0 {
			return cfg.InputRules, nil
		}
	}

	var rules []InputFilterRule
	if err := json.Unmarshal(b, &rules); err == nil && len(rules) > 0 {
		return rules, nil
	}

	var single InputFilterRule
	if err := json.Unmarshal(b, &single); err == nil && !single.isEmpty() {
		return []InputFilterRule{single}, nil
	}

	return nil, fmt.Errorf("unable to parse input filter rules configuration")
}

func loadInputFilterRules(dir string) ([]InputFilterRule, error) {
	for _, fn := range []string{
		"config.json",
		"inputfilter.json",
		"filterrules.json",
		"input_filter_rules.json",
	} {
		b, err := os.ReadFile(filepath.Join(dir, fn))
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return nil, err
		}
		return parseInputFilterConfig(b)
	}
	return nil, nil
}

func parseIPOrCIDR(s string) (net.IP, *net.IPNet, error) {
	s = strings.TrimSpace(s)
	if strings.Contains(s, "/") {
		ip, ipnet, err := net.ParseCIDR(s)
		if err != nil {
			return nil, nil, err
		}
		return ip, ipnet, nil
	}
	ip := net.ParseIP(s)
	if ip == nil {
		return nil, nil, fmt.Errorf("could not parse IP address %q", s)
	}
	return ip, nil, nil
}

func ipMatchExpr(ip net.IP, ipnet *net.IPNet, invert bool, isSource bool, tableFamily nftables.TableFamily) []expr.Any {
	cmpOp := expr.CmpOpEq
	if invert {
		cmpOp = expr.CmpOpNeq
	}

	if tableFamily == nftables.TableFamilyIPv4 {
		offset := uint32(16) // daddr
		if isSource {
			offset = 12 // saddr
		}
		if ipnet != nil {
			ones, bits := ipnet.Mask.Size()
			if ones < bits {
				return []expr.Any{
					&expr.Payload{
						DestRegister: 1,
						Base:         expr.PayloadBaseNetworkHeader,
						Offset:       offset,
						Len:          4,
					},
					&expr.Bitwise{
						DestRegister:   1,
						SourceRegister: 1,
						Len:            4,
						Mask:           ipnet.Mask,
						Xor:            []byte{0x00, 0x00, 0x00, 0x00},
					},
					&expr.Cmp{
						Op:       cmpOp,
						Register: 1,
						Data:     ip.Mask(ipnet.Mask).To4(),
					},
				}
			}
		}
		return []expr.Any{
			&expr.Payload{
				DestRegister: 1,
				Base:         expr.PayloadBaseNetworkHeader,
				Offset:       offset,
				Len:          4,
			},
			&expr.Cmp{
				Op:       cmpOp,
				Register: 1,
				Data:     ip.To4(),
			},
		}
	}

	// IPv6
	offset := uint32(24) // daddr
	if isSource {
		offset = 8 // saddr
	}
	if ipnet != nil {
		ones, bits := ipnet.Mask.Size()
		if ones < bits {
			zeroXor := make([]byte, 16)
			return []expr.Any{
				&expr.Payload{
					DestRegister: 1,
					Base:         expr.PayloadBaseNetworkHeader,
					Offset:       offset,
					Len:          16,
				},
				&expr.Bitwise{
					DestRegister:   1,
					SourceRegister: 1,
					Len:            16,
					Mask:           ipnet.Mask,
					Xor:            zeroXor,
				},
				&expr.Cmp{
					Op:       cmpOp,
					Register: 1,
					Data:     ip.Mask(ipnet.Mask).To16(),
				},
			}
		}
	}
	return []expr.Any{
		&expr.Payload{
			DestRegister: 1,
			Base:         expr.PayloadBaseNetworkHeader,
			Offset:       offset,
			Len:          16,
		},
		&expr.Cmp{
			Op:       cmpOp,
			Register: 1,
			Data:     ip.To16(),
		},
	}
}

func buildInputFilterRule(r InputFilterRule, tableFamily nftables.TableFamily) ([][]expr.Any, bool, error) {
	portStr := r.Port
	if portStr == "" {
		portStr = r.DPort
	}
	srcStr := r.Source
	if srcStr == "" {
		srcStr = r.SAddr
	}
	destStr := r.Dest
	if destStr == "" {
		destStr = r.DAddr
	}

	invertSource := r.InvertSource
	if strings.HasPrefix(srcStr, "!=") {
		invertSource = true
		srcStr = strings.TrimSpace(strings.TrimPrefix(srcStr, "!="))
	} else if strings.HasPrefix(srcStr, "!") {
		invertSource = true
		srcStr = strings.TrimSpace(strings.TrimPrefix(srcStr, "!"))
	}

	invertDest := r.InvertDest
	if strings.HasPrefix(destStr, "!=") {
		invertDest = true
		destStr = strings.TrimSpace(strings.TrimPrefix(destStr, "!="))
	} else if strings.HasPrefix(destStr, "!") {
		invertDest = true
		destStr = strings.TrimSpace(strings.TrimPrefix(destStr, "!"))
	}

	var ruleFamily nftables.TableFamily
	famLower := strings.ToLower(r.Family)
	switch famLower {
	case "ip", "ip4", "ipv4", "v4":
		ruleFamily = nftables.TableFamilyIPv4
	case "ip6", "ipv6", "v6":
		ruleFamily = nftables.TableFamilyIPv6
	case "", "both", "all":
		if srcStr != "" {
			ip, _, err := parseIPOrCIDR(srcStr)
			if err != nil {
				return nil, false, fmt.Errorf("invalid source %q: %v", srcStr, err)
			}
			if ip.To4() != nil {
				ruleFamily = nftables.TableFamilyIPv4
			} else {
				ruleFamily = nftables.TableFamilyIPv6
			}
		} else if destStr != "" {
			ip, _, err := parseIPOrCIDR(destStr)
			if err != nil {
				return nil, false, fmt.Errorf("invalid dest %q: %v", destStr, err)
			}
			if ip.To4() != nil {
				ruleFamily = nftables.TableFamilyIPv4
			} else {
				ruleFamily = nftables.TableFamilyIPv6
			}
		}
	default:
		return nil, false, fmt.Errorf("unknown family %q", r.Family)
	}

	if ruleFamily != 0 && ruleFamily != tableFamily {
		return nil, false, nil
	}

	var protos []uint8
	if r.Proto == "" {
		protos = []uint8{0}
	} else {
		for _, pStr := range strings.Split(r.Proto, ",") {
			switch strings.ToLower(strings.TrimSpace(pStr)) {
			case "", "all":
				protos = append(protos, 0)
			case "tcp":
				protos = append(protos, unix.IPPROTO_TCP)
			case "udp":
				protos = append(protos, unix.IPPROTO_UDP)
			case "icmp":
				protos = append(protos, unix.IPPROTO_ICMP)
			case "icmpv6", "ipv6-icmp":
				protos = append(protos, unix.IPPROTO_ICMPV6)
			default:
				return nil, false, fmt.Errorf("unknown proto %q", pStr)
			}
		}
	}

	var dmin, dmax uint16
	if portStr != "" {
		var err error
		dmin, dmax, err = parsePort(portStr)
		if err != nil {
			return nil, false, fmt.Errorf("invalid port %q: %v", portStr, err)
		}
	}

	var smin, smax uint16
	if r.SPort != "" {
		var err error
		smin, smax, err = parsePort(r.SPort)
		if err != nil {
			return nil, false, fmt.Errorf("invalid sport %q: %v", r.SPort, err)
		}
	}

	var srcIP net.IP
	var srcNet *net.IPNet
	if srcStr != "" {
		var err error
		srcIP, srcNet, err = parseIPOrCIDR(srcStr)
		if err != nil {
			return nil, false, fmt.Errorf("invalid source %q: %v", srcStr, err)
		}
	}

	var dstIP net.IP
	var dstNet *net.IPNet
	if destStr != "" {
		var err error
		dstIP, dstNet, err = parseIPOrCIDR(destStr)
		if err != nil {
			return nil, false, fmt.Errorf("invalid dest %q: %v", destStr, err)
		}
	}

	var verdictExpr expr.Any
	switch strings.ToLower(r.Action) {
	case "", "drop":
		verdictExpr = &expr.Verdict{Kind: expr.VerdictDrop}
	case "accept":
		verdictExpr = &expr.Verdict{Kind: expr.VerdictAccept}
	case "reject":
		verdictExpr = &expr.Reject{Type: 0}
	default:
		return nil, false, fmt.Errorf("unknown action %q", r.Action)
	}

	var result [][]expr.Any
	for _, proto := range protos {
		var exprs []expr.Any

		if r.IIFName != "" {
			exprs = append(exprs,
				&expr.Meta{Key: expr.MetaKeyIIFNAME, Register: 1},
				&expr.Cmp{
					Op:       expr.CmpOpEq,
					Register: 1,
					Data:     nfifname(r.IIFName),
				},
			)
		}

		if proto != 0 {
			exprs = append(exprs,
				&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
				&expr.Cmp{
					Op:       expr.CmpOpEq,
					Register: 1,
					Data:     []byte{proto},
				},
			)
		}

		if portStr != "" {
			exprs = append(exprs,
				&expr.Payload{
					DestRegister: 1,
					Base:         expr.PayloadBaseTransportHeader,
					Offset:       2,
					Len:          2,
				},
			)
			if dmin == dmax {
				exprs = append(exprs,
					&expr.Cmp{
						Op:       expr.CmpOpEq,
						Register: 1,
						Data:     binaryutil.BigEndian.PutUint16(dmin),
					},
				)
			} else {
				exprs = append(exprs,
					&expr.Cmp{
						Op:       expr.CmpOpGte,
						Register: 1,
						Data:     binaryutil.BigEndian.PutUint16(dmin),
					},
					&expr.Cmp{
						Op:       expr.CmpOpLte,
						Register: 1,
						Data:     binaryutil.BigEndian.PutUint16(dmax),
					},
				)
			}
		}

		if r.SPort != "" {
			exprs = append(exprs,
				&expr.Payload{
					DestRegister: 1,
					Base:         expr.PayloadBaseTransportHeader,
					Offset:       0,
					Len:          2,
				},
			)
			if smin == smax {
				exprs = append(exprs,
					&expr.Cmp{
						Op:       expr.CmpOpEq,
						Register: 1,
						Data:     binaryutil.BigEndian.PutUint16(smin),
					},
				)
			} else {
				exprs = append(exprs,
					&expr.Cmp{
						Op:       expr.CmpOpGte,
						Register: 1,
						Data:     binaryutil.BigEndian.PutUint16(smin),
					},
					&expr.Cmp{
						Op:       expr.CmpOpLte,
						Register: 1,
						Data:     binaryutil.BigEndian.PutUint16(smax),
					},
				)
			}
		}

		if srcIP != nil {
			srcExprs := ipMatchExpr(srcIP, srcNet, invertSource, true, tableFamily)
			exprs = append(exprs, srcExprs...)
		}

		if dstIP != nil {
			dstExprs := ipMatchExpr(dstIP, dstNet, invertDest, false, tableFamily)
			exprs = append(exprs, dstExprs...)
		}

		exprs = append(exprs, verdictExpr)
		result = append(result, exprs)
	}

	return result, true, nil
}
