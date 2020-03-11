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

package diag

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/digineo/go-ping"
	"github.com/vishvananda/netlink"
)

func formatRTT(rtt time.Duration) string {
	return fmt.Sprintf("%.2fms", float64(rtt)/float64(time.Millisecond))
}

type ping4gw struct {
	children []Node
}

func (d *ping4gw) String() string {
	return "ping4: $default-gateway"
}

func (d *ping4gw) Then(t Node) Node {
	d.children = append(d.children, t)
	return d
}

func (d *ping4gw) Children() []Node {
	return d.children
}

func defaultIPv4Gateway() (string, error) {
	rl, err := netlink.RouteGet(net.ParseIP("8.8.8.8"))
	if err != nil {
		return "", err
	}
	if got, want := len(rl), 1; got != want {
		return "", fmt.Errorf("unexpected number of default routes: got %d, want %d", got, want)
	}
	r := rl[0]

	return r.Gw.String(), nil
}

func (d *ping4gw) Evaluate() (string, error) {
	const timeout = 1 * time.Second
	gw, err := defaultIPv4Gateway()
	if err != nil {
		return "", nil
	}
	addr, err := net.ResolveIPAddr("ip4", gw)
	if err != nil {
		return "", err
	}
	p, err := ping.New("0.0.0.0", "")
	if err != nil {
		return "", err
	}
	rtt, err := p.Ping(addr, timeout)
	if err != nil {
		return "", err
		//return fmt.Errorf("%s did not respond within %v", gw, timeout)
	}
	return formatRTT(rtt) + " from " + gw, nil
}

// Ping4Gateway returns a Node which succeeds when the default gateway responds
// to an ICMPv4 ping.
func Ping4Gateway() Node {
	return &ping4gw{}
}

type ping4 struct {
	children []Node
	addr     string
}

func (d *ping4) String() string {
	return "ping4: " + d.addr
}

func (d *ping4) Then(t Node) Node {
	d.children = append(d.children, t)
	return d
}

func (d *ping4) Children() []Node {
	return d.children
}

func (d *ping4) Evaluate() (string, error) {
	const timeout = 1 * time.Second
	addr, err := net.ResolveIPAddr("ip4", d.addr)
	if err != nil {
		return "", err
	}
	p, err := ping.New("0.0.0.0", "")
	if err != nil {
		return "", err
	}
	rtt, err := p.Ping(addr, timeout)
	if err != nil {
		return "", err
		//return fmt.Errorf("%s did not respond within %v", gw, timeout)
	}
	return formatRTT(rtt), nil
}

// Ping4 returns a Node which succeeds when the specified address responds to an
// ICMPv4 ping.
func Ping4(addr string) Node {
	return &ping4{addr: addr}
}

type ping6gw struct {
	children []Node
}

func (d *ping6gw) String() string {
	return "ping6gw: $default-gateway"
}

func (d *ping6gw) Then(t Node) Node {
	d.children = append(d.children, t)
	return d
}

func (d *ping6gw) Children() []Node {
	return d.children
}

func defaultIPv6Gateway() (string, error) {
	rl, err := netlink.RouteGet(net.IPv6zero)
	if err != nil {
		return "", err
	}
	if got, want := len(rl), 1; got != want {
		return "", fmt.Errorf("unexpected number of default routes: got %d, want %d", got, want)
	}
	r := rl[0]

	iface, err := net.InterfaceByIndex(r.LinkIndex)
	if err != nil {
		return "", err
	}
	return r.Gw.String() + "%" + iface.Name, nil
}

func (d *ping6gw) Evaluate() (string, error) {
	const timeout = 1 * time.Second
	gw, err := defaultIPv6Gateway()
	if err != nil {
		return "", err
	}
	addr, err := net.ResolveIPAddr("ip6", gw)
	if err != nil {
		return "", fmt.Errorf("net.ResolveIPAddr(%s): %v", gw, err)
	}
	p, err := ping.New("", "::")
	if err != nil {
		return "", fmt.Errorf("ping.New(::): %v", err)
	}
	rtt, err := p.Ping(addr, timeout)
	if err != nil {
		return "", fmt.Errorf("ping6(%v, %v): %v", addr, timeout, err)
	}
	return formatRTT(rtt) + " from " + gw, nil
}

// Ping6Gateway returns a Node which succeeds when the default gateway responds
// to an ICMPv6 ping.
func Ping6Gateway() Node {
	return &ping6gw{}
}

type ping6 struct {
	children []Node
	addr     string
	ifname   string
}

func (d *ping6) String() string {
	if d.ifname == "" {
		return "ping6: " + d.addr
	}
	return fmt.Sprintf("ping6: %s → %s", d.ifname, d.addr)
}

func (d *ping6) Then(t Node) Node {
	d.children = append(d.children, t)
	return d
}

func (d *ping6) Children() []Node {
	return d.children
}

func (d *ping6) Evaluate() (string, error) {
	const timeout = 1 * time.Second
	addr, err := net.ResolveIPAddr("ip6", d.addr)
	if err != nil {
		return "", err
	}
	bind6 := "::"
	if d.ifname != "" {
		iface, err := net.InterfaceByName(d.ifname)
		if err != nil {
			return "", err
		}
		addrs, err := iface.Addrs()
		if err != nil {
			return "", err
		}
		for _, addr := range addrs {
			ipnet, ok := addr.(*net.IPNet)
			if !ok {
				continue
			}

			if ipnet.IP.To4() != nil {
				continue // skip IPv4 addresses
			}

			if !global.Contains(ipnet.IP) {
				continue // skip local IPv6 addresses
			}

			bind6 = ipnet.IP.String()
			break
		}
	}

	p, err := ping.New("", bind6)
	if err != nil {
		return "", err
	}
	ctx, canc := context.WithTimeout(context.Background(), timeout)
	defer canc()
	if strings.HasPrefix(addr.String(), "ff02::") {
		replies, err := p.PingMulticastContext(ctx, addr)
		if err != nil {
			return "", err
		}
		addrs, err := net.InterfaceAddrs()
		if err != nil {
			return "", err
		}
		localAddr := make(map[string]bool)
		for _, addr := range addrs {
			ipnet, ok := addr.(*net.IPNet)
			if !ok {
				continue
			}
			localAddr[ipnet.IP.String()] = true
		}
		for reply := range replies {
			if localAddr[reply.Address.String()] {
				continue
			}
			return formatRTT(reply.Duration) + " from " + reply.Address.String(), nil
		}
		return "", fmt.Errorf("no responses to %s within %v", addr, timeout)
	}
	rtt, err := p.PingContext(ctx, addr)
	if err != nil {
		return "", err
		//return fmt.Errorf("%s did not respond within %v", gw, timeout)
	}
	return formatRTT(rtt), nil
}

// Ping6 returns a Node which succeeds when the specified address responds to an
// ICMPv6 ping.
func Ping6(ifname, addr string) Node {
	return &ping6{
		ifname: ifname,
		addr:   addr,
	}
}
