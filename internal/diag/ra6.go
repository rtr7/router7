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
	"fmt"
	"net"
)

type ra6 struct {
	children []Node
	ifname   string
}

func (d *ra6) String() string {
	return "ra6/" + d.ifname
}

func (d *ra6) Then(t Node) Node {
	d.children = append(d.children, t)
	return d
}

func (d *ra6) Children() []Node {
	return d.children
}

func isEUI64(ip net.IP) bool {
	if ip.To16() == nil {
		return false
	}
	ip = ip.To16()
	return ip[11] == 0xff && ip[12] == 0xfe
}

func (d *ra6) Evaluate() (string, error) {
	iface, err := net.InterfaceByName(d.ifname)
	if err != nil {
		return "", err
	}
	addrs, err := iface.Addrs()
	if err != nil {
		return "", err
	}
	var first string
	for _, addr := range addrs {
		ipnet, ok := addr.(*net.IPNet)
		if !ok {
			continue
		}
		if ones, _ := ipnet.Mask.Size(); ones != 64 {
			continue
		}
		if !global.Contains(ipnet.IP) {
			continue // skip local IPv6 addresses
		}
		if !isEUI64(ipnet.IP) {
			continue // skip non-autoconf addresses (e.g. DHCPv6 temporary IP)
		}

		first = ipnet.String()
	}
	if first == "" {
		return "", fmt.Errorf("no SLAAC address found")
	}
	return first, nil
}

// RouterAdvertisments returns a Node which succeeds if the specified interface
// obtained at least one address from IPv6 router advertisments.
func RouterAdvertisments(ifname string) Node {
	return &ra6{ifname: ifname}
}
