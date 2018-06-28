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
	"encoding/json"
	"fmt"
	"io/ioutil"
	"time"
)

func leaseValid(fn string) (status string, _ error) {
	var lease struct {
		ValidUntil time.Time `json:"valid_until"`
	}
	b, err := ioutil.ReadFile(fn)
	if err != nil {
		return "", err
	}
	if err := json.Unmarshal(b, &lease); err != nil {
		return "", err
	}
	if time.Now().After(lease.ValidUntil) {
		return "", fmt.Errorf("lease expired at %v", lease.ValidUntil)
	}
	return fmt.Sprintf("lease valid until %v", lease.ValidUntil), nil
}

type dhcpv4 struct {
	children []Node
}

func (d *dhcpv4) String() string {
	return "dhcp4"
}

func (d *dhcpv4) Then(t Node) Node {
	d.children = append(d.children, t)
	return d
}

func (d *dhcpv4) Children() []Node {
	return d.children
}

func (d *dhcpv4) Evaluate() (string, error) {
	return leaseValid("/perm/dhcp4/wire/lease.json")
}

// DHCPv4 returns a Node which succeeds if /perm/dhcp4/wire/lease.json contains
// a non-expired DHCPv4 lease.
func DHCPv4() Node {
	return &dhcpv4{}
}

type dhcpv6 struct {
	children []Node
}

func (d *dhcpv6) String() string {
	return "dhcp6"
}

func (d *dhcpv6) Then(t Node) Node {
	d.children = append(d.children, t)
	return d
}

func (d *dhcpv6) Children() []Node {
	return d.children
}

func (d *dhcpv6) Evaluate() (string, error) {
	return leaseValid("/perm/dhcp6/wire/lease.json")
}

// DHCPv6 returns a Node which succeeds if /perm/dhcp6/wire/lease.json contains
// a non-expired DHCPv6 lease.
func DHCPv6() Node {
	return &dhcpv6{}
}
