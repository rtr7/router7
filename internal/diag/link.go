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

	"github.com/vishvananda/netlink"
)

type link struct {
	children []Node
	ifname   string
}

func (l *link) String() string {
	return "link/" + l.ifname
}

func (l *link) Then(t Node) Node {
	l.children = append(l.children, t)
	return l
}

func (l *link) Children() []Node {
	return l.children
}

func (l *link) Evaluate() (string, error) {
	link, err := netlink.LinkByName(l.ifname)
	if err != nil {
		return "", err
	}
	attrs := link.Attrs()

	// TODO: check RUNNING as well?
	if attrs.Flags&net.FlagUp == 0 {
		return "", fmt.Errorf("link %s not UP", l.ifname)
	}

	return fmt.Sprintf("%d rx, %d tx", attrs.Statistics.RxPackets, attrs.Statistics.TxPackets), nil
}

// Link returns a Node which succeeds when the specified network interface is in
// state UP and RUNNING.
func Link(ifname string) Node {
	return &link{ifname: ifname}
}
