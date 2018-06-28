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
	"net"
)

type tcp4 struct {
	children []Node
	addr     string
}

func (d *tcp4) String() string {
	return "tcp4/" + d.addr
}

func (d *tcp4) Then(t Node) Node {
	d.children = append(d.children, t)
	return d
}

func (d *tcp4) Children() []Node {
	return d.children
}

func (d *tcp4) Evaluate() (string, error) {
	conn, err := net.Dial("tcp4", d.addr)
	if err != nil {
		return "", err
	}
	defer conn.Close()
	return "connection established", nil
}

// TCP4 returns a Node which succeeds when the specified address accepts a TCPv4
// connection.
func TCP4(addr string) Node {
	return &tcp4{addr: addr}
}

type tcp6 struct {
	children []Node
	addr     string
}

func (d *tcp6) String() string {
	return "tcp6/" + d.addr
}

func (d *tcp6) Then(t Node) Node {
	d.children = append(d.children, t)
	return d
}

func (d *tcp6) Children() []Node {
	return d.children
}

func (d *tcp6) Evaluate() (string, error) {
	conn, err := net.Dial("tcp6", d.addr)
	if err != nil {
		return "", err
	}
	defer conn.Close()
	return "connection established", nil
}

// TCP6 returns a Node which succeeds when the specified address accepts a TCPv6
// connection.
func TCP6(addr string) Node {
	return &tcp6{addr: addr}
}
