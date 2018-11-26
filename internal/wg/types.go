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

// Package wg implements the WireGuard Linux kernel module’s generic netlink
// interface, e.g. for configuring WireGuard network interfaces (e.g. wg0)
// without resorting to the wg command line tool.
package wg

import (
	"net"
	"time"
)

const (
	wg_cmd_get_device = iota
	wg_cmd_set_device
)
const (
	wgdevice_a_unspec = iota
	wgdevice_a_ifindex
	wgdevice_a_ifname
	wgdevice_a_private_key
	wgdevice_a_public_key
	wgdevice_a_flags
	wgdevice_a_listen_port
	wgdevice_a_fwmark
	wgdevice_a_peers
)

const (
	wgpeer_a_unspec = iota
	wgpeer_a_public_key
	wgpeer_a_preshared_key
	wgpeer_a_flags
	wgpeer_a_endpoint
	wgpeer_a_persistent_keepalive_interval
	wgpeer_a_last_handshake_time
	wgpeer_a_rx_bytes
	wgpeer_a_tx_bytes
	wgpeer_a_allowedips
	wgpeer_a_protocol_version
)

const (
	wgallowedip_a_unspec = iota
	wgallowedip_a_family
	wgallowedip_a_ipaddr
	wgallowedip_a_cidr_mask
)

type Peer struct {
	PublicKey                   []byte
	PresharedKey                []byte
	PersistentKeepaliveInterval uint16
	LastHandshakeTime           time.Time
	RxBytes                     uint64
	TxBytes                     uint64
	AllowedIPs                  []*net.IPNet
	ProtocolVersion             uint32
	Endpoint                    string
}

type Device struct {
	Ifindex    uint32
	Ifname     string
	PrivateKey []byte
	PublicKey  []byte
	ListenPort uint16
	Fwmark     uint32
	Peers      []*Peer
}
