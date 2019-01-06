// +build ignore

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

package main

import (
	"bytes"
	"fmt"
	"go/format"
	"io"
	"log"

	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/renameio"
)

// udp and (port 67 or port 68)   # dhcpv4
// udp and (port 546 or port 547) # dhcpv6
// icmp6                          # router|neighbor solicitation|announcement
const expression = `icmp6 or (udp and (port 67 or port 68 or port 546 or port 547))`

func gen(w io.Writer) error {
	fmt.Fprintf(w, "package main\n")
	instructions, err := pcap.CompileBPFFilter(layers.LinkTypeEthernet, 1500, expression)
	if err != nil {
		return err
	}
	fmt.Fprintf(w, "import %q\n", "golang.org/x/net/bpf")
	fmt.Fprintf(w, "var instructions = []bpf.RawInstruction{\n")
	for _, inst := range instructions {
		fmt.Fprintf(w, "{%d, %d, %d, %d},\n", inst.Code, inst.Jt, inst.Jf, inst.K)
	}
	fmt.Fprintf(w, "}")
	return nil
}

func main() {
	var buffer bytes.Buffer
	if err := gen(&buffer); err != nil {
		log.Fatal(err)
	}
	gofmt, err := format.Source(buffer.Bytes())
	if err != nil {
		log.Fatal(err)
	}
	if err := renameio.WriteFile("GENERATED_filterexpr.go", gofmt, 0644); err != nil {
		log.Fatal(err)
	}
}
