// +build ignore

package main

import (
	"bytes"
	"fmt"
	"go/format"
	"io"
	"io/ioutil"
	"log"

	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
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
	if err := ioutil.WriteFile("GENERATED_filterexpr.go", gofmt, 0644); err != nil {
		log.Fatal(err)
	}
}
