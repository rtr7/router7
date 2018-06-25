// Package netconfig implements network configuration (interfaces, addresses, firewall rules, …).
package netconfig

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"

	"github.com/google/nftables"
	"github.com/google/nftables/binaryutil"
	"github.com/google/nftables/expr"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"router7/internal/dhcp4"
	"router7/internal/dhcp6"
	"router7/internal/notify"
	"router7/internal/teelogger"
)

var log = teelogger.NewConsole()

func subnetMaskSize(mask string) (int, error) {
	parts := strings.Split(mask, ".")
	if got, want := len(parts), 4; got != want {
		return 0, fmt.Errorf("unexpected number of parts in subnet mask %q: got %d, want %d", mask, got, want)
	}
	numeric := make([]byte, len(parts))
	for idx, part := range parts {
		i, err := strconv.ParseUint(part, 0, 8)
		if err != nil {
			return 0, err
		}
		numeric[idx] = byte(i)
	}
	ones, _ := net.IPv4Mask(numeric[0], numeric[1], numeric[2], numeric[3]).Size()
	return ones, nil
}

func applyDhcp4(dir string) error {
	b, err := ioutil.ReadFile(filepath.Join(dir, "dhcp4/wire/lease.json"))
	if err != nil {
		if os.IsNotExist(err) {
			return nil // dhcp4 might not have obtained a lease yet
		}
		return err
	}
	var got dhcp4.Config
	if err := json.Unmarshal(b, &got); err != nil {
		return err
	}

	link, err := netlink.LinkByName("uplink0")
	if err != nil {
		return err
	}

	if got.SubnetMask == "" {
		return fmt.Errorf("invalid DHCP lease: no subnet mask present")
	}

	subnetSize, err := subnetMaskSize(got.SubnetMask)
	if err != nil {
		return err
	}

	addr, err := netlink.ParseAddr(fmt.Sprintf("%s/%d", got.ClientIP, subnetSize))
	if err != nil {
		return err
	}

	h, err := netlink.NewHandle()
	if err != nil {
		return fmt.Errorf("netlink.NewHandle: %v", err)
	}
	if err := h.AddrReplace(link, addr); err != nil {
		return fmt.Errorf("AddrReplace(%v): %v", addr, err)
	}

	// from include/uapi/linux/rtnetlink.h
	const (
		RTPROT_STATIC = 4
		RTPROT_DHCP   = 16
	)

	if err := h.RouteReplace(&netlink.Route{
		LinkIndex: link.Attrs().Index,
		Dst: &net.IPNet{
			IP:   net.ParseIP(got.Router),
			Mask: net.CIDRMask(32, 32),
		},
		Src:      net.ParseIP(got.ClientIP),
		Scope:    netlink.SCOPE_LINK,
		Protocol: RTPROT_DHCP,
	}); err != nil {
		return fmt.Errorf("RouteReplace(router): %v", err)
	}

	if err := h.RouteReplace(&netlink.Route{
		LinkIndex: link.Attrs().Index,
		Dst: &net.IPNet{
			IP:   net.ParseIP("0.0.0.0"),
			Mask: net.CIDRMask(0, 32),
		},
		Gw:       net.ParseIP(got.Router),
		Src:      net.ParseIP(got.ClientIP),
		Protocol: RTPROT_DHCP,
	}); err != nil {
		return fmt.Errorf("RouteReplace(default): %v", err)
	}

	return nil
}

func applyDhcp6(dir string) error {
	b, err := ioutil.ReadFile(filepath.Join(dir, "dhcp6/wire/lease.json"))
	if err != nil {
		if os.IsNotExist(err) {
			return nil // dhcp6 might not have obtained a lease yet
		}
		return err
	}
	var got dhcp6.Config
	if err := json.Unmarshal(b, &got); err != nil {
		return err
	}

	link, err := netlink.LinkByName("lan0")
	if err != nil {
		return err
	}

	for _, prefix := range got.Prefixes {
		// pick the first address of the prefix, e.g. address 2a02:168:4a00::1
		// for prefix 2a02:168:4a00::/48
		prefix.IP[len(prefix.IP)-1] = 1
		// Use the first /64 subnet within larger prefixes
		if ones, bits := prefix.Mask.Size(); ones < 64 {
			prefix.Mask = net.CIDRMask(64, bits)
		}
		addr, err := netlink.ParseAddr(prefix.String())
		if err != nil {
			return err
		}

		if err := netlink.AddrReplace(link, addr); err != nil {
			return fmt.Errorf("AddrReplace(%v): %v", addr, err)
		}
	}
	return nil
}

type InterfaceDetails struct {
	HardwareAddr      string `json:"hardware_addr"`       // e.g. dc:9b:9c:ee:72:fd
	SpoofHardwareAddr string `json:"spoof_hardware_addr"` // e.g. dc:9b:9c:ee:72:fd
	Name              string `json:"name"`                // e.g. uplink0, or lan0
	Addr              string `json:"addr"`                // e.g. 192.168.42.1/24
}

type InterfaceConfig struct {
	Interfaces []InterfaceDetails `json:"interfaces"`
}

// LinkAddress returns the IP address configured for the interface ifname in
// interfaces.json.
func LinkAddress(dir, ifname string) (net.IP, error) {
	fn := filepath.Join(dir, "interfaces.json")
	b, err := ioutil.ReadFile(fn)
	if err != nil {
		return nil, err
	}
	var cfg InterfaceConfig
	if err := json.Unmarshal(b, &cfg); err != nil {
		return nil, err
	}
	for _, details := range cfg.Interfaces {
		if details.Name != ifname {
			continue
		}
		ip, _, err := net.ParseCIDR(details.Addr)
		return ip, err
	}
	return nil, fmt.Errorf("%s does not configure interface %q", fn, ifname)
}

func applyInterfaces(dir, root string) error {
	b, err := ioutil.ReadFile(filepath.Join(dir, "interfaces.json"))
	if err != nil {
		return err
	}
	var cfg InterfaceConfig
	if err := json.Unmarshal(b, &cfg); err != nil {
		return err
	}
	byHardwareAddr := make(map[string]InterfaceDetails)
	for _, details := range cfg.Interfaces {
		byHardwareAddr[details.HardwareAddr] = details
		if spoof := details.SpoofHardwareAddr; spoof != "" {
			byHardwareAddr[spoof] = details
		}
	}
	links, err := netlink.LinkList()
	for _, l := range links {
		attr := l.Attrs()
		// TODO: prefix log line with details about the interface.
		// link &{LinkAttrs:{Index:2 MTU:1500 TxQLen:1000 Name:eth0 HardwareAddr:00:0d:b9:49:70:18 Flags:broadcast|multicast RawFlags:4098 ParentIndex:0 MasterIndex:0 Namespace:<nil> Alias: Statistics:0xc4200f45f8 Promisc:0 Xdp:0xc4200ca180 EncapType:ether Protinfo:<nil> OperState:down NetNsID:0 NumTxQueues:0 NumRxQueues:0 Vfs:[]}}, attr &{Index:2 MTU:1500 TxQLen:1000 Name:eth0 HardwareAddr:00:0d:b9:49:70:18 Flags:broadcast|multicast RawFlags:4098 ParentIndex:0 MasterIndex:0 Namespace:<nil> Alias: Statistics:0xc4200f45f8 Promisc:0 Xdp:0xc4200ca180 EncapType:ether Protinfo:<nil> OperState:down NetNsID:0 NumTxQueues:0 NumRxQueues:0 Vfs:[]}

		addr := attr.HardwareAddr.String()
		details, ok := byHardwareAddr[addr]
		if !ok {
			if addr == "" {
				continue // not a configurable interface (e.g. sit0)
			}
			log.Printf("no config for hardwareattr %s", addr)
			continue
		}
		log.Printf("apply details %+v", details)
		if attr.Name != details.Name {
			if err := netlink.LinkSetName(l, details.Name); err != nil {
				return fmt.Errorf("LinkSetName(%q): %v", details.Name, err)
			}
			attr.Name = details.Name
		}

		if spoof := details.SpoofHardwareAddr; spoof != "" {
			hwaddr, err := net.ParseMAC(spoof)
			if err != nil {
				return fmt.Errorf("ParseMAC(%q): %v", spoof, err)
			}
			if err := netlink.LinkSetHardwareAddr(l, hwaddr); err != nil {
				return fmt.Errorf("LinkSetHardwareAddr(%v): %v", hwaddr, err)
			}
		}

		if attr.OperState != netlink.OperUp {
			// Set the interface to up, which is required by all other configuration.
			if err := netlink.LinkSetUp(l); err != nil {
				return fmt.Errorf("LinkSetUp(%s): %v", attr.Name, err)
			}
		}

		if details.Addr != "" {
			addr, err := netlink.ParseAddr(details.Addr)
			if err != nil {
				return fmt.Errorf("ParseAddr(%q): %v", details.Addr, err)
			}

			if err := netlink.AddrReplace(l, addr); err != nil {
				return fmt.Errorf("AddrReplace(%s, %v): %v", attr.Name, addr, err)
			}

			if details.Name == "lan0" {
				b := []byte("nameserver " + addr.IP.String() + "\n")
				fn := filepath.Join(root, "tmp", "resolv.conf")
				if err := os.Remove(fn); err != nil && !os.IsNotExist(err) {
					return err
				}
				if err := ioutil.WriteFile(fn, b, 0644); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

func ifname(n string) []byte {
	b := make([]byte, 16)
	copy(b, []byte(n+"\x00"))
	return b
}

func portForwardExpr(proto uint8, portMin, portMax uint16, dest net.IP, dportMin, dportMax uint16) []expr.Any {
	var cmp []expr.Any
	if portMin == portMax {
		cmp = []expr.Any{
			// [ cmp eq reg 1 0x0000e60f ]
			&expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     binaryutil.BigEndian.PutUint16(portMin),
			},
		}
	} else {
		cmp = []expr.Any{
			// [ cmp gte reg 1 0x0000e60f ]
			&expr.Cmp{
				Op:       expr.CmpOpGte,
				Register: 1,
				Data:     binaryutil.BigEndian.PutUint16(portMin),
			},
			// [ cmp lte reg 1 0x0000fa0f ]
			&expr.Cmp{
				Op:       expr.CmpOpLte,
				Register: 1,
				Data:     binaryutil.BigEndian.PutUint16(portMax),
			},
		}
	}
	ex := []expr.Any{
		// [ meta load iifname => reg 1 ]
		&expr.Meta{Key: expr.MetaKeyIIFNAME, Register: 1},
		// [ cmp eq reg 1 0x696c7075 0x00306b6e 0x00000000 0x00000000 ]
		&expr.Cmp{
			Op:       expr.CmpOpEq,
			Register: 1,
			Data:     ifname("uplink0"),
		},

		// [ meta load l4proto => reg 1 ]
		&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
		// [ cmp eq reg 1 0x00000006 ]
		&expr.Cmp{
			Op:       expr.CmpOpEq,
			Register: 1,
			Data:     []byte{proto},
		},

		// [ payload load 2b @ transport header + 2 => reg 1 ]
		&expr.Payload{
			DestRegister: 1,
			Base:         expr.PayloadBaseTransportHeader,
			Offset:       2, // TODO
			Len:          2, // TODO
		},
	}
	ex = append(ex, cmp...)
	ex = append(ex,
		// [ immediate reg 1 0x0217a8c0 ]
		&expr.Immediate{
			Register: 1,
			Data:     dest.To4(),
		},
	)
	if dportMin == dportMax {
		ex = append(ex,
			// [ immediate reg 2 0x0000f00f ]
			&expr.Immediate{
				Register: 2,
				Data:     binaryutil.BigEndian.PutUint16(dportMin),
			},
			// [ nat dnat ip addr_min reg 1 addr_max reg 0 proto_min reg 2 proto_max reg 0 ]
			&expr.NAT{
				Type:        expr.NATTypeDestNAT,
				Family:      unix.NFPROTO_IPV4,
				RegAddrMin:  1,
				RegProtoMin: 2,
			},
		)
	} else {
		ex = append(ex,
			// [ immediate reg 2 0x0000e60f ]
			&expr.Immediate{
				Register: 2,
				Data:     binaryutil.BigEndian.PutUint16(dportMin),
			},
			// [ immediate reg 3 0x0000fa0f ]
			&expr.Immediate{
				Register: 3,
				Data:     binaryutil.BigEndian.PutUint16(dportMax),
			},
			// [ nat dnat ip addr_min reg 1 addr_max reg 0 proto_min reg 2 proto_max reg 3 ]
			&expr.NAT{
				Type:        expr.NATTypeDestNAT,
				Family:      unix.NFPROTO_IPV4,
				RegAddrMin:  1,
				RegProtoMin: 2,
				RegProtoMax: 3,
			},
		)
	}
	return ex
}

type portForwarding struct {
	Proto    string `json:"proto"`     // e.g. “tcp” (or “tcp,udp”)
	Port     string `json:"port"`      // e.g. “8080” (or “8080-8090”)
	DestAddr string `json:"dest_addr"` // e.g. “192.168.42.2”
	DestPort string `json:"dest_port"` // e.g. “80” (or “80-90”)
}

type portForwardings struct {
	Forwardings []portForwarding `json:"forwardings"`
}

var rangeRe = regexp.MustCompile(`^([0-9]+)(?:-([0-9]+))?$`)

func parsePort(p string) (min uint16, max uint16, _ error) {
	matches := rangeRe.FindStringSubmatch(p)
	if len(matches) == 0 {
		return 0, 0, fmt.Errorf("malformed port %q, expected port number (e.g. 8080) or port range (e.g. 8080-8090)", p)
	}
	min64, err := strconv.ParseUint(matches[1], 0, 16)
	if err != nil {
		return 0, 0, fmt.Errorf("ParseInt(%q): %v", matches[1], err)
	}
	max64 := min64
	if matches[2] != "" {
		max64, err = strconv.ParseUint(matches[2], 0, 16)
		if err != nil {
			return 0, 0, fmt.Errorf("ParseInt(%q): %v", matches[2], err)
		}
	}
	return uint16(min64), uint16(max64), nil
}

func applyPortForwardings(dir string, c *nftables.Conn, nat *nftables.Table, prerouting *nftables.Chain) error {
	b, err := ioutil.ReadFile(filepath.Join(dir, "portforwardings.json"))
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	var cfg portForwardings
	if err := json.Unmarshal(b, &cfg); err != nil {
		return err
	}

	for _, fw := range cfg.Forwardings {
		for _, proto := range strings.Split(fw.Proto, ",") {
			var p uint8
			switch proto {
			case "", "tcp":
				p = unix.IPPROTO_TCP
			case "udp":
				p = unix.IPPROTO_UDP
			default:
				return fmt.Errorf(`unknown proto %q, expected "tcp" or "udp"`, proto)
			}

			min, max, err := parsePort(fw.Port)
			if err != nil {
				return err
			}
			dmin, dmax, err := parsePort(fw.DestPort)
			if err != nil {
				return err
			}

			c.AddRule(&nftables.Rule{
				Table: nat,
				Chain: prerouting,
				Exprs: portForwardExpr(p, min, max, net.ParseIP(fw.DestAddr), dmin, dmax),
			})
		}
	}
	return nil
}

// DefaultCounter is overridden while testing
var DefaultCounter expr.Counter

func getCounter(c *nftables.Conn, table *nftables.Table, chain *nftables.Chain) expr.Counter {
	rules, err := c.GetRule(table, chain)
	if err != nil {
		return DefaultCounter
	}
	if got, want := len(rules), 1; got != want {
		log.Printf("could not carry counter values: unexpected number of rules in table %v, chain %v: got %d, want %d", table.Name, chain.Name, got, want)
		return DefaultCounter
	}
	if got, want := len(rules[0].Exprs), 1; got != want {
		log.Printf("could not carry counter values: unexpected number of exprs in rule 0 in table %v, chain %v: got %d, want %d", table.Name, chain.Name, got, want)
		return DefaultCounter
	}
	if ce, ok := rules[0].Exprs[0].(*expr.Counter); ok {
		return *ce
	}
	return DefaultCounter
}

func applyFirewall(dir string) error {
	c := &nftables.Conn{}

	c.FlushRuleset()

	nat := c.AddTable(&nftables.Table{
		Family: nftables.TableFamilyIPv4,
		Name:   "nat",
	})

	prerouting := c.AddChain(&nftables.Chain{
		Name:     "prerouting",
		Hooknum:  nftables.ChainHookPrerouting,
		Priority: nftables.ChainPriorityFilter,
		Table:    nat,
		Type:     nftables.ChainTypeNAT,
	})

	postrouting := c.AddChain(&nftables.Chain{
		Name:     "postrouting",
		Hooknum:  nftables.ChainHookPostrouting,
		Priority: nftables.ChainPriorityNATSource,
		Table:    nat,
		Type:     nftables.ChainTypeNAT,
	})

	c.AddRule(&nftables.Rule{
		Table: nat,
		Chain: postrouting,
		Exprs: []expr.Any{
			// meta load oifname => reg 1
			&expr.Meta{Key: expr.MetaKeyOIFNAME, Register: 1},
			// cmp eq reg 1 0x696c7075 0x00306b6e 0x00000000 0x00000000
			&expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     ifname("uplink0"),
			},
			// masq
			&expr.Masq{},
		},
	})

	if err := applyPortForwardings(dir, c, nat, prerouting); err != nil {
		return err
	}

	filter4 := c.AddTable(&nftables.Table{
		Family: nftables.TableFamilyIPv4,
		Name:   "filter",
	})

	filter6 := c.AddTable(&nftables.Table{
		Family: nftables.TableFamilyIPv6,
		Name:   "filter",
	})

	for _, filter := range []*nftables.Table{filter4, filter6} {
		forward := c.AddChain(&nftables.Chain{
			Name:     "forward",
			Hooknum:  nftables.ChainHookForward,
			Priority: nftables.ChainPriorityFilter,
			Table:    filter,
			Type:     nftables.ChainTypeFilter,
		})

		counter := getCounter(c, filter, forward)

		c.AddRule(&nftables.Rule{
			Table: filter,
			Chain: forward,
			Exprs: []expr.Any{
				// [ counter pkts 23 bytes 42 ]
				&counter,
			},
		})
	}

	return c.Flush()
}

func applySysctl() error {
	if err := ioutil.WriteFile("/proc/sys/net/ipv4/ip_forward", []byte("1"), 0644); err != nil {
		return fmt.Errorf("sysctl(net.ipv4.ip_forward=1): %v", err)
	}

	if err := ioutil.WriteFile("/proc/sys/net/ipv6/conf/all/forwarding", []byte("1"), 0644); err != nil {
		return fmt.Errorf("sysctl(net.ipv6.conf.all.forwarding=1): %v", err)
	}

	if err := ioutil.WriteFile("/proc/sys/net/ipv6/conf/uplink0/accept_ra", []byte("2"), 0644); err != nil {
		return fmt.Errorf("sysctl(net.ipv6.conf.uplink0.accept_ra=2): %v", err)
	}

	return nil
}

func Apply(dir, root string) error {

	// TODO: split into two parts: delay the up until later
	if err := applyInterfaces(dir, root); err != nil {
		return fmt.Errorf("interfaces: %v", err)
	}

	var firstErr error

	if err := applyDhcp4(dir); err != nil {
		if firstErr == nil {
			firstErr = fmt.Errorf("dhcp4: %v", err)
		} else {
			log.Printf("cannot apply dhcp4 lease: %v", err)
		}
	}

	if err := applyDhcp6(dir); err != nil {
		if firstErr == nil {
			firstErr = fmt.Errorf("dhcp6: %v", err)
		} else {
			log.Printf("cannot apply dhcp6 lease: %v", err)
		}
	}

	for _, process := range []string{
		"dyndns", // depends on the public IPv4 address
		"dnsd",   // listens on private IPv4/IPv6 and public IPv6Net1
	} {
		if err := notify.Process("/user/"+process, syscall.SIGUSR1); err != nil {
			log.Printf("notifying %s: %v", process, err)
		}
	}

	if err := applySysctl(); err != nil {
		if firstErr == nil {
			firstErr = fmt.Errorf("sysctl: %v", err)
		} else {
			log.Printf("cannot apply sysctl config: %v", err)
		}
	}

	if err := applyFirewall(dir); err != nil {
		return fmt.Errorf("firewall: %v", err)
	}

	return firstErr
}
