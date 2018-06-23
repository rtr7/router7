// Binary netconfigd reads state from dhcp4, dhcp6, … and applies it.
package main

import (
	"flag"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/gokrazy/gokrazy"
	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"router7/internal/multilisten"
	"router7/internal/netconfig"
	"router7/internal/teelogger"
)

var log = teelogger.NewConsole()

var (
	linger = flag.Bool("linger", true, "linger around after applying the configuration (until killed)")
)

func init() {
	var c nftables.Conn
	for _, metric := range []struct {
		name   string
		labels prometheus.Labels
		table  *nftables.Table
		chain  *nftables.Chain
	}{
		{
			name:   "filter_forward",
			labels: prometheus.Labels{"family": "ipv4"},
			table:  &nftables.Table{Family: nftables.TableFamilyIPv4, Name: "filter"},
			chain:  &nftables.Chain{Name: "forward"},
		},
		{
			name:   "filter_forward",
			labels: prometheus.Labels{"family": "ipv6"},
			table:  &nftables.Table{Family: nftables.TableFamilyIPv6, Name: "filter"},
			chain:  &nftables.Chain{Name: "forward"},
		},
	} {
		metric := metric // copy
		promauto.NewCounterFunc(
			prometheus.CounterOpts{
				Subsystem:   "nftables",
				Name:        metric.name + "_packets",
				Help:        "packet count",
				ConstLabels: metric.labels,
			},
			func() float64 {
				rules, err := c.GetRule(metric.table, metric.chain)
				if err != nil ||
					len(rules) != 1 ||
					len(rules[0].Exprs) != 1 {
					return 0
				}
				if ce, ok := rules[0].Exprs[0].(*expr.Counter); ok {
					return float64(ce.Packets)
				}
				return 0
			})
		promauto.NewCounterFunc(
			prometheus.CounterOpts{
				Subsystem:   "nftables",
				Name:        metric.name + "_bytes",
				Help:        "bytes count",
				ConstLabels: metric.labels,
			},
			func() float64 {
				rules, err := c.GetRule(metric.table, metric.chain)
				if err != nil ||
					len(rules) != 1 ||
					len(rules[0].Exprs) != 1 {
					return 0
				}
				if ce, ok := rules[0].Exprs[0].(*expr.Counter); ok {
					return float64(ce.Bytes)
				}
				return 0
			})
	}
}

func updateListeners() error {
	hosts, err := gokrazy.PrivateInterfaceAddrs()
	if err != nil {
		return err
	}
	if net1, err := multilisten.IPv6Net1("/perm"); err == nil {
		hosts = append(hosts, net1)
	}

	return multilisten.ListenAndServe(hosts, "8066", http.DefaultServeMux)
}

func logic() error {
	if *linger {
		http.Handle("/metrics", promhttp.Handler())
		updateListeners()
	}
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGUSR1)
	for {
		err := netconfig.Apply("/perm/", "/")
		// Notify gokrazy about new addresses (netconfig.Apply might have
		// modified state before returning an error) so that listeners can be
		// updated.
		p, _ := os.FindProcess(1)
		if err := p.Signal(syscall.SIGHUP); err != nil {
			log.Printf("kill -HUP 1: %v", err)
		}
		if err != nil {
			return err
		}
		if !*linger {
			break
		}
		<-ch
		if err := updateListeners(); err != nil {
			log.Printf("updateListeners: %v", err)
		}
	}
	return nil
}

func main() {
	flag.Parse()
	if err := logic(); err != nil {
		log.Fatal(err)
	}
}
