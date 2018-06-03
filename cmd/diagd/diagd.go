// Binary diagd provides automated network diagnostics.
package main

import (
	"flag"
	"fmt"
	"html"
	"io"
	"log"
	"net/http"
	"sync"

	"router7/internal/diag"
)

func dump(w io.Writer, re *diag.EvalResult) {
	symbol := "✔"
	if re.Error {
		symbol = "✘"
	}
	fmt.Fprintf(w, "<li>%s %s: %s<ul>", symbol, html.EscapeString(re.Name), html.EscapeString(re.Status))
	for _, ch := range re.Children {
		dump(w, ch)
	}
	fmt.Fprintf(w, "</ul></li>")
}

func logic() error {
	const (
		uplink        = "uplink0" /* enp0s31f6 */
		ip6allrouters = "ff02::2" // no /etc/hosts on gokrazy
	)
	m := diag.NewMonitor(diag.Link(uplink).
		Then(diag.DHCPv4().
			Then(diag.Ping4Gateway().
				Then(diag.Ping4("google.ch").
					Then(diag.TCP4("www.google.ch:80"))))).
		Then(diag.DHCPv6().
			Then(diag.Ping6("lan0", "google.ch"))).
		Then(diag.RouterAdvertisments(uplink).
			Then(diag.Ping6Gateway().
				Then(diag.Ping6(uplink, "google.ch").
					Then(diag.TCP6("www.google.ch:80"))))).
		Then(diag.Ping6("", ip6allrouters+"%"+uplink)))
	var mu sync.Mutex
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		re := m.Evaluate()
		mu.Unlock()
		fmt.Fprintf(w, `<!DOCTYPE html><style type="text/css">ul { list-style-type: none; }</style><ul>`)
		dump(w, re)
	})
	// TODO: only listen on private IP addresses
	return http.ListenAndServe(":7733", nil)
}

func main() {
	flag.Parse()

	if err := logic(); err != nil {
		log.Fatal(err)
	}
}
