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

package dns

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rtr7/router7/internal/dhcp4d"

	"github.com/miekg/dns"
)

// TODO(later): upstream a dnstest.Recorder implementation
type recorder struct {
	response *dns.Msg
}

func (r *recorder) WriteMsg(m *dns.Msg) error {
	r.response = m
	return nil
}

func (r *recorder) LocalAddr() net.Addr       { return nil }
func (r *recorder) RemoteAddr() net.Addr      { return nil }
func (r *recorder) Write([]byte) (int, error) { return 0, nil }
func (r *recorder) Close() error              { return nil }
func (r *recorder) TsigStatus() error         { return nil }
func (r *recorder) TsigTimersOnly(bool)       {}
func (r *recorder) Hijack()                   {}

func TestNXDOMAIN(t *testing.T) {
	r := &recorder{}
	s := NewServer("localhost:0", "lan")
	m := new(dns.Msg)
	m.SetQuestion("foo.invalid.", dns.TypeA)
	s.Mux.ServeDNS(r, m)
	if got, want := r.response.MsgHdr.Rcode, dns.RcodeNameError; got != want {
		t.Fatalf("unexpected rcode: got %v, want %v", got, want)
	}
}

func TestResolveError(t *testing.T) {
	r := &recorder{}
	s := NewServer("localhost:0", "lan")
	s.upstream = []string{"266.266.266.266:53"}
	m := new(dns.Msg)
	m.SetQuestion("foo.invalid.", dns.TypeA)
	s.Mux.ServeDNS(r, m)
	if r.response != nil {
		t.Fatalf("r.response unexpectedly not nil: %v", r.response)
	}
}

func TestResolveFallback(t *testing.T) {
	s := NewServer("localhost:0", "lan")
	s.upstream = []string{
		"266.266.266.266:53",
		dnsServerAddr(t, dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
			reply(w, r, " 3600 IN A 127.0.0.1")
		})),
	}
	if err := resolveTestTarget(s, "google.ch.", net.ParseIP("127.0.0.1")); err != nil {
		t.Fatal(err)
	}
}

func dnsServerAddr(t *testing.T, h dns.Handler) string {
	t.Helper()

	pc, err := net.ListenPacket("udp", "localhost:0")
	if err != nil {
		t.Fatal(err)
	}
	go dns.ActivateAndServe(nil, pc, h)
	return pc.LocalAddr().String()
}

func TestResolveFallbackOnce(t *testing.T) {
	s := NewServer("localhost:0", "lan")
	var slowHits uint32
	s.upstream = []string{
		dnsServerAddr(t, dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
			atomic.AddUint32(&slowHits, 1)
			// trigger fallback by sending no reply
		})),
		dnsServerAddr(t, dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
			reply(w, r, " 3600 IN A 127.0.0.1")
		})),
		"266.266.266.266:53",
	}

	for i := 0; i < 2; i++ {
		if err := resolveTestTarget(s, "google.ch.", net.ParseIP("127.0.0.1")); err != nil {
			t.Fatal(err)
		}
	}
	if got, want := atomic.LoadUint32(&slowHits), uint32(1); got != want {
		t.Errorf("slow upstream server hits = %d, wanted %d", got, want)
	}
}

func reply(w dns.ResponseWriter, r *dns.Msg, response string) {
	rr, _ := dns.NewRR(r.Question[0].Name + response)
	m := new(dns.Msg)
	m.SetReply(r)
	m.Answer = append(m.Answer, rr)
	w.WriteMsg(m)
}

func TestResolveLatencySteering(t *testing.T) {
	s := NewServer("localhost:0", "lan")
	var slowHits uint32
	s.upstream = []string{
		dnsServerAddr(t, dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
			atomic.AddUint32(&slowHits, 1)
			time.Sleep(10 * time.Millisecond)
			reply(w, r, " 3600 IN A 127.0.0.1")
		})),
		dnsServerAddr(t, dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
			reply(w, r, " 3600 IN A 127.0.0.1")
		})),
		"266.266.266.266:53",
	}

	if err := resolveTestTarget(s, "google.ch.", net.ParseIP("127.0.0.1")); err != nil {
		t.Fatal(err)
	}
	s.probeUpstreamLatency()
	if err := resolveTestTarget(s, "google.ch.", net.ParseIP("127.0.0.1")); err != nil {
		t.Fatal(err)
	}

	want := uint32(2) // one for resolving, one for probing
	if got := atomic.LoadUint32(&slowHits); got != want {
		t.Errorf("slow upstream server hits = %d, wanted %d", got, want)
	}
}

func TestDHCP(t *testing.T) {
	r := &recorder{}
	s := NewServer("localhost:0", "lan")
	s.SetLeases([]dhcp4d.Lease{
		{
			Hostname: "testtarget",
			Addr:     net.IP{192, 168, 42, 23},
		},
	})

	t.Run("testtarget.lan.", func(t *testing.T) {
		if err := resolveTestTarget(s, "testtarget.lan.", net.ParseIP("192.168.42.23")); err != nil {
			t.Fatal(err)
		}
	})

	expired := time.Now().Add(-1 * time.Second)
	s.SetLeases([]dhcp4d.Lease{
		{
			Hostname: "testtarget",
			Addr:     net.IP{192, 168, 42, 23},
			Expiry:   time.Now().Add(1 * time.Minute),
		},
		{
			Hostname: "testtarget",
			Addr:     net.IP{192, 168, 42, 150},
			Expiry:   expired,
		},
	})

	t.Run("testtarget.lan. (expired)", func(t *testing.T) {
		if err := resolveTestTarget(s, "testtarget.lan.", net.ParseIP("192.168.42.23")); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("notfound.lan.", func(t *testing.T) {
		m := new(dns.Msg)
		m.SetQuestion("notfound.lan.", dns.TypeA)
		s.Mux.ServeDNS(r, m)
		if got, want := r.response.Rcode, dns.RcodeNameError; got != want {
			t.Fatalf("unexpected rcode: got %v, want %v", got, want)
		}
	})
}

func TestHostname(t *testing.T) {
	hostname, err := os.Hostname()
	if err != nil {
		t.Skipf("os.Hostname: %v", err)
	}

	r := &recorder{}
	s := NewServer("127.0.0.2:0", "lan")
	s.SetLeases([]dhcp4d.Lease{
		{
			Hostname: strings.ToUpper(hostname),
			Addr:     net.IP{192, 168, 42, 23},
		},
	})

	t.Run("A", func(t *testing.T) {
		for _, hostname := range []string{
			hostname,
			strings.ToUpper(hostname),
		} {
			t.Run(hostname, func(t *testing.T) {
				m := new(dns.Msg)
				m.SetQuestion(hostname+".lan.", dns.TypeA)
				s.Mux.ServeDNS(r, m)
				if got, want := len(r.response.Answer), 1; got != want {
					t.Fatalf("unexpected number of answers for %v: got %d, want %d", m.Question, got, want)
				}
				a := r.response.Answer[0]
				if _, ok := a.(*dns.A); !ok {
					t.Fatalf("unexpected response type: got %T, want dns.A", a)
				}
				if got, want := a.(*dns.A).A, net.ParseIP("127.0.0.2"); !got.Equal(want) {
					t.Fatalf("unexpected response IP: got %v, want %v", got, want)
				}
			})
		}
	})

	t.Run("PTR", func(t *testing.T) {
		m := new(dns.Msg)
		m.SetQuestion("2.0.0.127.in-addr.arpa.", dns.TypePTR)
		s.Mux.ServeDNS(r, m)
		if got, want := len(r.response.Answer), 1; got != want {
			t.Fatalf("unexpected number of answers: got %d, want %d", got, want)
		}
		a := r.response.Answer[0]
		if _, ok := a.(*dns.PTR); !ok {
			t.Fatalf("unexpected response type: got %T, want dns.PTR", a)
		}
		if got, want := a.(*dns.PTR).Ptr, hostname+".lan."; got != want {
			t.Fatalf("unexpected response record: got %q, want %q", got, want)
		}
	})

	t.Run("MoreRecent", func(t *testing.T) {
		now := time.Now()
		older := dhcp4d.Lease{
			Hostname: "xps",
			Addr:     net.IP{192, 168, 42, 23},
			Expiry:   now.Add(1 * time.Second),
		}
		newer := dhcp4d.Lease{
			Hostname: "xps",
			Addr:     net.IP{192, 168, 42, 42},
			Expiry:   now.Add(2 * time.Second),
		}

		for _, tt := range []struct {
			name  string
			order []dhcp4d.Lease
		}{
			{
				name:  "older, newer",
				order: []dhcp4d.Lease{older, newer},
			},
			{
				name:  "newer, older",
				order: []dhcp4d.Lease{newer, older},
			},
		} {
			t.Run(tt.name, func(t *testing.T) {
				s.SetLeases(tt.order)
				m := new(dns.Msg)
				m.SetQuestion("xps.lan.", dns.TypeA)
				s.Mux.ServeDNS(r, m)
				if got, want := len(r.response.Answer), 1; got != want {
					t.Fatalf("unexpected number of answers for %v: got %d, want %d", m.Question, got, want)
				}
				a := r.response.Answer[0]
				if _, ok := a.(*dns.A); !ok {
					t.Fatalf("unexpected response type: got %T, want dns.A", a)
				}
				if got, want := a.(*dns.A).A, net.ParseIP("192.168.42.42"); !got.Equal(want) {
					t.Fatalf("unexpected response IP: got %v, want %v", got, want)
				}
			})
		}
	})
}

func TestHostnameDHCP(t *testing.T) {
	hostname, err := os.Hostname()
	if err != nil {
		t.Skipf("os.Hostname: %v", err)
	}

	r := &recorder{}
	s := NewServer("127.0.0.2:0", "lan")

	t.Run("A", func(t *testing.T) {
		m := new(dns.Msg)
		m.SetQuestion(hostname+".lan.", dns.TypeA)
		s.Mux.ServeDNS(r, m)
		if got, want := len(r.response.Answer), 1; got != want {
			t.Fatalf("unexpected number of answers for %v: got %d, want %d", m.Question, got, want)
		}
		a := r.response.Answer[0]
		if _, ok := a.(*dns.A); !ok {
			t.Fatalf("unexpected response type: got %T, want dns.A", a)
		}
		if got, want := a.(*dns.A).A, net.ParseIP("127.0.0.2"); !got.Equal(want) {
			t.Fatalf("unexpected response IP: got %v, want %v", got, want)
		}
	})

	t.Run("PTR", func(t *testing.T) {
		m := new(dns.Msg)
		m.SetQuestion("2.0.0.127.in-addr.arpa.", dns.TypePTR)
		s.Mux.ServeDNS(r, m)
		if got, want := len(r.response.Answer), 1; got != want {
			t.Fatalf("unexpected number of answers: got %d, want %d", got, want)
		}
		a := r.response.Answer[0]
		if _, ok := a.(*dns.PTR); !ok {
			t.Fatalf("unexpected response type: got %T, want dns.PTR", a)
		}
		if got, want := a.(*dns.PTR).Ptr, hostname+".lan."; got != want {
			t.Fatalf("unexpected response record: got %q, want %q", got, want)
		}
	})

	t.Run("AAAA", func(t *testing.T) {
		m := new(dns.Msg)
		m.SetQuestion(hostname+".lan.", dns.TypeAAAA)
		s.Mux.ServeDNS(r, m)
		if got, want := r.response.MsgHdr.Rcode, dns.RcodeSuccess; got != want {
			t.Fatalf("unexpected rcode: got %v, want %v", got, want)
		}
		if got, want := len(r.response.Answer), 0; got != want {
			t.Fatalf("unexpected number of answers: got %d, want %d", got, want)
		}
	})
}

func TestLocalhost(t *testing.T) {
	r := &recorder{}
	s := NewServer("127.0.0.2:0", "lan")

	t.Run("A", func(t *testing.T) {
		m := new(dns.Msg)
		m.SetQuestion("localhost.", dns.TypeA)
		s.Mux.ServeDNS(r, m)
		if got, want := len(r.response.Answer), 1; got != want {
			t.Fatalf("unexpected number of answers for %v: got %d, want %d", m.Question, got, want)
		}
		a := r.response.Answer[0]
		if _, ok := a.(*dns.A); !ok {
			t.Fatalf("unexpected response type: got %T, want dns.A", a)
		}
		if got, want := a.(*dns.A).A, net.ParseIP("127.0.0.1"); !got.Equal(want) {
			t.Fatalf("unexpected response IP: got %v, want %v", got, want)
		}
	})

	t.Run("AAAA", func(t *testing.T) {
		m := new(dns.Msg)
		m.SetQuestion("localhost.", dns.TypeAAAA)
		s.Mux.ServeDNS(r, m)
		if got, want := len(r.response.Answer), 1; got != want {
			t.Fatalf("unexpected number of answers for %v: got %d, want %d", m.Question, got, want)
		}
		a := r.response.Answer[0]
		if _, ok := a.(*dns.AAAA); !ok {
			t.Fatalf("unexpected response type: got %T, want dns.A", a)
		}
		if got, want := a.(*dns.AAAA).AAAA, (net.ParseIP("::1")); !bytes.Equal(got, want) {
			t.Fatalf("unexpected response IP: got %v, want %v", got, want)
		}
	})

	t.Run("PTR", func(t *testing.T) {
		m := new(dns.Msg)
		m.SetQuestion("1.0.0.127.in-addr.arpa.", dns.TypePTR)
		s.Mux.ServeDNS(r, m)
		if got, want := len(r.response.Answer), 1; got != want {
			t.Fatalf("unexpected number of answers: got %d, want %d", got, want)
		}
		a := r.response.Answer[0]
		if _, ok := a.(*dns.PTR); !ok {
			t.Fatalf("unexpected response type: got %T, want dns.PTR", a)
		}
		if got, want := a.(*dns.PTR).Ptr, "localhost."; got != want {
			t.Fatalf("unexpected response record: got %q, want %q", got, want)
		}
	})
}

func TestDHCPReverse(t *testing.T) {
	for _, test := range []struct {
		ip       net.IP
		question string
	}{
		{
			ip:       net.IP{192, 168, 42, 23},
			question: "23.42.168.192.in-addr.arpa.",
		},

		{
			ip:       net.IP{10, 0, 0, 2},
			question: "2.0.0.10.in-addr.arpa.",
		},

		{
			ip:       net.IP{172, 16, 0, 1}, // 172.16/12 HostMin
			question: "1.0.16.172.in-addr.arpa.",
		},

		{
			ip:       net.IP{172, 31, 255, 254}, // 172.16/12 HostMax
			question: "254.255.31.172.in-addr.arpa.",
		},
	} {
		t.Run(test.question, func(t *testing.T) {
			r := &recorder{}
			s := NewServer("localhost:0", "lan")
			s.SetLeases([]dhcp4d.Lease{
				{
					Hostname: "testtarget",
					Addr:     test.ip,
				},
			})
			m := new(dns.Msg)
			m.SetQuestion(test.question, dns.TypePTR)
			s.Mux.ServeDNS(r, m)
			if got, want := len(r.response.Answer), 1; got != want {
				t.Fatalf("unexpected number of answers: got %d, want %d", got, want)
			}
			a := r.response.Answer[0]
			if _, ok := a.(*dns.PTR); !ok {
				t.Fatalf("unexpected response type: got %T, want dns.PTR", a)
			}
			if got, want := a.(*dns.PTR).Ptr, "testtarget.lan."; got != want {
				t.Fatalf("unexpected response record: got %q, want %q", got, want)
			}
		})
	}

	t.Run("no leases", func(t *testing.T) {
		r := &recorder{}
		s := NewServer("localhost:0", "lan")
		m := new(dns.Msg)
		m.SetQuestion("254.255.31.172.in-addr.arpa.", dns.TypePTR)
		s.Mux.ServeDNS(r, m)
		if got, want := r.response.Rcode, dns.RcodeNameError; got != want {
			t.Fatalf("unexpected rcode: got %v, want %v", got, want)
		}
	})

}

func resolveTestTarget(s *Server, name string, want net.IP) error {
	m := new(dns.Msg)
	typ := dns.TypeA
	if want.To4() == nil {
		typ = dns.TypeAAAA
	}
	m.SetQuestion(name, typ)
	r := &recorder{}
	s.Mux.ServeDNS(r, m)
	if r.response == nil {
		return fmt.Errorf("nil response")
	}
	if got, want := len(r.response.Answer), 1; got != want {
		return fmt.Errorf("unexpected number of answers: got %d, want %d", got, want)
	}
	a := r.response.Answer[0]
	if typ == dns.TypeA {
		if _, ok := a.(*dns.A); !ok {
			return fmt.Errorf("unexpected response type: got %T, want dns.A", a)
		}
		if got := a.(*dns.A).A; !got.Equal(want) {
			return fmt.Errorf("unexpected response IP: got %v, want %v", got, want)
		}
	} else {
		if _, ok := a.(*dns.AAAA); !ok {
			return fmt.Errorf("unexpected response type: got %T, want dns.A", a)
		}
		if got := a.(*dns.AAAA).AAAA; !got.Equal(want) {
			return fmt.Errorf("unexpected response IP: got %v, want %v", got, want)
		}
	}
	return nil
}

// TODO: multiple questions

func TestUppercase(t *testing.T) {
	s := NewServer("127.0.0.2:0", "lan")
	s.SetLeases([]dhcp4d.Lease{
		{
			Hostname: "UPPERCASE",
			Addr:     net.IP{192, 168, 42, 23},
		},
	})
	for _, casing := range []string{
		"UPPERCASE",
		"uppercase",
		"upperCase",
	} {
		if err := resolveTestTarget(s, casing+".lan.", net.ParseIP("192.168.42.23")); err != nil {
			t.Fatal(err)
		}
	}
}

func TestSubname(t *testing.T) {
	r := &recorder{}
	s := NewServer("127.0.0.2:0", "lan")
	s.SetLeases([]dhcp4d.Lease{
		{
			Hostname: "testtarget",
			Addr:     net.IP{192, 168, 42, 23},
		},
	})

	t.Run("testtarget.lan.", func(t *testing.T) {
		if err := resolveTestTarget(s, "testtarget.lan.", net.ParseIP("192.168.42.23")); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("sub.testtarget.lan.", func(t *testing.T) {
		m := new(dns.Msg)
		m.SetQuestion("notfound.lan.", dns.TypeA)
		s.Mux.ServeDNS(r, m)
		if got, want := r.response.Rcode, dns.RcodeNameError; got != want {
			t.Fatalf("unexpected rcode: got %v, want %v", got, want)
		}
	})

	setSubname := func(ip, remoteAddr string) {
		val := url.Values{
			"host": []string{"sub"},
			"ip":   []string{ip},
		}
		req := httptest.NewRequest("POST", "/dyndns", strings.NewReader(val.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.RemoteAddr = remoteAddr
		rec := httptest.NewRecorder()
		s.DyndnsHandler(rec, req)
		resp := rec.Result()
		if got, want := resp.StatusCode, http.StatusOK; got != want {
			body, _ := ioutil.ReadAll(resp.Body)
			t.Fatalf("POST /dyndns: unexpected HTTP status: got %v, want %v (%q)", resp.Status, want, string(body))
		}
	}
	const ip = "fdf5:3606:2a21:1341:b26e:bfff:fe30:504b"
	setSubname(ip, "192.168.42.23:1234")

	for _, name := range []string{
		"sub.testtarget.lan.",
		"sub.testtarget.",
	} {
		t.Run(name+" (after dyndns)", func(t *testing.T) {
			if err := resolveTestTarget(s, name, net.ParseIP(ip)); err != nil {
				t.Fatal(err)
			}
		})
	}

	t.Run("Hostname", func(t *testing.T) {
		hostname, err := os.Hostname()
		if err != nil {
			t.Skipf("os.Hostname: %v", err)
		}
		if err := resolveTestTarget(s, hostname+".lan.", net.ParseIP("127.0.0.2")); err != nil {
			t.Fatal(err)
		}
		setSubname(ip, "127.0.0.2:1234")
		if err := resolveTestTarget(s, "sub."+hostname+".lan.", net.ParseIP(ip)); err != nil {
			t.Fatal(err)
		}
	})
}
