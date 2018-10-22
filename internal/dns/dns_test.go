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
	"net"
	"os"
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
	s.upstream = "266.266.266.266:53"
	m := new(dns.Msg)
	m.SetQuestion("foo.invalid.", dns.TypeA)
	s.Mux.ServeDNS(r, m)
	if r.response != nil {
		t.Fatalf("r.response unexpectedly not nil: %v", r.response)
	}
}

func TestDHCP(t *testing.T) {
	r := &recorder{}
	s := NewServer("localhost:0", "lan")
	s.SetLeases([]dhcp4d.Lease{
		{
			Hostname: "xps",
			Addr:     net.IP{192, 168, 42, 23},
		},
	})

	resolveXps := func(t *testing.T) {
		m := new(dns.Msg)
		m.SetQuestion("xps.lan.", dns.TypeA)
		s.Mux.ServeDNS(r, m)
		if got, want := len(r.response.Answer), 1; got != want {
			t.Fatalf("unexpected number of answers: got %d, want %d", got, want)
		}
		a := r.response.Answer[0]
		if _, ok := a.(*dns.A); !ok {
			t.Fatalf("unexpected response type: got %T, want dns.A", a)
		}
		if got, want := a.(*dns.A).A, net.ParseIP("192.168.42.23"); !got.Equal(want) {
			t.Fatalf("unexpected response IP: got %v, want %v", got, want)
		}
	}
	t.Run("xps.lan.", resolveXps)

	expired := time.Now().Add(-1 * time.Second)
	s.SetLeases([]dhcp4d.Lease{
		{
			Hostname: "xps",
			Addr:     net.IP{192, 168, 42, 23},
			Expiry:   time.Now().Add(1 * time.Minute),
		},
		{
			Hostname: "xps",
			Addr:     net.IP{192, 168, 42, 150},
			Expiry:   expired,
		},
	})

	t.Run("xps.lan. (expired)", resolveXps)

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
			Hostname: hostname,
			Addr:     net.IP{192, 168, 42, 23},
		},
	})

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
					Hostname: "xps",
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
			if got, want := a.(*dns.PTR).Ptr, "xps.lan."; got != want {
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

// TODO: multiple questions
