package dns

import (
	"log"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"router7/internal/dhcp4d"

	"golang.org/x/time/rate"

	"github.com/miekg/dns"
)

type Server struct {
	*dns.Server
	client    *dns.Client
	domain    string
	upstream  string
	sometimes *rate.Limiter

	mu           sync.Mutex
	hostname, ip string
	hostsByName  map[string]string
	hostsByIP    map[string]string
}

func NewServer(addr, domain string) *Server {
	hostname, _ := os.Hostname()
	ip, _, _ := net.SplitHostPort(addr)
	server := &Server{
		Server:    &dns.Server{Addr: addr, Net: "udp"},
		client:    &dns.Client{},
		domain:    domain,
		upstream:  "8.8.8.8:53",
		sometimes: rate.NewLimiter(rate.Every(1*time.Second), 1), // at most once per second
		hostname:  hostname,
		ip:        ip,
	}
	server.initHostsLocked()
	dns.HandleFunc(".", server.handleRequest)
	return server
}

func (s *Server) initHostsLocked() {
	s.hostsByName = make(map[string]string)
	s.hostsByIP = make(map[string]string)
	if s.hostname != "" && s.ip != "" {
		s.hostsByName[s.hostname] = s.ip
		s.hostsByIP[s.ip] = s.hostname
	}
}

func (s *Server) hostByName(n string) (string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.hostsByName[n]
	return r, ok
}

func (s *Server) hostByIP(n string) (string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.hostsByIP[n]
	return r, ok
}

func (s *Server) SetLeases(leases []dhcp4d.Lease) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.initHostsLocked()
	for _, l := range leases {
		s.hostsByName[l.Hostname] = l.Addr.String()
		if rev, err := dns.ReverseAddr(l.Addr.String()); err == nil {
			s.hostsByIP[rev] = l.Hostname
		}
	}
}

func mustParseCIDR(s string) *net.IPNet {
	_, ipnet, err := net.ParseCIDR(s)
	if err != nil {
		panic(err)
	}
	return ipnet
}

var (
	localNets = []*net.IPNet{
		// reversed: https://tools.ietf.org/html/rfc1918#section-3
		mustParseCIDR("10.0.0.0/8"),
		mustParseCIDR("172.16.0.0/12"),
		mustParseCIDR("192.168.0.0/16"),
	}
)

func reverse(ss []string) {
	last := len(ss) - 1
	for i := 0; i < len(ss)/2; i++ {
		ss[i], ss[last-i] = ss[last-i], ss[i]
	}
}

func isLocalInAddrArpa(q string) bool {
	if !strings.HasSuffix(q, ".in-addr.arpa.") {
		return false
	}
	parts := strings.Split(strings.TrimSuffix(q, ".in-addr.arpa."), ".")
	reverse(parts)
	ip := net.ParseIP(strings.Join(parts, "."))
	if ip == nil {
		return false
	}
	var local bool
	for _, l := range localNets {
		if l.Contains(ip) {
			local = true
			break
		}
	}
	return local
}

// TODO: require search domains to be present, then use HandleFunc("lan.", internalName)
func (s *Server) handleRequest(w dns.ResponseWriter, r *dns.Msg) {
	if len(r.Question) == 1 { // TODO: answer all questions we can answer
		q := r.Question[0]
		if q.Qtype == dns.TypeA && q.Qclass == dns.ClassINET {
			name := strings.TrimSuffix(q.Name, ".")
			name = strings.TrimSuffix(name, "."+s.domain)

			if !strings.Contains(name, ".") {
				if host, ok := s.hostByName(name); ok {
					rr, err := dns.NewRR(q.Name + " 3600 IN A " + host)
					if err != nil {
						log.Fatal(err)
					}
					m := new(dns.Msg)
					m.SetReply(r)
					m.Answer = append(m.Answer, rr)
					w.WriteMsg(m)
					return
				}
			}
		}
		if q.Qtype == dns.TypePTR && q.Qclass == dns.ClassINET {
			if isLocalInAddrArpa(q.Name) {
				if host, ok := s.hostByIP(q.Name); ok {
					rr, err := dns.NewRR(q.Name + " 3600 IN PTR " + host + "." + s.domain)
					if err != nil {
						log.Fatal(err)
					}
					m := new(dns.Msg)
					m.SetReply(r)
					m.Answer = append(m.Answer, rr)
					w.WriteMsg(m)
					return
				}
			}
		}
	}

	in, _, err := s.client.Exchange(r, s.upstream)
	if err != nil {
		if s.sometimes.Allow() {
			log.Printf("resolving %v failed: %v", r.Question, err)
		}
		return // DNS has no reply for resolving errors
	}
	w.WriteMsg(in)
}
