package dns

import (
	"log"
	"strings"
	"time"

	"router7/internal/dhcp4d"

	"golang.org/x/time/rate"

	"github.com/miekg/dns"
)

type Server struct {
	*dns.Server
	client      *dns.Client
	domain      string
	upstream    string
	sometimes   *rate.Limiter
	hostsByName map[string]string
	hostsByIP   map[string]string
}

func NewServer(addr, domain string) *Server {
	server := &Server{
		Server:      &dns.Server{Addr: addr, Net: "udp"},
		client:      &dns.Client{},
		domain:      domain,
		upstream:    "8.8.8.8:53",
		sometimes:   rate.NewLimiter(rate.Every(1*time.Second), 1), // at most once per second
		hostsByName: make(map[string]string),
		hostsByIP:   make(map[string]string),
	}
	dns.HandleFunc(".", server.handleRequest)
	return server
}

func (s *Server) SetLeases(leases []dhcp4d.Lease) {
	for _, l := range leases {
		s.hostsByName[l.Hostname] = l.Addr.String()
		if rev, err := dns.ReverseAddr(l.Addr.String()); err == nil {
			s.hostsByIP[rev] = l.Hostname
		}
	}
}

// TODO: is handleRequest called in more than one goroutine at a time?
// TODO: require search domains to be present, then use HandleFunc("lan.", internalName)
func (s *Server) handleRequest(w dns.ResponseWriter, r *dns.Msg) {
	if len(r.Question) == 1 { // TODO: answer all questions we can answer
		q := r.Question[0]
		if q.Qtype == dns.TypeA && q.Qclass == dns.ClassINET {
			name := strings.TrimSuffix(q.Name, ".")
			name = strings.TrimSuffix(name, "."+s.domain)

			if !strings.Contains(name, ".") {
				if host, ok := s.hostsByName[name]; ok {
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
			if strings.HasSuffix(q.Name, "168.192.in-addr.arpa.") {
				if host, ok := s.hostsByIP[q.Name]; ok {
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
