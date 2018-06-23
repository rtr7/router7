package dns

import (
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"router7/internal/dhcp4d"

	"github.com/miekg/dns"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"golang.org/x/time/rate"
)

type Server struct {
	*dns.Server
	client    *dns.Client
	domain    string
	upstream  string
	sometimes *rate.Limiter
	prom      struct {
		registry  *prometheus.Registry
		queries   prometheus.Counter
		upstream  *prometheus.CounterVec
		questions prometheus.Histogram
	}

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
	server.prom.registry = prometheus.NewRegistry()

	server.prom.queries = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "dns_queries",
		Help: "Number of DNS queries received",
	})
	server.prom.registry.MustRegister(server.prom.queries)

	server.prom.upstream = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "dns_upstream",
			Help: "Which upstream answered which DNS query",
		},
		[]string{"upstream"},
	)
	server.prom.registry.MustRegister(server.prom.upstream)

	server.prom.questions = prometheus.NewHistogram(prometheus.HistogramOpts{
		Name:    "dns_questions",
		Help:    "Number of questions in each DNS request",
		Buckets: prometheus.LinearBuckets(0, 1, 10),
	})
	server.prom.registry.MustRegister(server.prom.questions)

	server.prom.registry.MustRegister(prometheus.NewGoCollector())
	server.initHostsLocked()
	dns.HandleFunc(".", server.handleRequest)
	return server
}

func (s *Server) initHostsLocked() {
	s.hostsByName = make(map[string]string)
	s.hostsByIP = make(map[string]string)
	if s.hostname != "" && s.ip != "" {
		s.hostsByName[s.hostname] = s.ip
		if rev, err := dns.ReverseAddr(s.ip); err == nil {
			s.hostsByIP[rev] = s.hostname
		}
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

func (s *Server) PrometheusHandler() http.Handler {
	return promhttp.HandlerFor(s.prom.registry, promhttp.HandlerOpts{})
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
		// loopback: https://tools.ietf.org/html/rfc3330#section-2
		mustParseCIDR("127.0.0.0/8"),
		// loopback: https://tools.ietf.org/html/rfc3513#section-2.4
		mustParseCIDR("::1/128"),

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
	s.prom.queries.Inc()
	s.prom.questions.Observe(float64(len(r.Question)))
	if len(r.Question) == 1 { // TODO: answer all questions we can answer
		q := r.Question[0]
		if q.Qtype == dns.TypeA && q.Qclass == dns.ClassINET {
			name := strings.TrimSuffix(q.Name, ".")
			name = strings.TrimSuffix(name, "."+s.domain)

			if !strings.Contains(name, ".") {
				s.prom.upstream.WithLabelValues("local").Inc()
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
				// Send an authoritative NXDOMAIN for local names:
				m := new(dns.Msg)
				m.SetReply(r)
				m.SetRcode(r, dns.RcodeNameError)
				w.WriteMsg(m)
				return
			}
		}
		if q.Qtype == dns.TypePTR && q.Qclass == dns.ClassINET {
			if isLocalInAddrArpa(q.Name) {
				s.prom.upstream.WithLabelValues("local").Inc()
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
				// Send an authoritative NXDOMAIN for local names:
				m := new(dns.Msg)
				m.SetReply(r)
				m.SetRcode(r, dns.RcodeNameError)
				w.WriteMsg(m)
				return
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
	s.prom.upstream.WithLabelValues("DNS").Inc()
}
