package dnsx

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"strings"
	"time"

	"github.com/miekg/dns"

	"tsr/internal/mapstore"
)

type Server struct {
	addr  string
	store *mapstore.Store
	udp   *dns.Server
	tcp   *dns.Server
}

func New(addr string, store *mapstore.Store) *Server {
	return &Server{addr: addr, store: store}
}

func (s *Server) Start() error {
	mux := dns.NewServeMux()
	mux.HandleFunc(".", s.handle)
	s.udp = &dns.Server{Addr: s.addr, Net: "udp", Handler: mux}
	s.tcp = &dns.Server{Addr: s.addr, Net: "tcp", Handler: mux}

	errc := make(chan error, 2)
	go func() { errc <- s.udp.ListenAndServe() }()
	go func() { errc <- s.tcp.ListenAndServe() }()

	select {
	case err := <-errc:
		if err != nil {
			_ = s.Shutdown(context.Background())
			return err
		}
	case <-time.After(150 * time.Millisecond):
	}
	log.Printf("dns listening on %s", s.addr)
	return nil
}

func (s *Server) Shutdown(ctx context.Context) error {
	var out error
	if s.udp != nil {
		if err := s.udp.ShutdownContext(ctx); err != nil {
			out = errors.Join(out, err)
		}
	}
	if s.tcp != nil {
		if err := s.tcp.ShutdownContext(ctx); err != nil {
			out = errors.Join(out, err)
		}
	}
	return out
}

func (s *Server) handle(w dns.ResponseWriter, req *dns.Msg) {
	resp := new(dns.Msg)
	resp.SetReply(req)
	resp.Authoritative = true
	resp.RecursionAvailable = false

	for _, q := range req.Question {
		host := strings.TrimSuffix(q.Name, ".")
		entry, matched, err := s.store.Resolve(host)
		if err != nil {
			log.Printf("dns mapping failed for %s: %v", host, err)
			resp.Rcode = dns.RcodeServerFailure
			break
		}
		if !matched {
			resp.Rcode = dns.RcodeNameError
			continue
		}

		switch q.Qtype {
		case dns.TypeA:
			resp.Answer = append(resp.Answer, &dns.A{
				Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
				A:   net.IP(entry.IP.AsSlice()).To4(),
			})
			log.Printf("dns map %s -> %s via %s", host, entry.IP, entry.Route.Name)
		case dns.TypeAAAA:
			// IPv6 is intentionally unsupported. Return a successful
			// empty answer so clients may continue with A.
		default:
			// TSR is authoritative only for address routing.
		}
	}

	if err := w.WriteMsg(resp); err != nil {
		log.Printf("dns write response: %v", err)
	}
}

func ListenHostPort(addr string) (string, int, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return "", 0, err
	}
	var p int
	if _, err := fmt.Sscanf(port, "%d", &p); err != nil {
		return "", 0, err
	}
	return host, p, nil
}
