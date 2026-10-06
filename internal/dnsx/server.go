package dnsx

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/miekg/dns"

	"github.com/exilens/xns-resolver/internal/mapstore"
)

const (
	ownerDNSPort       = 53
	ownerDNSTimeout    = 15 * time.Second
	upstreamDNSTimeout = 5 * time.Second
)

type Transport interface {
	DialContext(context.Context, string, uint16) (net.Conn, error)
}

type Server struct {
	addr      string
	store     *mapstore.Store
	transport Transport
	upstream  string
	udp       *dns.Server
	tcp       *dns.Server
}

func New(addr string, store *mapstore.Store, transport Transport, upstream string) *Server {
	return &Server{addr: addr, store: store, transport: transport, upstream: upstream}
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
	if s.upstream == "" {
		log.Print("non-XNS DNS forwarding disabled")
	} else {
		log.Printf("non-XNS DNS upstream: %s", s.upstream)
	}
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
	resp.RecursionAvailable = s.upstream != ""
	defer func() { writeReply(w, req, resp) }()

	if req.Opcode != dns.OpcodeQuery {
		resp.Rcode = dns.RcodeNotImplemented
		return
	}
	// Reject ambiguous requests rather than risk forwarding an XNS question
	// alongside an ordinary DNS question.
	if len(req.Question) != 1 {
		resp.Rcode = dns.RcodeFormatError
		return
	}
	q := req.Question[0]
	host := strings.TrimSuffix(q.Name, ".")
	lowerHost := strings.ToLower(host)
	if lowerHost != "xns" && !strings.HasSuffix(lowerHost, ".xns") {
		if s.upstream == "" {
			resp.Rcode = dns.RcodeRefused
			return
		}
		reply, err := s.forwardUpstream(req, w.RemoteAddr().Network())
		if err != nil {
			log.Printf("upstream DNS failed for %s: %v", host, err)
			resp.Rcode = dns.RcodeServerFailure
			return
		}
		resp = reply
		return
	}

	resp.Authoritative = true
	if q.Qclass != dns.ClassINET {
		resp.Rcode = dns.RcodeRefused
		return
	}
	entry, matched, err := s.store.Resolve(host)
	if err != nil {
		log.Printf("dns mapping failed for %s: %v", host, err)
		resp.Rcode = dns.RcodeServerFailure
		return
	}
	if !matched {
		resp.Rcode = dns.RcodeNameError
		return
	}

	switch q.Qtype {
	case dns.TypeA:
		resp.Answer = append(resp.Answer, &dns.A{
			Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: entry.TTL},
			A:   net.IP(entry.IP.AsSlice()).To4(),
		})
		log.Printf("dns map %s -> %s -> %s", host, entry.IP, entry.Destination)
	case dns.TypeAAAA:
		// Return a successful empty answer so clients may continue with A.
	default:
		reply, err := s.forward(req, q, entry)
		if err != nil {
			log.Printf("dns forward failed for %s %s via %s: %v", host, qtype(q.Qtype), entry.Destination, err)
			resp.Rcode = dns.RcodeServerFailure
			return
		}
		resp.Answer = append(resp.Answer, nonAddressRRs(reply.Answer)...)
		resp.Ns = append(resp.Ns, nonAddressRRs(reply.Ns)...)
		resp.Extra = append(resp.Extra, nonAddressRRs(reply.Extra)...)
		resp.Rcode = reply.Rcode
	}
}

func writeReply(w dns.ResponseWriter, req, resp *dns.Msg) {
	resp.Compress = true
	if strings.HasPrefix(w.RemoteAddr().Network(), "udp") {
		size := dns.MinMsgSize
		if opt := req.IsEdns0(); opt != nil && int(opt.UDPSize()) > size {
			size = int(opt.UDPSize())
		}
		resp.Truncate(size)
	}
	if err := w.WriteMsg(resp); err != nil {
		log.Printf("dns write response: %v", err)
	}
}

func (s *Server) forwardUpstream(req *dns.Msg, network string) (*dns.Msg, error) {
	ctx, cancel := context.WithTimeout(context.Background(), upstreamDNSTimeout)
	defer cancel()
	netw := "udp"
	if strings.HasPrefix(network, "tcp") {
		netw = "tcp"
	}
	client := &dns.Client{Net: netw, Timeout: upstreamDNSTimeout}
	reply, _, err := client.ExchangeContext(ctx, req, s.upstream)
	if err != nil {
		return nil, err
	}
	if reply.Truncated && netw == "udp" {
		client.Net = "tcp"
		reply, _, err = client.ExchangeContext(ctx, req, s.upstream)
	}
	return reply, err
}

func (s *Server) forward(req *dns.Msg, q dns.Question, entry mapstore.Entry) (*dns.Msg, error) {
	if s.transport == nil {
		return nil, errors.New("transport is required")
	}

	query := new(dns.Msg)
	query.SetQuestion(q.Name, q.Qtype)
	query.Question[0].Qclass = q.Qclass
	query.RecursionDesired = req.RecursionDesired
	query.CheckingDisabled = req.CheckingDisabled
	query.AuthenticatedData = req.AuthenticatedData
	query.Extra = append([]dns.RR(nil), req.Extra...)

	ctx, cancel := context.WithTimeout(context.Background(), ownerDNSTimeout)
	defer cancel()

	conn, err := s.transport.DialContext(ctx, entry.Destination, ownerDNSPort)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}
	dnsConn := &dns.Conn{Conn: conn}
	if err := dnsConn.WriteMsg(query); err != nil {
		return nil, err
	}
	reply, err := dnsConn.ReadMsg()
	if err != nil {
		return nil, err
	}
	reply.Id = req.Id
	return reply, nil
}

func nonAddressRRs(records []dns.RR) []dns.RR {
	out := records[:0]
	for _, record := range records {
		switch record.Header().Rrtype {
		case dns.TypeA, dns.TypeAAAA:
			continue
		default:
			out = append(out, record)
		}
	}
	return out
}

func qtype(value uint16) string {
	if name := dns.TypeToString[value]; name != "" {
		return name
	}
	return strconv.Itoa(int(value))
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
