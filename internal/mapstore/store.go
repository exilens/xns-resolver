package mapstore

import (
	"encoding/binary"
	"errors"
	"fmt"
	"hash/fnv"
	"math"
	"net/netip"
	"strings"
	"sync"

	"tsr/internal/config"
)

type Entry struct {
	IP       netip.Addr
	Host     string
	Route    config.RuntimeRoute
	LastPort uint16
}

type Store struct {
	mu       sync.RWMutex
	prefix   netip.Prefix
	gateway  netip.Addr
	routes   []config.RuntimeRoute
	aliases  []config.RuntimeAlias
	byHost   map[string]Entry
	byIP     map[netip.Addr]Entry
	capacity uint32
}

func New(prefix netip.Prefix, gateway netip.Addr, routes []config.RuntimeRoute, aliases []config.RuntimeAlias) (*Store, error) {
	ones := prefix.Bits()
	if ones < 16 || ones > 30 {
		return nil, errors.New("net.cidr must have prefix length between /16 and /30")
	}
	capacity := uint32(1) << uint32(32-ones)
	if capacity < 4 {
		return nil, errors.New("net.cidr has no usable host addresses")
	}
	return &Store{
		prefix:   prefix.Masked(),
		gateway:  gateway,
		routes:   append([]config.RuntimeRoute(nil), routes...),
		aliases:  append([]config.RuntimeAlias(nil), aliases...),
		byHost:   map[string]Entry{},
		byIP:     map[netip.Addr]Entry{},
		capacity: capacity,
	}, nil
}

func (s *Store) Resolve(host string) (Entry, bool, error) {
	host = normalizeHost(host)
	host = s.canonicalHost(host)
	route, ok := s.MatchRoute(host)
	if !ok {
		return Entry{}, false, nil
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if e, ok := s.byHost[host]; ok {
		return e, true, nil
	}

	ip, err := s.allocateLocked(host)
	if err != nil {
		return Entry{}, true, err
	}
	e := Entry{IP: ip, Host: host, Route: route}
	s.byHost[host] = e
	s.byIP[ip] = e
	return e, true, nil
}

func (s *Store) canonicalHost(host string) string {
	for _, alias := range s.aliases {
		for _, domain := range alias.Domains {
			base := strings.TrimPrefix(domain, ".")
			if host == base {
				return strings.TrimPrefix(alias.Target, ".")
			}
			if strings.HasSuffix(host, domain) {
				return strings.TrimSuffix(host, domain) + alias.Target
			}
		}
	}
	return host
}

func (s *Store) LookupIP(ip netip.Addr) (Entry, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	e, ok := s.byIP[ip]
	return e, ok
}

func (s *Store) MatchRoute(host string) (config.RuntimeRoute, bool) {
	host = normalizeHost(host)
	for _, r := range s.routes {
		for _, domain := range r.Domains {
			if host == strings.TrimPrefix(domain, ".") || strings.HasSuffix(host, domain) {
				return r, true
			}
		}
	}
	return config.RuntimeRoute{}, false
}

func (s *Store) allocateLocked(host string) (netip.Addr, error) {
	start := hashHost(host) % s.capacity
	for i := uint32(0); i < s.capacity; i++ {
		offset := (start + i) % s.capacity
		ip := addIPv4(s.prefix.Addr(), offset)
		if !s.usable(ip) {
			continue
		}
		if _, exists := s.byIP[ip]; !exists {
			return ip, nil
		}
	}
	return netip.Addr{}, fmt.Errorf("address pool %s is exhausted", s.prefix)
}

func (s *Store) usable(ip netip.Addr) bool {
	if !s.prefix.Contains(ip) || ip == s.gateway {
		return false
	}
	base := ipv4ToUint32(s.prefix.Addr())
	v := ipv4ToUint32(ip)
	if v == base {
		return false
	}
	if s.prefix.Bits() < 31 && v == base+s.capacity-1 {
		return false
	}
	return true
}

func normalizeHost(s string) string {
	return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(s), "."))
}

func hashHost(host string) uint32 {
	h := fnv.New32a()
	_, _ = h.Write([]byte(host))
	return h.Sum32()
}

func addIPv4(base netip.Addr, offset uint32) netip.Addr {
	return uint32ToIPv4(ipv4ToUint32(base) + offset)
}

func ipv4ToUint32(addr netip.Addr) uint32 {
	a := addr.As4()
	return binary.BigEndian.Uint32(a[:])
}

func uint32ToIPv4(v uint32) netip.Addr {
	if v == math.MaxUint32 {
		return netip.AddrFrom4([4]byte{255, 255, 255, 255})
	}
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], v)
	return netip.AddrFrom4(b)
}
