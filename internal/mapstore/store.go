package mapstore

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/fnv"
	"math"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/exilens/xns-resolver/internal/xns"
)

const dnsTTL = 60

type Entry struct {
	IP          netip.Addr
	Name        string
	Destination string
	TTL         uint32
	ExpiresAt   time.Time
}

type Store struct {
	mu       sync.RWMutex
	prefix   netip.Prefix
	gateway  netip.Addr
	resolver *xns.Client
	byName   map[string]Entry
	byIP     map[netip.Addr]Entry
	capacity uint32
}

func New(prefix netip.Prefix, gateway netip.Addr, resolver *xns.Client) (*Store, error) {
	ones := prefix.Bits()
	if ones < 16 || ones > 30 {
		return nil, errors.New("virtual network must have prefix length between /16 and /30")
	}
	if resolver == nil {
		return nil, errors.New("resolver is required")
	}
	capacity := uint32(1) << uint32(32-ones)
	return &Store{
		prefix:   prefix.Masked(),
		gateway:  gateway,
		resolver: resolver,
		byName:   make(map[string]Entry),
		byIP:     make(map[netip.Addr]Entry),
		capacity: capacity,
	}, nil
}

func (s *Store) Resolve(host string) (Entry, bool, error) {
	name, ok := xns.NameFromHost(host)
	if !ok {
		return Entry{}, false, nil
	}

	now := time.Now()
	s.mu.RLock()
	entry, cached := s.byName[name]
	s.mu.RUnlock()
	if cached && now.Before(entry.ExpiresAt) {
		entry.TTL = ttl(entry.ExpiresAt, now)
		return entry, true, nil
	}

	result, err := s.resolver.Lookup(context.Background(), name)
	if errors.Is(err, xns.ErrNotFound) {
		s.remove(name)
		return Entry{}, false, nil
	}
	if err != nil {
		return Entry{}, true, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	entry, cached = s.byName[name]
	if !cached {
		ip, err := s.allocateLocked(name)
		if err != nil {
			return Entry{}, true, err
		}
		entry = Entry{IP: ip, Name: name}
	}
	entry.Destination = result.Destination
	entry.ExpiresAt = result.CacheUntil
	entry.TTL = ttl(entry.ExpiresAt, now)
	s.byName[name] = entry
	s.byIP[entry.IP] = entry
	return entry, true, nil
}

func (s *Store) LookupIP(ip netip.Addr) (Entry, bool) {
	s.mu.RLock()
	entry, ok := s.byIP[ip]
	s.mu.RUnlock()
	if !ok || !time.Now().Before(entry.ExpiresAt) {
		return Entry{}, false
	}
	return entry, true
}

func (s *Store) remove(name string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if entry, ok := s.byName[name]; ok {
		delete(s.byIP, entry.IP)
		delete(s.byName, name)
	}
}

func (s *Store) allocateLocked(name string) (netip.Addr, error) {
	start := hashName(name) % s.capacity
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
	value := ipv4ToUint32(ip)
	return value != base && (s.prefix.Bits() >= 31 || value != base+s.capacity-1)
}

func ttl(expires, now time.Time) uint32 {
	if !expires.After(now) {
		return 1
	}
	seconds := uint64(expires.Sub(now) / time.Second)
	if seconds == 0 {
		return 1
	}
	if seconds > dnsTTL {
		return dnsTTL
	}
	return uint32(seconds)
}

func hashName(name string) uint32 {
	h := fnv.New32a()
	_, _ = h.Write([]byte(strings.ToLower(name)))
	return h.Sum32()
}

func addIPv4(base netip.Addr, offset uint32) netip.Addr {
	return uint32ToIPv4(ipv4ToUint32(base) + offset)
}

func ipv4ToUint32(addr netip.Addr) uint32 {
	a := addr.As4()
	return binary.BigEndian.Uint32(a[:])
}

func uint32ToIPv4(value uint32) netip.Addr {
	if value == math.MaxUint32 {
		return netip.AddrFrom4([4]byte{255, 255, 255, 255})
	}
	var raw [4]byte
	binary.BigEndian.PutUint32(raw[:], value)
	return netip.AddrFrom4(raw)
}
