package config

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"os"
	"sort"
	"strings"

	"github.com/BurntSushi/toml"
)

const DefaultConfig = `[dns]
listen = "10.203.0.1:53"

[net]
tun = "tsr0"
cidr = "10.203.0.0/16"
gateway = "10.203.0.1"
mtu = 1500

[[route]]
name = "tor"
domains = [".onion"]
proxy = "socks5://127.0.0.1:9050"

[[alias]]
target = ".onion"
domains = [".onio", ".onionn"]

[[route]]
name = "i2p"
domains = [".i2p", ".b32.i2p"]
proxy = "http://127.0.0.1:4444"
`

type Config struct {
	DNS     DNSConfig `toml:"dns"`
	Net     NetConfig `toml:"net"`
	Routes  []Route   `toml:"route"`
	Aliases []Alias   `toml:"alias"`
}

type DNSConfig struct {
	Listen string `toml:"listen"`
}

type NetConfig struct {
	TUN     string `toml:"tun"`
	CIDR    string `toml:"cidr"`
	Gateway string `toml:"gateway"`
	MTU     uint32 `toml:"mtu"`
}

type Route struct {
	Name    string   `toml:"name"`
	Domains []string `toml:"domains"`
	Proxy   string   `toml:"proxy"`
}

type Alias struct {
	Target  string   `toml:"target"`
	Domains []string `toml:"domains"`
}

type Runtime struct {
	Config
	ListenAddr *net.UDPAddr
	Prefix     netip.Prefix
	Gateway    netip.Addr
	Routes     []RuntimeRoute
	Aliases    []RuntimeAlias
}

type RuntimeRoute struct {
	Name    string
	Domains []string
	Proxy   *url.URL
}

type RuntimeAlias struct {
	Target  string
	Domains []string
}

func Load(path string) (*Runtime, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cfg Config
	if _, err := toml.Decode(string(b), &cfg); err != nil {
		return nil, err
	}
	return Validate(cfg)
}

func Generate(path string) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.WriteString(DefaultConfig)
	return err
}

func Validate(cfg Config) (*Runtime, error) {
	applyDefaults(&cfg)

	listenAddr, err := net.ResolveUDPAddr("udp", cfg.DNS.Listen)
	if err != nil {
		return nil, fmt.Errorf("dns.listen: %w", err)
	}

	prefix, err := netip.ParsePrefix(cfg.Net.CIDR)
	if err != nil {
		return nil, fmt.Errorf("net.cidr: %w", err)
	}
	prefix = prefix.Masked()
	if !prefix.Addr().Is4() {
		return nil, errors.New("net.cidr must be IPv4")
	}

	gateway, err := netip.ParseAddr(cfg.Net.Gateway)
	if err != nil {
		return nil, fmt.Errorf("net.gateway: %w", err)
	}
	if !gateway.Is4() || !prefix.Contains(gateway) {
		return nil, errors.New("net.gateway must be an IPv4 address inside net.cidr")
	}

	if cfg.Net.TUN == "" {
		return nil, errors.New("net.tun is required")
	}
	if listenAddr.Port != 53 {
		return nil, errors.New("dns.listen must use port 53 on the TSR gateway address")
	}
	listenIP, ok := netip.AddrFromSlice(listenAddr.IP)
	if !ok || listenIP.Unmap() != gateway {
		return nil, errors.New("dns.listen must bind to net.gateway")
	}

	routes, err := validateRoutes(cfg.Routes)
	if err != nil {
		return nil, err
	}
	aliases, err := validateAliases(cfg.Aliases, routes)
	if err != nil {
		return nil, err
	}

	return &Runtime{
		Config:     cfg,
		ListenAddr: listenAddr,
		Prefix:     prefix,
		Gateway:    gateway,
		Routes:     routes,
		Aliases:    aliases,
	}, nil
}

func applyDefaults(cfg *Config) {
	if cfg.DNS.Listen == "" {
		cfg.DNS.Listen = "10.203.0.1:53"
	}
	if cfg.Net.TUN == "" {
		cfg.Net.TUN = "tsr0"
	}
	if cfg.Net.CIDR == "" {
		cfg.Net.CIDR = "10.203.0.0/16"
	}
	if cfg.Net.Gateway == "" {
		cfg.Net.Gateway = "10.203.0.1"
	}
	if cfg.Net.MTU == 0 {
		cfg.Net.MTU = 1500
	}
}

func validateRoutes(in []Route) ([]RuntimeRoute, error) {
	if len(in) == 0 {
		return nil, errors.New("at least one route is required")
	}
	seenNames := map[string]struct{}{}
	out := make([]RuntimeRoute, 0, len(in))
	seenDomains := map[string]string{}

	for i, r := range in {
		name := strings.TrimSpace(r.Name)
		if name == "" {
			return nil, fmt.Errorf("route[%d].name is required", i)
		}
		if _, ok := seenNames[name]; ok {
			return nil, fmt.Errorf("route name %q is duplicated", name)
		}
		seenNames[name] = struct{}{}

		u, err := url.Parse(r.Proxy)
		if err != nil {
			return nil, fmt.Errorf("route[%d].proxy: %w", i, err)
		}
		if u.Scheme != "socks5" && u.Scheme != "http" {
			return nil, fmt.Errorf("route[%d].proxy must use socks5:// or http://", i)
		}
		if u.Host == "" {
			return nil, fmt.Errorf("route[%d].proxy host is required", i)
		}

		domains, err := validateDomains(i, name, r.Domains, seenDomains)
		if err != nil {
			return nil, err
		}

		out = append(out, RuntimeRoute{Name: name, Domains: domains, Proxy: u})
	}

	sort.Slice(out, func(i, j int) bool {
		a, b := out[i].LongestDomain(), out[j].LongestDomain()
		if len(a) == len(b) {
			return a < b
		}
		return len(a) > len(b)
	})
	return out, nil
}

func validateAliases(in []Alias, routes []RuntimeRoute) ([]RuntimeAlias, error) {
	routeDomains := map[string]struct{}{}
	for _, r := range routes {
		for _, domain := range r.Domains {
			routeDomains[domain] = struct{}{}
		}
	}

	out := make([]RuntimeAlias, 0, len(in))
	seenAliases := map[string]string{}
	for i, a := range in {
		target := normalizeDomain(a.Target)
		if _, ok := routeDomains[target]; !ok {
			return nil, fmt.Errorf("alias[%d].target %q is not a configured route domain", i, target)
		}
		if len(a.Domains) == 0 {
			return nil, fmt.Errorf("alias[%d].domains must contain at least one domain", i)
		}

		domains := make([]string, 0, len(a.Domains))
		localSeen := map[string]struct{}{}
		for j, raw := range a.Domains {
			domain := normalizeDomain(raw)
			if domain == "." {
				return nil, fmt.Errorf("alias[%d].domains[%d] cannot match every domain", i, j)
			}
			if domain == target {
				return nil, fmt.Errorf("alias[%d].domains[%d] duplicates target %q", i, j, target)
			}
			if _, ok := routeDomains[domain]; ok {
				return nil, fmt.Errorf("alias domain %q duplicates a route domain", domain)
			}
			if _, ok := localSeen[domain]; ok {
				return nil, fmt.Errorf("alias[%d].domains[%d] duplicates %q", i, j, domain)
			}
			if owner, ok := seenAliases[domain]; ok {
				return nil, fmt.Errorf("alias domain %q is duplicated by targets %q and %q", domain, owner, target)
			}
			localSeen[domain] = struct{}{}
			seenAliases[domain] = target
			domains = append(domains, domain)
		}
		sort.Slice(domains, func(i, j int) bool {
			if len(domains[i]) == len(domains[j]) {
				return domains[i] < domains[j]
			}
			return len(domains[i]) > len(domains[j])
		})
		out = append(out, RuntimeAlias{Target: target, Domains: domains})
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i].LongestDomain(), out[j].LongestDomain()
		if len(a) == len(b) {
			return a < b
		}
		return len(a) > len(b)
	})
	return out, nil
}

func validateDomains(routeIndex int, routeName string, raw []string, seen map[string]string) ([]string, error) {
	if len(raw) == 0 {
		return nil, fmt.Errorf("route[%d].domains must contain at least one domain", routeIndex)
	}
	domains := make([]string, 0, len(raw))
	localSeen := map[string]struct{}{}
	for j, d := range raw {
		domain := normalizeDomain(d)
		if domain == "." {
			return nil, fmt.Errorf("route[%d].domains[%d] cannot match every domain", routeIndex, j)
		}
		if _, ok := localSeen[domain]; ok {
			return nil, fmt.Errorf("route[%d].domains[%d] duplicates %q", routeIndex, j, domain)
		}
		if owner, ok := seen[domain]; ok {
			return nil, fmt.Errorf("route domain %q is duplicated by routes %q and %q", domain, owner, routeName)
		}
		localSeen[domain] = struct{}{}
		seen[domain] = routeName
		domains = append(domains, domain)
	}
	sort.Slice(domains, func(i, j int) bool {
		if len(domains[i]) == len(domains[j]) {
			return domains[i] < domains[j]
		}
		return len(domains[i]) > len(domains[j])
	})
	return domains, nil
}

func (r RuntimeRoute) LongestDomain() string {
	if len(r.Domains) == 0 {
		return ""
	}
	return r.Domains[0]
}

func (a RuntimeAlias) LongestDomain() string {
	if len(a.Domains) == 0 {
		return ""
	}
	return a.Domains[0]
}

func normalizeDomain(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	s = strings.TrimSuffix(s, ".")
	if s == "" {
		return "."
	}
	if !strings.HasPrefix(s, ".") {
		s = "." + s
	}
	return s
}
