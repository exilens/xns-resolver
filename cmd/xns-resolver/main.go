package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/netip"
	"net/url"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/exilens/xns-resolver/internal/dnsx"
	"github.com/exilens/xns-resolver/internal/engine"
	"github.com/exilens/xns-resolver/internal/mapstore"
	"github.com/exilens/xns-resolver/internal/system"
	"github.com/exilens/xns-resolver/internal/xns"
)

const (
	defaultTorProxy = "socks5://127.0.0.1:9050"
	defaultTUN      = "xns0"
	defaultCIDR     = "10.204.0.0/16"
	defaultGateway  = "10.204.0.1"
	defaultDNS      = "10.204.0.1:53"
	defaultMTU      = 1500
)

type options struct {
	indexer  string
	torProxy string
	tun      string
	cidr     string
	gateway  string
	dns      string
	mtu      uint
}

func main() {
	log.SetFlags(log.LstdFlags | log.Lmsgprefix)
	log.SetPrefix("xns-resolver: ")

	if err := run(); err != nil {
		log.Printf("fatal: %v", err)
		os.Exit(1)
	}
}

func run() error {
	opts, err := parseArgs()
	if err != nil {
		return err
	}
	prefix, gateway, dnsAddr, proxy, err := validate(opts)
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	resolver, err := xns.New(opts.indexer)
	if err != nil {
		return fmt.Errorf("--indexer: %w", err)
	}
	store, err := mapstore.New(prefix, gateway, proxy, resolver)
	if err != nil {
		return err
	}
	setup := system.Setup{
		TUN:       opts.tun,
		Prefix:    prefix,
		Gateway:   gateway,
		DNSListen: dnsAddr.String(),
		Domains:   []string{".xns"},
	}

	eng, err := engine.Start(ctx, opts.tun, uint32(opts.mtu), store)
	if err != nil {
		return err
	}
	defer eng.Close()

	if err := system.Up(setup); err != nil {
		_ = system.Down(setup)
		return err
	}
	defer func() {
		if err := system.Down(setup); err != nil {
			log.Printf("cleanup: %v", err)
		}
	}()

	dnsSrv := dnsx.New(dnsAddr.String(), store)
	if err := dnsSrv.Start(); err != nil {
		return err
	}
	defer func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		if err := dnsSrv.Shutdown(shutdownCtx); err != nil {
			log.Printf("dns shutdown: %v", err)
		}
	}()

	log.Printf("ready: indexer=%s tor=%s", opts.indexer, proxy)
	<-ctx.Done()
	log.Print("shutting down")
	return nil
}

func parseArgs() (options, error) {
	var opts options
	flag.StringVar(&opts.indexer, "indexer", "", "XNS indeXer URL")
	flag.StringVar(&opts.torProxy, "tor-proxy", defaultTorProxy, "Tor SOCKS5 proxy URL")
	flag.StringVar(&opts.tun, "tun", defaultTUN, "TUN interface name")
	flag.StringVar(&opts.cidr, "cidr", defaultCIDR, "virtual IPv4 range")
	flag.StringVar(&opts.gateway, "gateway", defaultGateway, "virtual gateway address")
	flag.StringVar(&opts.dns, "dns", defaultDNS, "DNS listen address")
	flag.UintVar(&opts.mtu, "mtu", defaultMTU, "TUN MTU")
	flag.Parse()
	if flag.NArg() != 0 {
		return opts, fmt.Errorf("unexpected arguments: %v", flag.Args())
	}
	if opts.indexer == "" {
		return opts, errors.New("--indexer is required")
	}
	return opts, nil
}

func validate(opts options) (netip.Prefix, netip.Addr, *net.UDPAddr, *url.URL, error) {
	prefix, err := netip.ParsePrefix(opts.cidr)
	if err != nil {
		return netip.Prefix{}, netip.Addr{}, nil, nil, fmt.Errorf("--cidr: %w", err)
	}
	prefix = prefix.Masked()
	if !prefix.Addr().Is4() || prefix.Bits() < 16 || prefix.Bits() > 30 {
		return netip.Prefix{}, netip.Addr{}, nil, nil, errors.New("--cidr must be IPv4 with prefix length between /16 and /30")
	}
	gateway, err := netip.ParseAddr(opts.gateway)
	if err != nil {
		return netip.Prefix{}, netip.Addr{}, nil, nil, fmt.Errorf("--gateway: %w", err)
	}
	if !gateway.Is4() || !prefix.Contains(gateway) {
		return netip.Prefix{}, netip.Addr{}, nil, nil, errors.New("--gateway must be inside --cidr")
	}
	dnsAddr, err := net.ResolveUDPAddr("udp", opts.dns)
	if err != nil {
		return netip.Prefix{}, netip.Addr{}, nil, nil, fmt.Errorf("--dns: %w", err)
	}
	dnsIP, ok := netip.AddrFromSlice(dnsAddr.IP)
	if !ok || dnsIP.Unmap() != gateway || dnsAddr.Port != 53 {
		return netip.Prefix{}, netip.Addr{}, nil, nil, errors.New("--dns must use port 53 on --gateway")
	}
	proxy, err := url.Parse(opts.torProxy)
	if err != nil {
		return netip.Prefix{}, netip.Addr{}, nil, nil, fmt.Errorf("--tor-proxy: %w", err)
	}
	if proxy.Scheme != "socks5" || proxy.Host == "" {
		return netip.Prefix{}, netip.Addr{}, nil, nil, errors.New("--tor-proxy must be a socks5 URL")
	}
	if opts.tun == "" {
		return netip.Prefix{}, netip.Addr{}, nil, nil, errors.New("--tun is required")
	}
	if opts.mtu == 0 || opts.mtu > 65535 {
		return netip.Prefix{}, netip.Addr{}, nil, nil, errors.New("--mtu must be between 1 and 65535")
	}
	return prefix, gateway, dnsAddr, proxy, nil
}
