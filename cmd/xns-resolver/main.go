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
	"github.com/exilens/xns-resolver/internal/netdial"
	"github.com/exilens/xns-resolver/internal/sam"
	"github.com/exilens/xns-resolver/internal/system"
	"github.com/exilens/xns-resolver/internal/tor"
	"github.com/exilens/xns-resolver/internal/xns"
)

const (
	defaultTUN     = "xns0"
	defaultCIDR    = "10.204.0.0/16"
	defaultGateway = "10.204.0.1"
	defaultDNS     = "10.204.0.1:53"
	defaultMTU     = 1500
)

type options struct {
	indexer  string
	network  string
	torSocks string
	i2pSAM   string
	tun      string
	cidr     string
	gateway  string
	dns      string
	mtu      uint
}

type config struct {
	prefix   netip.Prefix
	gateway  netip.Addr
	dns      *net.UDPAddr
	torSocks *url.URL
	i2pSAM   string
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
	cfg, err := validate(opts)
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	resolver, err := xns.New(opts.indexer, opts.network)
	if err != nil {
		return fmt.Errorf("--indexer: %w", err)
	}
	store, err := mapstore.New(cfg.prefix, cfg.gateway, resolver)
	if err != nil {
		return err
	}
	transport, err := newTransport(ctx, opts.network, cfg)
	if err != nil {
		return err
	}
	defer transport.Close()

	setup := system.Setup{
		TUN:       opts.tun,
		Prefix:    cfg.prefix,
		Gateway:   cfg.gateway,
		DNSListen: cfg.dns.String(),
		Domains:   []string{".xns"},
	}

	eng, err := engine.Start(ctx, opts.tun, uint32(opts.mtu), store, transport)
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

	dnsSrv := dnsx.New(cfg.dns.String(), store)
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

	log.Printf("ready: network=%s indexer=%s transport=%s", opts.network, opts.indexer, transportAddress(opts, cfg))
	<-ctx.Done()
	log.Print("shutting down")
	return nil
}

func parseArgs() (options, error) {
	var opts options
	flag.StringVar(&opts.indexer, "indexer", "", "XNS indeXer URL")
	flag.StringVar(&opts.network, "network", "", "destination network: tor or i2p")
	flag.StringVar(&opts.torSocks, "tor-socks", "", "Tor SOCKS5 proxy URL")
	flag.StringVar(&opts.i2pSAM, "i2p-sam", "", "I2P SAM TCP address")
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
	if opts.network == "" {
		return opts, errors.New("--network is required")
	}
	return opts, nil
}

func validate(opts options) (config, error) {
	var cfg config
	prefix, err := netip.ParsePrefix(opts.cidr)
	if err != nil {
		return cfg, fmt.Errorf("--cidr: %w", err)
	}
	prefix = prefix.Masked()
	if !prefix.Addr().Is4() || prefix.Bits() < 16 || prefix.Bits() > 30 {
		return cfg, errors.New("--cidr must be IPv4 with prefix length between /16 and /30")
	}
	gateway, err := netip.ParseAddr(opts.gateway)
	if err != nil {
		return cfg, fmt.Errorf("--gateway: %w", err)
	}
	if !gateway.Is4() || !prefix.Contains(gateway) {
		return cfg, errors.New("--gateway must be inside --cidr")
	}
	dnsAddr, err := net.ResolveUDPAddr("udp", opts.dns)
	if err != nil {
		return cfg, fmt.Errorf("--dns: %w", err)
	}
	dnsIP, ok := netip.AddrFromSlice(dnsAddr.IP)
	if !ok || dnsIP.Unmap() != gateway || dnsAddr.Port != 53 {
		return cfg, errors.New("--dns must use port 53 on --gateway")
	}
	if opts.tun == "" {
		return cfg, errors.New("--tun is required")
	}
	if opts.mtu == 0 || opts.mtu > 65535 {
		return cfg, errors.New("--mtu must be between 1 and 65535")
	}

	switch opts.network {
	case "tor":
		if opts.torSocks == "" {
			return cfg, errors.New("--tor-socks is required for --network tor")
		}
		if opts.i2pSAM != "" {
			return cfg, errors.New("--i2p-sam cannot be used with --network tor")
		}
		proxy, err := url.Parse(opts.torSocks)
		if err != nil {
			return cfg, fmt.Errorf("--tor-socks: %w", err)
		}
		if proxy.Scheme != "socks5" || proxy.Host == "" {
			return cfg, errors.New("--tor-socks must be a socks5 URL")
		}
		cfg.torSocks = proxy
	case "i2p":
		if opts.i2pSAM == "" {
			return cfg, errors.New("--i2p-sam is required for --network i2p")
		}
		if opts.torSocks != "" {
			return cfg, errors.New("--tor-socks cannot be used with --network i2p")
		}
		if err := validTCPAddress(opts.i2pSAM); err != nil {
			return cfg, fmt.Errorf("--i2p-sam: %w", err)
		}
		cfg.i2pSAM = opts.i2pSAM
	default:
		return cfg, errors.New("--network must be tor or i2p")
	}

	cfg.prefix = prefix
	cfg.gateway = gateway
	cfg.dns = dnsAddr
	return cfg, nil
}

func newTransport(ctx context.Context, network string, cfg config) (netdial.Transport, error) {
	switch network {
	case "tor":
		return tor.New(cfg.torSocks), nil
	case "i2p":
		transport, err := sam.New(ctx, cfg.i2pSAM)
		if err != nil {
			return nil, err
		}
		return transport, nil
	default:
		return nil, errors.New("unsupported network")
	}
}

func validTCPAddress(address string) error {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return err
	}
	if host == "" {
		return errors.New("host is required")
	}
	number, err := net.LookupPort("tcp", port)
	if err != nil || number < 1 || number > 65535 {
		return errors.New("valid TCP port is required")
	}
	return nil
}

func transportAddress(opts options, cfg config) string {
	if opts.network == "tor" {
		return cfg.torSocks.String()
	}
	return cfg.i2pSAM
}
