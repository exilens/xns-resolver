//go:build linux

package system

import (
	"errors"
	"fmt"
	"log"
	"net"
	"net/netip"
	"os/exec"
	"strings"

	"github.com/vishvananda/netlink"
)

type Setup struct {
	TUN       string
	Prefix    netip.Prefix
	Gateway   netip.Addr
	DNSListen string
	Domains   []string
}

func Up(cfg Setup) error {
	link, err := netlink.LinkByName(cfg.TUN)
	if err != nil {
		return fmt.Errorf("find tun interface %s after open: %w", cfg.TUN, err)
	}

	addr, err := netlink.ParseAddr(fmt.Sprintf("%s/%d", cfg.Gateway, cfg.Prefix.Bits()))
	if err != nil {
		return err
	}
	if err := ensureAddr(link, addr); err != nil {
		return err
	}
	if err := netlink.LinkSetUp(link); err != nil {
		return fmt.Errorf("bring %s up: %w", cfg.TUN, err)
	}

	dst := net.IPNet{IP: net.IP(cfg.Prefix.Addr().AsSlice()).To4(), Mask: net.CIDRMask(cfg.Prefix.Bits(), 32)}
	route := netlink.Route{LinkIndex: link.Attrs().Index, Dst: &dst}
	if err := netlink.RouteReplace(&route); err != nil {
		return fmt.Errorf("route replace %s dev %s: %w", cfg.Prefix, cfg.TUN, err)
	}
	log.Printf("network ready: %s %s route %s", cfg.TUN, cfg.Gateway, cfg.Prefix)

	if err := ResolvedUp(cfg); err != nil {
		return err
	}
	return nil
}

func Down(cfg Setup) error {
	var out error
	out = errors.Join(out, ResolvedDown(cfg.TUN))
	if link, err := netlink.LinkByName(cfg.TUN); err == nil {
		dst := net.IPNet{IP: net.IP(cfg.Prefix.Addr().AsSlice()).To4(), Mask: net.CIDRMask(cfg.Prefix.Bits(), 32)}
		if err := netlink.RouteDel(&netlink.Route{LinkIndex: link.Attrs().Index, Dst: &dst}); err != nil && !osIsNotExist(err) {
			out = errors.Join(out, fmt.Errorf("delete route: %w", err))
		}
		if err := netlink.LinkDel(link); err != nil {
			out = errors.Join(out, fmt.Errorf("delete %s: %w", cfg.TUN, err))
		}
	}
	return out
}

func ensureAddr(link netlink.Link, want *netlink.Addr) error {
	addrs, err := netlink.AddrList(link, netlink.FAMILY_V4)
	if err != nil {
		return err
	}
	for _, a := range addrs {
		if a.IPNet.String() == want.IPNet.String() {
			return nil
		}
	}
	if err := netlink.AddrAdd(link, want); err != nil && !osIsExist(err) {
		return fmt.Errorf("add addr %s: %w", want, err)
	}
	return nil
}

func ResolvedUp(cfg Setup) error {
	host, _, err := net.SplitHostPort(cfg.DNSListen)
	if err != nil {
		return err
	}
	if host == "" {
		return errors.New("dns.listen must include an explicit host when managing systemd-resolved")
	}

	args := []string{"dns", cfg.TUN, cfg.DNSListen}
	if err := run("resolvectl", args...); err != nil {
		return err
	}

	domains := make([]string, 0, len(cfg.Domains))
	for _, d := range cfg.Domains {
		d = strings.TrimPrefix(strings.TrimSuffix(d, "."), ".")
		if d != "" {
			domains = append(domains, "~"+d)
		}
	}
	if len(domains) > 0 {
		args = append([]string{"domain", cfg.TUN}, domains...)
		if err := run("resolvectl", args...); err != nil {
			return err
		}
	}
	if err := run("resolvectl", "dnsovertls", cfg.TUN, "false"); err != nil {
		return err
	}
	if err := run("resolvectl", "dnssec", cfg.TUN, "false"); err != nil {
		return err
	}
	if err := run("resolvectl", "llmnr", cfg.TUN, "false"); err != nil {
		return err
	}
	if err := run("resolvectl", "mdns", cfg.TUN, "false"); err != nil {
		return err
	}
	if err := run("resolvectl", "default-route", cfg.TUN, "false"); err != nil {
		return err
	}
	log.Printf("systemd-resolved route-only domains on %s: %s", cfg.TUN, strings.Join(domains, " "))
	return nil
}

func ResolvedDown(iface string) error {
	var out error
	out = errors.Join(out, run("resolvectl", "revert", iface))
	return out
}

func run(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	b, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %s: %w: %s", name, strings.Join(args, " "), err, strings.TrimSpace(string(b)))
	}
	return nil
}

func osIsExist(err error) bool {
	return strings.Contains(strings.ToLower(err.Error()), "file exists")
}

func osIsNotExist(err error) bool {
	s := strings.ToLower(err.Error())
	return strings.Contains(s, "no such process") || strings.Contains(s, "not found")
}
