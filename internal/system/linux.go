//go:build linux

package system

import (
	"errors"
	"fmt"
	"log"
	"net"
	"net/netip"
	"strings"

	"github.com/vishvananda/netlink"
)

type Setup struct {
	TUN     string
	Prefix  netip.Prefix
	Gateway netip.Addr
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

	return nil
}

func Down(cfg Setup) error {
	var out error
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

func osIsExist(err error) bool {
	return strings.Contains(strings.ToLower(err.Error()), "file exists")
}

func osIsNotExist(err error) bool {
	s := strings.ToLower(err.Error())
	return strings.Contains(s, "no such process") || strings.Contains(s, "not found")
}
