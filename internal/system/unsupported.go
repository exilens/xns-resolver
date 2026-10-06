//go:build !linux

package system

import (
	"errors"
	"net/netip"
)

type Setup struct {
	TUN     string
	Prefix  netip.Prefix
	Gateway netip.Addr
}

func Up(Setup) error {
	return errors.New("xns-resolver is Linux-only")
}

func Down(Setup) error {
	return errors.New("xns-resolver is Linux-only")
}
