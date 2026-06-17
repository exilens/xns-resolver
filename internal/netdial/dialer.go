package netdial

import (
	"context"
	"fmt"
	"net"
	"time"

	M "github.com/xjasonlyu/tun2socks/v2/metadata"

	"github.com/exilens/xns-resolver/internal/mapstore"
)

const udpSetupTimeout = 60 * time.Second

type Transport interface {
	DialContext(context.Context, string, uint16) (net.Conn, error)
	DialPacket(context.Context, string, uint16, uint16) (net.PacketConn, error)
	Close() error
}

type Dialer struct {
	store     *mapstore.Store
	transport Transport
}

func New(store *mapstore.Store, transport Transport) *Dialer {
	return &Dialer{store: store, transport: transport}
}

func (d *Dialer) DialContext(ctx context.Context, meta *M.Metadata) (net.Conn, error) {
	entry, ok := d.store.LookupIP(meta.DstIP)
	if !ok {
		return nil, fmt.Errorf("unmapped destination %s", meta.DestinationAddress())
	}
	return d.transport.DialContext(ctx, entry.Destination, meta.DstPort)
}

func (d *Dialer) DialUDP(meta *M.Metadata) (net.PacketConn, error) {
	entry, ok := d.store.LookupIP(meta.DstIP)
	if !ok {
		return nil, fmt.Errorf("unmapped destination %s", meta.DestinationAddress())
	}
	ctx, cancel := context.WithTimeout(context.Background(), udpSetupTimeout)
	defer cancel()
	return d.transport.DialPacket(ctx, entry.Destination, meta.SrcPort, meta.DstPort)
}
