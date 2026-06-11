package socksdial

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strconv"

	xproxy "golang.org/x/net/proxy"

	M "github.com/xjasonlyu/tun2socks/v2/metadata"

	"github.com/exilens/xns-resolver/internal/mapstore"
)

type Dialer struct {
	store *mapstore.Store
}

func New(store *mapstore.Store) *Dialer {
	return &Dialer{store: store}
}

func (d *Dialer) DialContext(ctx context.Context, meta *M.Metadata) (net.Conn, error) {
	entry, ok := d.store.LookupIP(meta.DstIP)
	if !ok {
		return nil, fmt.Errorf("unmapped destination %s", meta.DestinationAddress())
	}
	addr := net.JoinHostPort(entry.Destination, strconv.Itoa(int(meta.DstPort)))
	conn, err := dialSocks(ctx, entry.Proxy, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("Tor -> %s: %w", addr, err)
	}
	return conn, nil
}

func (d *Dialer) DialUDP(*M.Metadata) (net.PacketConn, error) {
	return nil, errors.New("UDP is unsupported")
}

func dialSocks(ctx context.Context, u *url.URL, network, addr string) (net.Conn, error) {
	var auth *xproxy.Auth
	if u.User != nil {
		auth = &xproxy.Auth{User: u.User.Username()}
		auth.Password, _ = u.User.Password()
	}
	d, err := xproxy.SOCKS5("tcp", u.Host, auth, xproxy.Direct)
	if err != nil {
		return nil, err
	}
	if cd, ok := d.(xproxy.ContextDialer); ok {
		return cd.DialContext(ctx, network, addr)
	}
	type result struct {
		conn net.Conn
		err  error
	}
	ch := make(chan result, 1)
	go func() {
		c, err := d.Dial(network, addr)
		ch <- result{conn: c, err: err}
	}()
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case r := <-ch:
		return r.conn, r.err
	}
}
