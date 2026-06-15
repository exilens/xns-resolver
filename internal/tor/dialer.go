package tor

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"strconv"

	xproxy "golang.org/x/net/proxy"
)

type Dialer struct {
	proxy *url.URL
}

func New(proxy *url.URL) *Dialer {
	return &Dialer{proxy: proxy}
}

func (d *Dialer) DialContext(ctx context.Context, destination string, port uint16) (net.Conn, error) {
	addr := net.JoinHostPort(destination, strconv.Itoa(int(port)))
	conn, err := dialSocks(ctx, d.proxy, addr)
	if err != nil {
		return nil, fmt.Errorf("Tor -> %s: %w", addr, err)
	}
	return conn, nil
}

func (d *Dialer) Close() error {
	return nil
}

func dialSocks(ctx context.Context, u *url.URL, addr string) (net.Conn, error) {
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
		return cd.DialContext(ctx, "tcp", addr)
	}
	type result struct {
		conn net.Conn
		err  error
	}
	ch := make(chan result, 1)
	go func() {
		conn, err := d.Dial("tcp", addr)
		ch <- result{conn: conn, err: err}
	}()
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case result := <-ch:
		return result.conn, result.err
	}
}
