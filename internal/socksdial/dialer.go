package socksdial

import (
	"bufio"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"time"

	xproxy "golang.org/x/net/proxy"

	M "github.com/xjasonlyu/tun2socks/v2/metadata"

	"tsr/internal/mapstore"
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
	addr := net.JoinHostPort(entry.Host, strconv.Itoa(int(meta.DstPort)))
	conn, err := dialProxy(ctx, entry.Route.Proxy, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("proxy %s -> %s: %w", entry.Route.Name, addr, err)
	}
	return conn, nil
}

func (d *Dialer) DialUDP(*M.Metadata) (net.PacketConn, error) {
	return nil, errors.New("UDP is unsupported")
}

func dialProxy(ctx context.Context, u *url.URL, network, addr string) (net.Conn, error) {
	switch u.Scheme {
	case "socks5":
		return dialSocks(ctx, u, network, addr)
	case "http":
		if network != "tcp" {
			return nil, fmt.Errorf("http CONNECT does not support network %q", network)
		}
		return dialHTTPConnect(ctx, u, addr)
	default:
		return nil, fmt.Errorf("unsupported proxy scheme %q", u.Scheme)
	}
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

func dialHTTPConnect(ctx context.Context, u *url.URL, target string) (net.Conn, error) {
	var d net.Dialer
	conn, err := d.DialContext(ctx, "tcp", u.Host)
	if err != nil {
		return nil, err
	}
	ok := false
	defer func() {
		if !ok {
			_ = conn.Close()
		}
	}()

	headers := make(http.Header)
	if u.User != nil {
		pass, _ := u.User.Password()
		token := base64.StdEncoding.EncodeToString([]byte(u.User.Username() + ":" + pass))
		headers.Set("Proxy-Authorization", "Basic "+token)
	}
	if deadline, hasDeadline := ctx.Deadline(); hasDeadline {
		_ = conn.SetDeadline(deadline)
		defer conn.SetDeadline(time.Time{})
	}
	if _, err := fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n", target, target); err != nil {
		return nil, err
	}
	if err := headers.Write(conn); err != nil {
		return nil, err
	}
	if _, err := fmt.Fprint(conn, "\r\n"); err != nil {
		return nil, err
	}
	req := &http.Request{Method: http.MethodConnect}
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, req)
	if err != nil {
		return nil, err
	}
	_ = resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return nil, fmt.Errorf("CONNECT %s: %s", target, resp.Status)
	}
	ok = true
	if br.Buffered() > 0 {
		return &bufferedConn{Conn: conn, r: br}, nil
	}
	return conn, nil
}

type bufferedConn struct {
	net.Conn
	r *bufio.Reader
}

func (c *bufferedConn) Read(b []byte) (int, error) {
	if c.r == nil || c.r.Buffered() == 0 {
		return c.Conn.Read(b)
	}
	n, err := c.r.Read(b)
	if err == io.EOF {
		return n, nil
	}
	return n, err
}
