package sam

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
)

const commandLimit = 1 << 20

type Dialer struct {
	address string
	id      string
	session net.Conn
	reader  *bufio.Reader
	mu      sync.Mutex
	packet  *packetSession
	closed  bool
}

func New(ctx context.Context, address string) (*Dialer, error) {
	conn, reader, err := connect(ctx, address)
	if err != nil {
		return nil, err
	}
	id, err := sessionID()
	if err != nil {
		conn.Close()
		return nil, err
	}
	if err := writeCommand(ctx, conn, "SESSION CREATE STYLE=STREAM ID="+id+" DESTINATION=TRANSIENT SIGNATURE_TYPE=7\n"); err != nil {
		conn.Close()
		return nil, err
	}
	reply, err := readReply(ctx, conn, reader)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("SAM session: %w", err)
	}
	if !strings.HasPrefix(reply, "SESSION STATUS ") || result(reply) != "OK" {
		conn.Close()
		return nil, fmt.Errorf("SAM session: %s", reply)
	}

	d := &Dialer{address: address, id: id, session: conn, reader: reader}
	go d.watchSession()
	return d, nil
}

func (d *Dialer) DialContext(ctx context.Context, destination string, port uint16) (net.Conn, error) {
	d.mu.Lock()
	closed := d.closed
	d.mu.Unlock()
	if closed {
		return nil, errors.New("SAM session is closed")
	}

	conn, reader, err := connect(ctx, d.address)
	if err != nil {
		return nil, err
	}
	stop := interruptOnCancel(ctx, conn)
	defer stop()
	command := "STREAM CONNECT ID=" + d.id +
		" DESTINATION=" + destination +
		" SILENT=false TO_PORT=" + strconv.Itoa(int(port)) + "\n"
	if err := writeCommand(ctx, conn, command); err != nil {
		conn.Close()
		return nil, err
	}
	reply, err := readReply(ctx, conn, reader)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("SAM stream: %w", err)
	}
	if !strings.HasPrefix(reply, "STREAM STATUS ") || result(reply) != "OK" {
		conn.Close()
		return nil, fmt.Errorf("I2P -> %s: %s", destination, reply)
	}
	return &bufferedConn{Conn: conn, reader: reader}, nil
}

func (d *Dialer) DialPacket(ctx context.Context, destination string, fromPort, toPort uint16) (net.PacketConn, error) {
	d.mu.Lock()
	if d.closed {
		d.mu.Unlock()
		return nil, errors.New("SAM session is closed")
	}
	packet := d.packet
	if packet == nil {
		var err error
		packet, err = newPacketSession(ctx, d.address)
		if err != nil {
			d.mu.Unlock()
			return nil, err
		}
		d.packet = packet
	}
	d.mu.Unlock()
	return packet.Dial(ctx, destination, fromPort, toPort)
}

func (d *Dialer) Close() error {
	d.mu.Lock()
	if d.closed {
		d.mu.Unlock()
		return nil
	}
	d.closed = true
	conn := d.session
	packet := d.packet
	d.mu.Unlock()
	var err error
	if packet != nil {
		err = packet.Close()
	}
	return errors.Join(err, conn.Close())
}

func (d *Dialer) watchSession() {
	defer func() {
		d.mu.Lock()
		d.closed = true
		d.mu.Unlock()
	}()
	for {
		line, err := d.reader.ReadString('\n')
		if err != nil {
			return
		}
		line = strings.TrimSpace(line)
		if line == "PING" {
			d.mu.Lock()
			if !d.closed {
				_, _ = io.WriteString(d.session, "PONG\n")
			}
			d.mu.Unlock()
		} else if strings.HasPrefix(line, "PING ") {
			d.mu.Lock()
			if !d.closed {
				_, _ = io.WriteString(d.session, "PONG "+strings.TrimPrefix(line, "PING ")+"\n")
			}
			d.mu.Unlock()
		}
	}
}

func connect(ctx context.Context, address string) (net.Conn, *bufio.Reader, error) {
	var dialer net.Dialer
	conn, err := dialer.DialContext(ctx, "tcp", address)
	if err != nil {
		return nil, nil, fmt.Errorf("SAM %s: %w", address, err)
	}
	stop := interruptOnCancel(ctx, conn)
	defer stop()
	reader := bufio.NewReaderSize(conn, 4096)
	if err := writeCommand(ctx, conn, "HELLO VERSION MIN=3.0 MAX=3.3\n"); err != nil {
		conn.Close()
		return nil, nil, err
	}
	reply, err := readReply(ctx, conn, reader)
	if err != nil {
		conn.Close()
		return nil, nil, fmt.Errorf("SAM handshake: %w", err)
	}
	if !strings.HasPrefix(reply, "HELLO REPLY ") || result(reply) != "OK" {
		conn.Close()
		return nil, nil, fmt.Errorf("SAM handshake: %s", reply)
	}
	return conn, reader, nil
}

func interruptOnCancel(ctx context.Context, conn net.Conn) func() {
	done := make(chan struct{})
	stop := context.AfterFunc(ctx, func() {
		_ = conn.SetDeadline(time.Now())
		close(done)
	})
	return func() {
		if !stop() {
			<-done
		}
		_ = conn.SetDeadline(time.Time{})
	}
}

func writeCommand(ctx context.Context, conn net.Conn, command string) error {
	if deadline, ok := ctx.Deadline(); ok {
		if err := conn.SetWriteDeadline(deadline); err != nil {
			return err
		}
		defer conn.SetWriteDeadline(time.Time{})
	}
	_, err := io.WriteString(conn, command)
	return err
}

func readReply(ctx context.Context, conn net.Conn, reader *bufio.Reader) (string, error) {
	if deadline, ok := ctx.Deadline(); ok {
		if err := conn.SetReadDeadline(deadline); err != nil {
			return "", err
		}
		defer conn.SetReadDeadline(time.Time{})
	}
	line, err := reader.ReadString('\n')
	if err != nil {
		return "", err
	}
	if len(line) > commandLimit {
		return "", errors.New("reply is too large")
	}
	return strings.TrimSpace(line), nil
}

func result(reply string) string {
	for _, field := range strings.Fields(reply) {
		if strings.HasPrefix(field, "RESULT=") {
			return strings.TrimPrefix(field, "RESULT=")
		}
	}
	return ""
}

func sessionID() (string, error) {
	var raw [8]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	return "xns-" + hex.EncodeToString(raw[:]), nil
}

type bufferedConn struct {
	net.Conn
	reader *bufio.Reader
}

func (c *bufferedConn) Read(p []byte) (int, error) {
	return c.reader.Read(p)
}
