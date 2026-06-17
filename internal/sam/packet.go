package sam

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
)

const maxDatagramSize = 31744

type packetSession struct {
	address string
	id      string
	conn    net.Conn
	reader  *bufio.Reader
	mu      sync.Mutex
	flows   map[string]*packetConn
	closed  bool
}

func newPacketSession(ctx context.Context, address string) (*packetSession, error) {
	conn, reader, err := connect(ctx, address)
	if err != nil {
		return nil, err
	}
	id, err := sessionID()
	if err != nil {
		conn.Close()
		return nil, err
	}
	if err := writeCommand(ctx, conn, "SESSION CREATE STYLE=DATAGRAM ID="+id+" DESTINATION=TRANSIENT SIGNATURE_TYPE=7\n"); err != nil {
		conn.Close()
		return nil, err
	}
	reply, err := readReply(ctx, conn, reader)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("SAM datagram session: %w", err)
	}
	if !strings.HasPrefix(reply, "SESSION STATUS ") || result(reply) != "OK" {
		conn.Close()
		return nil, fmt.Errorf("SAM datagram session: %s", reply)
	}

	s := &packetSession{
		address: address,
		id:      id,
		conn:    conn,
		reader:  reader,
		flows:   make(map[string]*packetConn),
	}
	go s.readLoop()
	return s, nil
}

func (s *packetSession) Dial(ctx context.Context, destination string, fromPort, toPort uint16) (net.PacketConn, error) {
	base64Destination, err := lookupDestination(ctx, s.address, destination)
	if err != nil {
		return nil, err
	}
	pc := &packetConn{
		session:     s,
		destination: base64Destination,
		fromPort:    fromPort,
		toPort:      toPort,
		in:          make(chan packet, 16),
		local:       &net.UDPAddr{IP: net.IPv4zero, Port: int(fromPort)},
		remote:      unresolvedUDPAddr{network: "udp", address: net.JoinHostPort(destination, strconv.Itoa(int(toPort)))},
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil, errors.New("SAM datagram session is closed")
	}
	if old := s.flows[flowKey(base64Destination, fromPort, toPort)]; old != nil {
		old.close()
	}
	s.flows[flowKey(base64Destination, fromPort, toPort)] = pc
	return pc, nil
}

func (s *packetSession) Close() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	for _, flow := range s.flows {
		flow.close()
	}
	s.flows = nil
	conn := s.conn
	s.mu.Unlock()
	return conn.Close()
}

func (s *packetSession) send(ctx context.Context, destination string, fromPort, toPort uint16, payload []byte) error {
	if len(payload) == 0 || len(payload) > maxDatagramSize {
		return fmt.Errorf("SAM datagram size must be 1..%d bytes", maxDatagramSize)
	}
	command := "DATAGRAM SEND DESTINATION=" + destination +
		" FROM_PORT=" + strconv.Itoa(int(fromPort)) +
		" TO_PORT=" + strconv.Itoa(int(toPort)) +
		" SIZE=" + strconv.Itoa(len(payload)) + "\n"

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return errors.New("SAM datagram session is closed")
	}
	if err := writeCommand(ctx, s.conn, command); err != nil {
		return err
	}
	_, err := s.conn.Write(payload)
	return err
}

func (s *packetSession) readLoop() {
	for {
		line, err := s.reader.ReadString('\n')
		if err != nil {
			s.closeFromReader()
			return
		}
		line = strings.TrimSpace(line)
		switch {
		case line == "PING":
			s.mu.Lock()
			if !s.closed {
				_, _ = io.WriteString(s.conn, "PONG\n")
			}
			s.mu.Unlock()
			continue
		case strings.HasPrefix(line, "PING "):
			s.mu.Lock()
			if !s.closed {
				_, _ = io.WriteString(s.conn, "PONG "+strings.TrimPrefix(line, "PING ")+"\n")
			}
			s.mu.Unlock()
			continue
		case !strings.HasPrefix(line, "DATAGRAM RECEIVED "):
			continue
		}

		fields := parseFields(line)
		size, err := strconv.Atoi(fields["SIZE"])
		if err != nil || size < 0 || size > maxDatagramSize {
			s.closeFromReader()
			return
		}
		payload := make([]byte, size)
		if _, err := io.ReadFull(s.reader, payload); err != nil {
			s.closeFromReader()
			return
		}
		fromPort := parsePort(fields["FROM_PORT"])
		toPort := parsePort(fields["TO_PORT"])
		key := flowKey(fields["DESTINATION"], toPort, fromPort)

		s.mu.Lock()
		flow := s.flows[key]
		s.mu.Unlock()
		if flow == nil {
			continue
		}
		select {
		case flow.in <- packet{data: payload}:
		default:
		}
	}
}

func (s *packetSession) closeFromReader() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return
	}
	s.closed = true
	for _, flow := range s.flows {
		flow.close()
	}
	s.flows = nil
}

func (s *packetSession) remove(pc *packetConn) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.flows != nil && s.flows[flowKey(pc.destination, pc.fromPort, pc.toPort)] == pc {
		delete(s.flows, flowKey(pc.destination, pc.fromPort, pc.toPort))
	}
}

type packetConn struct {
	session     *packetSession
	destination string
	fromPort    uint16
	toPort      uint16
	in          chan packet
	local       net.Addr
	remote      net.Addr
	mu          sync.Mutex
	once        sync.Once
	readUntil   time.Time
	writeUntil  time.Time
	closed      bool
}

type packet struct {
	data []byte
}

func (c *packetConn) ReadFrom(buf []byte) (int, net.Addr, error) {
	c.mu.Lock()
	deadline := c.readUntil
	closed := c.closed
	c.mu.Unlock()
	if closed {
		return 0, nil, net.ErrClosed
	}

	var timer <-chan time.Time
	if !deadline.IsZero() {
		if !deadline.After(time.Now()) {
			return 0, nil, timeoutError{}
		}
		t := time.NewTimer(time.Until(deadline))
		defer t.Stop()
		timer = t.C
	}

	select {
	case packet, ok := <-c.in:
		if !ok {
			return 0, nil, net.ErrClosed
		}
		return copy(buf, packet.data), c.remote, nil
	case <-timer:
		return 0, nil, timeoutError{}
	}
}

func (c *packetConn) WriteTo(payload []byte, _ net.Addr) (int, error) {
	c.mu.Lock()
	deadline := c.writeUntil
	closed := c.closed
	c.mu.Unlock()
	if closed {
		return 0, net.ErrClosed
	}
	ctx := context.Background()
	if !deadline.IsZero() {
		var cancel context.CancelFunc
		ctx, cancel = context.WithDeadline(ctx, deadline)
		defer cancel()
	}
	if err := c.session.send(ctx, c.destination, c.fromPort, c.toPort, payload); err != nil {
		return 0, err
	}
	return len(payload), nil
}

func (c *packetConn) Close() error {
	c.session.remove(c)
	c.close()
	return nil
}

func (c *packetConn) close() {
	c.once.Do(func() {
		c.mu.Lock()
		c.closed = true
		close(c.in)
		c.mu.Unlock()
	})
}

func (c *packetConn) LocalAddr() net.Addr {
	return c.local
}

func (c *packetConn) SetDeadline(t time.Time) error {
	c.mu.Lock()
	c.readUntil = t
	c.writeUntil = t
	c.mu.Unlock()
	return nil
}

func (c *packetConn) SetReadDeadline(t time.Time) error {
	c.mu.Lock()
	c.readUntil = t
	c.mu.Unlock()
	return nil
}

func (c *packetConn) SetWriteDeadline(t time.Time) error {
	c.mu.Lock()
	c.writeUntil = t
	c.mu.Unlock()
	return nil
}

type unresolvedUDPAddr struct {
	network string
	address string
}

func (a unresolvedUDPAddr) Network() string { return a.network }
func (a unresolvedUDPAddr) String() string  { return a.address }

type timeoutError struct{}

func (timeoutError) Error() string   { return "i/o timeout" }
func (timeoutError) Timeout() bool   { return true }
func (timeoutError) Temporary() bool { return true }

func lookupDestination(ctx context.Context, address, destination string) (string, error) {
	conn, reader, err := connect(ctx, address)
	if err != nil {
		return "", err
	}
	defer conn.Close()
	if err := writeCommand(ctx, conn, "NAMING LOOKUP NAME="+destination+"\n"); err != nil {
		return "", err
	}
	reply, err := readReply(ctx, conn, reader)
	if err != nil {
		return "", fmt.Errorf("SAM naming lookup: %w", err)
	}
	if !strings.HasPrefix(reply, "NAMING REPLY ") || result(reply) != "OK" {
		return "", fmt.Errorf("SAM naming lookup: %s", reply)
	}
	value := parseFields(reply)["VALUE"]
	if value == "" {
		return "", errors.New("SAM naming lookup returned no destination")
	}
	return value, nil
}

func parseFields(line string) map[string]string {
	out := make(map[string]string)
	for _, field := range strings.Fields(line) {
		key, value, ok := strings.Cut(field, "=")
		if ok {
			out[key] = value
		}
	}
	return out
}

func parsePort(raw string) uint16 {
	port, err := strconv.ParseUint(raw, 10, 16)
	if err != nil {
		return 0
	}
	return uint16(port)
}

func flowKey(destination string, fromPort, toPort uint16) string {
	return destination + "|" + strconv.Itoa(int(fromPort)) + "|" + strconv.Itoa(int(toPort))
}
