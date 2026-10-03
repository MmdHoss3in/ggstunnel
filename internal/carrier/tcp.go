package carrier

import (
	"bufio"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"ggstunnel/internal/config"
	"io"
	"net"
	"sync"
	"time"
)

type TCP struct {
	cfg       *config.Config
	rx, tx    chan []byte
	closeOnce sync.Once
	closeCh   chan struct{}
	ln        net.Listener
	mu        sync.Mutex
	sessionMu sync.Mutex
	active    net.Conn
}

func NewTCP(c *config.Config) *TCP {
	return &TCP{cfg: c, rx: make(chan []byte, c.Performance.QueueSize), tx: make(chan []byte, c.Performance.QueueSize), closeCh: make(chan struct{})}
}
func (t *TCP) Name() string        { return "tcp" }
func (t *TCP) Recv() <-chan []byte { return t.rx }
func (t *TCP) Send(b []byte) error { return enqueue(t.tx, b) }

func (t *TCP) SendContext(ctx context.Context, b []byte) error {
	return enqueueContext(ctx, t.closeCh, t.tx, b)
}

func (t *TCP) Start(ctx context.Context) error {
	if t.cfg.Role == "server" {
		ln, err := net.Listen("tcp4", t.cfg.Real.ListenAddr)
		if err != nil {
			return err
		}
		t.ln = ln
		go t.serve(ctx, ln)
	} else {
		go t.dialLoop(ctx)
	}
	go func() {
		select {
		case <-ctx.Done():
			t.Close()
		case <-t.closeCh:
		}
	}()
	return nil
}
func (t *TCP) serve(ctx context.Context, ln net.Listener) {
	slots := make(chan struct{}, 16)
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		if t.cfg.Real.PeerIP != "" && !c.RemoteAddr().(*net.TCPAddr).IP.Equal(net.ParseIP(t.cfg.Real.PeerIP)) {
			c.Close()
			continue
		}
		select {
		case slots <- struct{}{}:
		default:
			c.Close()
			continue
		}
		go func() {
			defer func() { <-slots }()
			if err := t.serverHandshake(c); err != nil {
				c.Close()
				return
			}
			t.session(ctx, c)
		}()
	}
}
func (t *TCP) pause(ctx context.Context) bool {
	select {
	case <-time.After(t.cfg.RetryInterval()):
		return true
	case <-ctx.Done():
	case <-t.closeCh:
	}
	return false
}
func (t *TCP) dialLoop(ctx context.Context) {
	d := net.Dialer{Timeout: t.cfg.DialTimeout(), KeepAlive: 15 * time.Second}
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.closeCh:
			return
		default:
		}
		c, err := d.DialContext(ctx, "tcp4", t.cfg.Real.PeerAddr)
		if err == nil {
			err = t.clientHandshake(c)
			if err != nil {
				c.Close()
			} else {
				t.session(ctx, c)
			}
		}
		if !t.pause(ctx) {
			return
		}
	}
}
func (t *TCP) tune(c net.Conn) {
	if tc, ok := c.(*net.TCPConn); ok {
		tc.SetNoDelay(true)
		tc.SetKeepAlive(true)
		tc.SetKeepAlivePeriod(15 * time.Second)
		tc.SetReadBuffer(t.cfg.Transport.SockBuf)
		tc.SetWriteBuffer(t.cfg.Transport.SockBuf)
	}
}
func (t *TCP) session(parent context.Context, c net.Conn) {
	// Only an authenticated new connection can replace an old connection.
	t.mu.Lock()
	if t.active != nil {
		t.active.Close()
	}
	t.active = c
	t.mu.Unlock()
	t.sessionMu.Lock()
	defer t.sessionMu.Unlock()
	defer c.Close()
	select {
	case <-t.closeCh:
		return
	case <-parent.Done():
		return
	default:
	}
	t.mu.Lock()
	current := t.active == c
	t.mu.Unlock()
	if !current {
		return
	}
	t.tune(c)
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	done := make(chan error, 2)
	go func() { done <- t.readLoop(ctx, c) }()
	go func() { done <- t.writeLoop(ctx, c) }()
	completed := 0
	select {
	case <-done:
		completed++
	case <-parent.Done():
	case <-t.closeCh:
	}
	cancel()
	c.Close()
	for completed < 2 {
		<-done
		completed++
	}

	t.mu.Lock()
	if t.active == c {
		t.active = nil
	}
	t.mu.Unlock()

}
func (t *TCP) readLoop(ctx context.Context, c net.Conn) error {
	r := bufio.NewReaderSize(c, 64<<10)
	var header [4]byte
	for {
		c.SetReadDeadline(time.Now().Add(t.cfg.IdleTimeout()))
		if _, err := io.ReadFull(r, header[:]); err != nil {
			return err
		}
		n := binary.BigEndian.Uint32(header[:])
		if n == 0 || n > uint32(t.cfg.Performance.MaxFramePayload+60) {
			return fmt.Errorf("invalid tcp frame size %d", n)
		}
		b := make([]byte, n)
		if _, err := io.ReadFull(r, b); err != nil {
			return err
		}
		select {
		case t.rx <- b:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}
func writeFull(w io.Writer, b []byte) error {
	for len(b) > 0 {
		n, err := w.Write(b)
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
		b = b[n:]
	}
	return nil
}
func (t *TCP) writeLoop(ctx context.Context, c net.Conn) error {
	for {
		select {
		case b := <-t.tx:
			c.SetWriteDeadline(time.Now().Add(t.cfg.IdleTimeout()))
			// One contiguous write avoids two syscalls per packet.
			buf := make([]byte, 4+len(b))
			binary.BigEndian.PutUint32(buf, uint32(len(b)))
			copy(buf[4:], b)
			if err := writeFull(c, buf); err != nil {
				return err
			}
		case <-ctx.Done():
			return ctx.Err()
		case <-t.closeCh:
			return io.EOF
		}
	}
}
func (t *TCP) proof(label string, nonce []byte) []byte {
	h := hmac.New(sha256.New, []byte(t.cfg.PSK))
	h.Write([]byte("ggstunnel/tcp/v2/" + label))
	h.Write(nonce)
	return h.Sum(nil)
}
func (t *TCP) clientHandshake(c net.Conn) error {
	c.SetDeadline(time.Now().Add(5 * time.Second))
	defer c.SetDeadline(time.Time{})
	hello := make([]byte, 36)
	copy(hello, "GGT2")
	if _, err := rand.Read(hello[4:]); err != nil {
		return err
	}
	if err := writeFull(c, hello); err != nil {
		return err
	}
	reply := make([]byte, 64)
	if _, err := io.ReadFull(c, reply); err != nil {
		return err
	}
	transcript := append(hello[4:], reply[:32]...)
	if !hmac.Equal(reply[32:], t.proof("server", transcript)) {
		return fmt.Errorf("server authentication failed")
	}
	return writeFull(c, t.proof("client", transcript))
}
func (t *TCP) serverHandshake(c net.Conn) error {
	c.SetDeadline(time.Now().Add(5 * time.Second))
	defer c.SetDeadline(time.Time{})
	hello := make([]byte, 36)
	if _, err := io.ReadFull(c, hello); err != nil {
		return err
	}
	if string(hello[:4]) != "GGT2" {
		return fmt.Errorf("unsupported TCP handshake")
	}
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		return err
	}
	transcript := append(hello[4:], nonce...)
	if err := writeFull(c, append(nonce, t.proof("server", transcript)...)); err != nil {
		return err
	}
	proof := make([]byte, 32)
	if _, err := io.ReadFull(c, proof); err != nil {
		return err
	}
	if !hmac.Equal(proof, t.proof("client", transcript)) {
		return fmt.Errorf("client authentication failed")
	}
	return nil
}
func (t *TCP) Close() error {
	t.closeOnce.Do(func() {
		close(t.closeCh)
		if t.ln != nil {
			t.ln.Close()
		}
		t.mu.Lock()
		if t.active != nil {
			t.active.Close()
		}
		t.mu.Unlock()
	})
	return nil
}
