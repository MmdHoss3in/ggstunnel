package carrier

import (
	"context"
	"errors"
	"fmt"
	"ggstunnel/internal/config"
	"net"
	"sync"
	"time"
)

// UDP uses explicitly configured public endpoints. Unauthenticated datagrams
// must never change the return destination. NAT endpoint roaming is not enabled.
type UDP struct {
	cfg       *config.Config
	rx, tx    chan []byte
	conn      *net.UDPConn
	peer      *net.UDPAddr
	closeOnce sync.Once
	closeCh   chan struct{}
	errors    chan error
	startMu   sync.Mutex
	started   bool
	workers   sync.WaitGroup
	stats     datagramStats
}

func NewUDP(c *config.Config) *UDP {
	return &UDP{cfg: c, rx: make(chan []byte, c.Performance.QueueSize), tx: make(chan []byte, c.Performance.QueueSize), closeCh: make(chan struct{}), errors: make(chan error, 1)}
}
func (u *UDP) Name() string         { return "udp" }
func (u *UDP) Recv() <-chan []byte  { return u.rx }
func (u *UDP) Errors() <-chan error { return u.errors }
func (u *UDP) Send(b []byte) error {
	err := enqueueOpen(u.closeCh, u.tx, b)
	if errors.Is(err, ErrQueueFull) {
		u.stats.txDrops.Add(1)
	}
	return err
}
func (u *UDP) SnapshotStats() RuntimeStats { return u.stats.snapshot() }
func (u *UDP) SendContext(ctx context.Context, b []byte) error {
	return enqueueContext(ctx, u.closeCh, u.tx, b)
}
func (u *UDP) Start(ctx context.Context) error {
	u.startMu.Lock()
	defer u.startMu.Unlock()
	if u.started {
		return errors.New("UDP carrier already started")
	}
	select {
	case <-u.closeCh:
		return ErrClosed
	case <-ctx.Done():
		return ctx.Err()
	default:
	}
	p, err := net.ResolveUDPAddr("udp4", u.cfg.Real.PeerAddr)
	if err != nil {
		return err
	}
	if p.IP == nil || p.Port == 0 {
		return fmt.Errorf("UDP requires fixed peer address and port")
	}
	local, err := net.ResolveUDPAddr("udp4", u.cfg.Real.ListenAddr)
	if err != nil {
		return err
	}
	c, err := net.ListenUDP("udp4", local)
	if err != nil {
		return err
	}
	if err := c.SetReadBuffer(u.cfg.Transport.SockBuf); err != nil {
		c.Close()
		return err
	}
	if err := c.SetWriteBuffer(u.cfg.Transport.SockBuf); err != nil {
		c.Close()
		return err
	}
	u.conn, u.peer, u.started = c, p, true
	u.workers.Add(2)
	go func() { defer u.workers.Done(); u.readLoop(ctx) }()
	go func() { defer u.workers.Done(); u.writeLoop(ctx) }()
	go func() {
		select {
		case <-ctx.Done():
			u.Close()
		case <-u.closeCh:
		}
	}()
	return nil
}
func (u *UDP) fail(err error) {
	select {
	case u.errors <- err:
	default:
	}
}
func (u *UDP) readLoopScalar(ctx context.Context) {
	buf := make([]byte, 65535)
	for {
		n, src, err := u.conn.ReadFromUDP(buf)
		if err != nil {
			select {
			case <-u.closeCh:
				return
			default:
				u.stats.rxErrors.Add(1)
				u.fail(err)
				return
			}
		}
		u.stats.receive(n)
		if !src.IP.Equal(u.peer.IP) || src.Port != u.peer.Port {
			u.stats.sourceRejected.Add(1)
			continue
		}
		if n > u.cfg.ReceiveFrameLimit() {
			u.stats.formatRejected.Add(1)
			continue
		}
		b := append([]byte(nil), buf[:n]...)
		select {
		case u.rx <- b:
		case <-u.closeCh:
			return
		case <-ctx.Done():
			return
		default:
			u.stats.rxDrops.Add(1)
		}
	}
}
func (u *UDP) writeLoopScalar(ctx context.Context) {
	for {
		select {
		case b := <-u.tx:
			u.conn.SetWriteDeadline(time.Now().Add(u.cfg.IdleTimeout()))
			if _, err := u.conn.WriteToUDP(b, u.peer); err != nil {
				u.stats.txErrors.Add(1)
				u.fail(err)
				return
			}
			u.stats.sent(len(b))
		case <-ctx.Done():
			return
		case <-u.closeCh:
			return
		}
	}
}
func (u *UDP) Close() error {
	u.closeOnce.Do(func() {
		u.startMu.Lock()
		defer u.startMu.Unlock()
		close(u.closeCh)
		if u.conn != nil {
			u.conn.Close()
		}
	})
	u.workers.Wait()
	return nil
}
