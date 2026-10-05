package carrier

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"net"
	"sync"
	"time"

	"ggstunnel/internal/config"
)

type rawCarrier struct {
	cfg           *config.Config
	kind, network string
	rx            chan []byte
	tx            chan []byte
	conn          *net.IPConn
	peer          *net.IPAddr
	closeOnce     sync.Once
	closeCh       chan struct{}
	errors        chan error
	icmpID        uint16
	icmpSeq       uint16
	innerID       uint16
	startMu       sync.Mutex
	started       bool
	workers       sync.WaitGroup
}

func NewRaw(c *config.Config, kind string) (Carrier, error) {
	network := ""
	switch kind {
	case "icmp":
		network = "ip4:icmp"
	case "gre":
		network = "ip4:47"
	case "ipip":
		network = "ip4:4"
	default:
		return nil, errors.New("bad raw kind")
	}
	var seed [4]byte
	if _, err := rand.Read(seed[:]); err != nil {
		return nil, err
	}
	return &rawCarrier{cfg: c, kind: kind, network: network, rx: make(chan []byte, c.Performance.QueueSize), tx: make(chan []byte, c.Performance.QueueSize), closeCh: make(chan struct{}), errors: make(chan error, 1), icmpID: binary.BigEndian.Uint16(seed[:2]), icmpSeq: binary.BigEndian.Uint16(seed[2:])}, nil
}
func (r *rawCarrier) Errors() <-chan error { return r.errors }
func (r *rawCarrier) Name() string         { return r.kind }
func (r *rawCarrier) Recv() <-chan []byte  { return r.rx }
func (r *rawCarrier) Send(b []byte) error  { return enqueueOpen(r.closeCh, r.tx, b) }
func (r *rawCarrier) Start(ctx context.Context) error {
	r.startMu.Lock()
	defer r.startMu.Unlock()
	if r.started {
		return errors.New("raw carrier already started")
	}
	select {
	case <-r.closeCh:
		return ErrClosed
	case <-ctx.Done():
		return ctx.Err()
	default:
	}
	local := &net.IPAddr{IP: net.ParseIP(r.cfg.Real.LocalIP).To4()}
	peer := &net.IPAddr{IP: net.ParseIP(r.cfg.Real.PeerIP).To4()}
	c, err := net.ListenIP(r.network, local)
	if err != nil {
		return err
	}
	if err := c.SetReadBuffer(r.cfg.Transport.SockBuf); err != nil {
		c.Close()
		return err
	}
	if err := c.SetWriteBuffer(r.cfg.Transport.SockBuf); err != nil {
		c.Close()
		return err
	}
	r.conn, r.peer, r.started = c, peer, true
	r.workers.Add(2)
	go func() { defer r.workers.Done(); r.readLoop(ctx) }()
	go func() { defer r.workers.Done(); r.writeLoop(ctx) }()
	go func() {
		select {
		case <-ctx.Done():
			r.Close()
		case <-r.closeCh:
		}
	}()
	return nil
}

// innerIPv4 gives GRE/IPIP a standards-shaped inner IPv4 packet instead of
// placing the tunnel frame directly after the outer protocol header. Protocol
// 253 is reserved for experimentation/testing and is only used inside our
// synthetic inner packet; it is never routed by the host stack.
func (r *rawCarrier) innerIPv4(marker string, payload []byte) []byte {
	r.innerID++
	p := make([]byte, 20+4+len(payload))
	p[0] = 0x45
	binary.BigEndian.PutUint16(p[2:4], uint16(len(p)))
	binary.BigEndian.PutUint16(p[4:6], r.innerID)
	binary.BigEndian.PutUint16(p[6:8], 0x4000) // DF
	p[8] = 64
	p[9] = 253 // RFC 3692 experimental protocol number
	// RFC 2544 benchmarking network; these addresses exist only inside the
	// encapsulated packet and never need to be configured on an interface.
	src := net.IPv4(198, 18, 0, 1).To4()
	dst := net.IPv4(198, 18, 0, 2).To4()
	if r.cfg.Role == "client" {
		src, dst = dst, src
	}
	copy(p[12:16], src)
	copy(p[16:20], dst)
	binary.BigEndian.PutUint16(p[10:12], checksum(p[:20]))
	copy(p[20:24], []byte(marker))
	copy(p[24:], payload)
	return p
}

func unwrapInnerIPv4(b []byte, marker string) ([]byte, bool) {
	if len(b) < 24 || b[0]>>4 != 4 {
		return nil, false
	}
	ihl := int(b[0]&0x0f) * 4
	if ihl < 20 || len(b) < ihl+4 || b[9] != 253 {
		return nil, false
	}
	total := int(binary.BigEndian.Uint16(b[2:4]))
	if total != len(b) || checksum(b[:ihl]) != 0 || binary.BigEndian.Uint16(b[6:8])&0x3fff != 0 {
		return nil, false
	}
	if total < ihl+4 || string(b[ihl:ihl+4]) != marker {
		return nil, false
	}
	return b[ihl+4 : total], true
}

func (r *rawCarrier) wrap(b []byte) []byte {
	switch r.kind {
	case "icmp":
		p := make([]byte, 8+4+len(b))
		typ := byte(8)
		if r.cfg.Role == "server" {
			typ = 0
		}
		p[0] = typ
		p[1] = byte(r.cfg.Transport.ICMPCode)
		binary.BigEndian.PutUint16(p[4:6], r.icmpID)
		r.icmpSeq++
		binary.BigEndian.PutUint16(p[6:8], r.icmpSeq)
		copy(p[8:12], []byte("IPXI"))
		copy(p[12:], b)
		binary.BigEndian.PutUint16(p[2:4], checksum(p))
		return p
	case "gre":
		inner := r.innerIPv4("IPXG", b)
		p := make([]byte, 4+len(inner))
		binary.BigEndian.PutUint16(p[0:2], 0)      // GRE flags/version
		binary.BigEndian.PutUint16(p[2:4], 0x0800) // inner IPv4
		copy(p[4:], inner)
		return p
	case "ipip":
		return r.innerIPv4("IPX4", b)
	}
	return b
}
func (r *rawCarrier) unwrap(b []byte) ([]byte, bool) {
	switch r.kind {
	case "icmp":
		if len(b) < 12 || string(b[8:12]) != "IPXI" || b[1] != byte(r.cfg.Transport.ICMPCode) || checksum(b) != 0 || (b[0] != 0 && b[0] != 8) {
			return nil, false
		}
		return b[12:], true
	case "gre":
		if len(b) < 4 || binary.BigEndian.Uint16(b[0:2]) != 0 || binary.BigEndian.Uint16(b[2:4]) != 0x0800 {
			return nil, false
		}
		return unwrapInnerIPv4(b[4:], "IPXG")
	case "ipip":
		return unwrapInnerIPv4(b, "IPX4")
	}
	return nil, false
}
func (r *rawCarrier) readLoopScalar(ctx context.Context) {
	buf := make([]byte, 65535)
	for {
		_ = r.conn.SetReadDeadline(time.Now().Add(time.Second))
		n, src, err := r.conn.ReadFromIP(buf)
		if err != nil {
			select {
			case <-ctx.Done():
				return
			default:
			}
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			select {
			case <-r.closeCh:
			default:
				select {
				case r.errors <- err:
				default:
				}
			}
			return
		}
		if !src.IP.Equal(r.peer.IP) {
			continue
		}
		if p, ok := r.unwrap(buf[:n]); ok && len(p) > 0 && len(p) <= r.cfg.Performance.MaxFramePayload+60 {
			cp := append([]byte(nil), p...)
			select {
			case r.rx <- cp:
			case <-ctx.Done():
				return
			case <-r.closeCh:
				return
			default:
			}
		}
	}
}
func (r *rawCarrier) writeLoopScalar(ctx context.Context) {
	for {
		select {
		case b := <-r.tx:
			p := r.wrap(b)
			r.conn.SetWriteDeadline(time.Now().Add(r.cfg.IdleTimeout()))
			if _, err := r.conn.WriteToIP(p, r.peer); err != nil {
				select {
				case r.errors <- err:
				default:
				}
				return
			}
		case <-ctx.Done():
			return
		case <-r.closeCh:
			return
		}
	}
}
func (r *rawCarrier) Close() error {
	r.closeOnce.Do(func() {
		r.startMu.Lock()
		defer r.startMu.Unlock()
		close(r.closeCh)
		if r.conn != nil {
			_ = r.conn.Close()
		}
	})
	r.workers.Wait()
	return nil
}
func checksum(b []byte) uint16 {
	var sum uint32
	for len(b) > 1 {
		sum += uint32(binary.BigEndian.Uint16(b))
		b = b[2:]
	}
	if len(b) > 0 {
		sum += uint32(b[0]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}
