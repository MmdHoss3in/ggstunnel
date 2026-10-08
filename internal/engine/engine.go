package engine

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"sync"
	"sync/atomic"
	"time"

	"ggstunnel/internal/carrier"
	"ggstunnel/internal/config"
	"ggstunnel/internal/forward"
	"ggstunnel/internal/frame"
	"ggstunnel/internal/session"
	"ggstunnel/internal/tun"
)

type packetDevice interface {
	Read([]byte) (int, error)
	Write([]byte) (int, error)
	Close() error
}

type Engine struct {
	transportMu sync.RWMutex
	cfg         *config.Config
	tun         packetDevice
	carrier     carrier.Carrier
	codec       *frame.Codec
	reasm       *frame.Reassembler

	txPackets     atomic.Uint64
	rxPackets     atomic.Uint64
	txBytes       atomic.Uint64
	rxBytes       atomic.Uint64
	drops         atomic.Uint64
	tunQueueDrops atomic.Uint64

	replays          atomic.Uint64
	reflections      atomic.Uint64
	authFails        atomic.Uint64
	malformed        atomic.Uint64
	lastRx           atomic.Int64
	recoveries       atomic.Uint64
	authenticatedRX  atomic.Int64
	effectivePayload atomic.Int64
	outerMTU         atomic.Int64
}

func New(c *config.Config) (*Engine, error) {
	if c == nil {
		return nil, errors.New("nil config")
	}
	owned := *c
	c = &owned
	if err := c.Validate(); err != nil {
		return nil, err
	}
	co, err := frame.NewCodec(c.PSK)
	if c.Transport.WireMode == "opaque" {
		co, err = frame.NewOpaqueCodec(c.PSK)
		if c.Transport.OpaqueSession == "challenge" {
			co, err = frame.NewBoundOpaqueCodec(c.PSK)
		}
	}
	if err != nil {
		return nil, err
	}
	if c.Profile == "bip" && c.Transport.BIPDelivery == "independent" {
		// A retained outer hole can be overtaken by up to 16 inner frames per
		// packed datagram. Include the TX lookahead and bounded heartbeat slack.
		co.SetReplayWindow(uint64(16*min(c.Performance.QueueSize, 8192) + 4096))
	}
	ca, err := carrier.New(c)
	if err != nil {
		return nil, err
	}
	if bound, ok := ca.(interface{ BindIdentity(uint64) error }); ok {
		if err := bound.BindIdentity(co.SessionID()); err != nil {
			return nil, err
		}
	}
	e := &Engine{cfg: c, carrier: ca, codec: co, reasm: frame.NewReassembler(10 * time.Second)}
	e.effectivePayload.Store(int64(c.Performance.MaxFramePayload))
	return e, nil
}

func (e *Engine) Run(ctx context.Context) error {
	for {
		err := e.runOnce(ctx)
		if ctx.Err() != nil {
			return nil
		}
		if !e.recoverable(err) {
			return err
		}
		e.recoveries.Add(1)
		log.Printf("recovering transport with fresh authenticated identity: %v", err)
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(time.Second):
		}
		if nextErr := e.refreshTransport(); nextErr != nil {
			return nextErr
		}
	}
}

// Key lifetime exhaustion always requires a new sender key. BIP also recovers
// bounded delivery/session rotation failures; unexpected errors remain fatal.
func (e *Engine) recoverable(err error) bool {
	return errors.Is(err, frame.ErrKeyLifetime) || (e.cfg.Transport.OpaqueSession == "challenge" && errors.Is(err, session.ErrRotationLimit)) || (e.cfg.Profile == "bip" &&
		(errors.Is(err, carrier.ErrBIPDeliveryTimeout) || errors.Is(err, carrier.ErrBIPPeerUnresponsive) || errors.Is(err, carrier.ErrBIPHandshakeTimeout) || errors.Is(err, session.ErrRotationLimit)))
}

func (e *Engine) refreshTransport() error {
	fresh, err := New(e.cfg)
	if err != nil {
		return err
	}
	// runOnce joins every worker first. New codecs generate fresh IDs/keys;
	// counters are never reset under an existing encryption key.
	e.transportMu.Lock()
	e.cfg = fresh.cfg
	e.carrier, e.codec, e.reasm = fresh.carrier, fresh.codec, fresh.reasm
	e.transportMu.Unlock()
	return nil
}

func (e *Engine) runOnce(ctx context.Context) error {
	e.authenticatedRX.Store(0)
	e.outerMTU.Store(0)
	e.cfg.PreserveReceiveFrameLimit()
	if mtu, err := tun.UnderlayMTU(e.cfg); err != nil {
		log.Printf("underlay MTU lookup unavailable; keeping configured payload: %v", err)
	} else {
		e.outerMTU.Store(int64(mtu))
		payload := config.SafePayload(e.cfg.Profile, e.cfg.Transport.WireMode, mtu, e.cfg.Performance.MaxFramePayload)
		if payload < 256 {
			return fmt.Errorf("underlay MTU %d cannot fit the minimum authenticated payload", mtu)
		}
		if payload < e.cfg.Performance.MaxFramePayload {
			log.Printf("underlay MTU %d: reducing local frame payload %d -> %d; TUN MTU retained for inner fragmentation", mtu, e.cfg.Performance.MaxFramePayload, payload)
			e.cfg.Performance.MaxFramePayload = payload
			e.effectivePayload.Store(int64(payload))
		}
	}
	d, err := tun.Open(e.cfg.TUN.Name)
	if err != nil {
		return err
	}
	e.tun = d
	defer d.Close()
	if err := d.Configure(e.cfg); err != nil {
		return err
	}
	if err := e.carrier.Start(ctx); err != nil {
		return fmt.Errorf("start %s carrier: %w", e.carrier.Name(), err)
	}
	fw, err := forward.Start(ctx, e.cfg.Forwards)
	if err != nil {
		e.carrier.Close()
		return fmt.Errorf("start forwards: %w", err)
	}
	defer fw.Close()
	e.lastRx.Store(time.Now().UnixNano())
	log.Printf("ggstunnel started role=%s profile=%s tun=%s", e.cfg.Role, e.cfg.Profile, d.Name)
	return e.runWorkers(ctx)
}

// Every exit path cancels all workers, closes blocking I/O and joins them.
func (e *Engine) runWorkers(parent context.Context) error {
	ctx, cancel := context.WithCancel(parent)
	var wg sync.WaitGroup
	errCh := make(chan error, 3)
	launch := func(f func(context.Context) error) { wg.Add(1); go func() { defer wg.Done(); errCh <- f(ctx) }() }
	launch(e.tunToCarrier)
	launch(e.carrierToTun)
	launch(e.heartbeatLoop)
	wg.Add(2)
	go func() { defer wg.Done(); e.statsLoop(ctx) }()
	go func() {
		defer wg.Done()
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for {
			select {
			case now := <-ticker.C:
				e.reasm.Cleanup(now)
			case <-ctx.Done():
				return
			}
		}
	}()
	var carrierErrors <-chan error
	if c, ok := e.carrier.(interface{ Errors() <-chan error }); ok {
		carrierErrors = c.Errors()
	}
	var err error
	select {
	case <-parent.Done():
	case err = <-errCh:
	case err = <-carrierErrors:
	}
	cancel()
	// TUN descriptors must support cancellation by Close (nonblocking runtime I/O).
	_ = e.tun.Close()
	_ = e.carrier.Close()
	wg.Wait()
	if parent.Err() != nil {
		return nil
	}
	if err == nil || errors.Is(err, io.EOF) {
		return io.ErrUnexpectedEOF
	}
	return err
}

func (e *Engine) tunToCarrier(ctx context.Context) error {
	if e.cfg.Profile == "bip" {
		return e.fairTunToCarrier(ctx)
	}
	buf := make([]byte, 65535)
	for {
		n, err := e.tun.Read(buf)
		if err != nil {
			return err
		}
		if n == 0 {
			continue
		}
		if err := e.sendPacket(ctx, buf[:n]); err != nil {
			return err
		}
	}
}

func (e *Engine) sendPacket(ctx context.Context, pkt []byte) error {
	if e.cfg.Transport.OpaqueSession == "challenge" && e.codec.RotationDue() {
		return frame.ErrKeyLifetime
	}
	if e.cfg.Transport.OpaqueSession == "challenge" {
		peer := e.carrier.(interface{ PeerSession() uint64 })
		id := peer.PeerSession()
		if id == 0 {
			tick := time.NewTicker(10 * time.Millisecond)
			defer tick.Stop()
			for id == 0 {
				select {
				case <-ctx.Done():
					return ctx.Err()
				case <-tick.C:
					id = peer.PeerSession()
				}
			}
		}
		if err := e.codec.BindSendPeer(id); err != nil {
			return err
		}
	}
	pid := e.codec.NextPacketID()
	maxp := e.cfg.Performance.MaxFramePayload
	cnt := (len(pkt) + maxp - 1) / maxp
	if cnt < 1 {
		cnt = 1
	}
	if cnt > 65535 {
		return fmt.Errorf("packet too fragmented")
	}
	for i := 0; i < cnt; i++ {
		a := i * maxp
		z := a + maxp
		if z > len(pkt) {
			z = len(pkt)
		}
		w, err := e.codec.Seal(frame.TypeData, pid, uint16(i), uint16(cnt), pkt[a:z])
		if err != nil {
			return err
		}
		var sendErr error
		if sender, ok := e.carrier.(interface {
			SendContext(context.Context, []byte) error
		}); ok {
			sendErr = sender.SendContext(ctx, w)
		} else {
			sendErr = e.carrier.Send(w)
		}
		if sendErr != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			e.drops.Add(1)
			continue
		}
	}
	e.txPackets.Add(1)
	e.txBytes.Add(uint64(len(pkt)))
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}
	return nil
}

func (e *Engine) carrierToTun(ctx context.Context) error {
	for {
		select {
		case b, ok := <-e.carrier.Recv():
			if !ok {
				return io.ErrUnexpectedEOF
			}
			var d *frame.Decoded
			var err error
			if sessions, ok := e.carrier.(interface{ PeerSession() uint64 }); ok {
				d, err = e.codec.OpenForSession(b, sessions.PeerSession())
			} else {
				d, err = e.codec.Open(b)
			}
			if err != nil {
				switch {
				case errors.Is(err, frame.ErrReplay):
					e.replays.Add(1)
				case errors.Is(err, frame.ErrReflectedLocal):
					e.reflections.Add(1)
				case errors.Is(err, frame.ErrAuthentication):
					e.authFails.Add(1)
				default:
					e.malformed.Add(1)
				}
				continue
			}
			e.lastRx.Store(time.Now().UnixNano())
			e.authenticatedRX.Store(time.Now().UnixNano())
			if d.Header.Type == frame.TypeHeartbeat {
				continue
			}
			if d.Header.Type != frame.TypeData {
				continue
			}
			pkt, ok := e.reasm.Add(d.Header, d.Payload)
			if !ok {
				continue
			}
			if _, err := e.tun.Write(pkt); err != nil {
				return err
			}
			e.rxPackets.Add(1)
			e.rxBytes.Add(uint64(len(pkt)))
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

func (e *Engine) heartbeatLoop(ctx context.Context) error {
	t := time.NewTicker(e.cfg.Heartbeat())
	defer t.Stop()
	for {
		select {
		case <-t.C:
			if e.cfg.Transport.OpaqueSession == "challenge" && e.codec.RotationDue() {
				return frame.ErrKeyLifetime
			}
			if e.cfg.Transport.OpaqueSession == "challenge" {
				id := e.carrier.(interface{ PeerSession() uint64 }).PeerSession()
				if id == 0 {
					continue
				}
				if err := e.codec.BindSendPeer(id); err != nil {
					return err
				}
			}
			w, err := e.codec.Seal(frame.TypeHeartbeat, 0, 0, 1, nil)
			if errors.Is(err, frame.ErrKeyLifetime) {
				return err
			}
			if err == nil {
				if err := e.carrier.Send(w); err != nil && !errors.Is(err, carrier.ErrPeerNotReady) {
					e.drops.Add(1)
				}
			}
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

func (e *Engine) statsLoop(ctx context.Context) {
	interval := time.Duration(e.cfg.Telemetry.IntervalSec) * time.Second
	if interval <= 0 {
		interval = 5 * time.Second
	}
	t := time.NewTicker(interval)
	// Engine counters survive transport recovery. Start this sampling epoch at
	// the current totals instead of attributing process history to one interval.
	lastAt := time.Now()
	lastTxPackets, lastRxPackets := e.txPackets.Load(), e.rxPackets.Load()
	lastTxBytes, lastRxBytes := e.txBytes.Load(), e.rxBytes.Load()
	var lastWireTx, lastWireRx uint64
	if s, ok := e.carrier.(carrier.Statser); ok {
		cs := s.SnapshotStats()
		lastWireTx, lastWireRx = cs.WireTxBytes, cs.WireRxBytes
	}
	if e.cfg.Telemetry.StatsFile != "" {
		if err := writeTelemetry(e.cfg.Telemetry.StatsFile, e.SnapshotTelemetry(time.Now())); err != nil {
			log.Printf("stats file: %v", err)
		}
	}
	defer t.Stop()
	for {
		select {
		case now := <-t.C:
			dt := now.Sub(lastAt).Seconds()
			if dt <= 0 {
				dt = interval.Seconds()
			}
			txp, rxp := e.txPackets.Load(), e.rxPackets.Load()
			txb, rxb := e.txBytes.Load(), e.rxBytes.Load()
			idle := time.Since(time.Unix(0, e.lastRx.Load())).Round(time.Second)
			base := fmt.Sprintf("stats tx=%d/%s rx=%d/%s rate{tx=%.2fMbps/%.0fpps rx=%.2fMbps/%.0fpps} drop=%d replay=%d reflection=%d auth_fail=%d malformed=%d last_rx=%s",
				txp, humanBytes(txb), rxp, humanBytes(rxb),
				mbps(txb-lastTxBytes, dt), float64(txp-lastTxPackets)/dt,
				mbps(rxb-lastRxBytes, dt), float64(rxp-lastRxPackets)/dt,
				e.drops.Load(), e.replays.Load(), e.reflections.Load(), e.authFails.Load(), e.malformed.Load(), idle)
			if s, ok := e.carrier.(carrier.Statser); ok {
				cs := s.SnapshotStats()
				if e.cfg.Profile != "bip" {
					authenticated := e.authenticatedRX.Load()
					silent := int64(0)
					if authenticated != 0 {
						silent = max(0, now.Sub(time.Unix(0, authenticated)).Milliseconds())
					}
					base += fmt.Sprintf(" carrier{profile=%s wire=%s session=%s socket_tx=%s socket_rx=%s source_reject=%d format_reject=%d rx_drop=%d tx_drop=%d rxerr=%d txerr=%d control_reject=%d} health{authenticated=%t silent=%dms handshake_wait=%dms}",
						e.cfg.Profile, e.cfg.Transport.WireMode, cs.SessionMode,
						humanBytes(cs.SocketTxBytes), humanBytes(cs.SocketRxBytes),
						cs.SourceRejected, cs.FormatRejected, cs.ReceiveQueueDrops, cs.TransmitQueueDrops,
						cs.RxErrors, cs.TxErrors, cs.ControlRejected, authenticated != 0, silent, cs.HandshakeWaitMS)
				} else {
					base += fmt.Sprintf(" bip5{wire_tx=%s/%.2fMbps wire_rx=%s/%.2fMbps fast=%d pull=%d bootstrap=%d compat=%d idle_probe=%d fast_probe=%d fast_ack_tx=%d needpull=%d pull_probe=%d fast_ack_rx=%d needpull_rx=%d pull_probe_rx=%d reflect_supp=%d payload_rx=%d hmac_fail=%d dup=%d pending=%d backlog=%d retry=%d expired=%d overflow=%d promote=%d demote=%d fast_ok=%t pull_active=%t compat_active=%t txerr=%d}",
						humanBytes(cs.WireTxBytes), mbps(cs.WireTxBytes-lastWireTx, dt),
						humanBytes(cs.WireRxBytes), mbps(cs.WireRxBytes-lastWireRx, dt),
						cs.FastDataTx, cs.PullDataTx, cs.BootstrapDataTx, cs.CompatDataTx, cs.IdleProbeTx, cs.FastProbeTx, cs.FastAckTx, cs.NeedPullTx, cs.PullProbeTx,
						cs.FastAckRx, cs.NeedPullRx, cs.PullProbeRx, cs.ReflectionsSuppressed, cs.PayloadFrameRx, cs.HMACFail, cs.DataDuplicate,
						cs.Pending, cs.Backlog, cs.Retransmits, cs.PendingExpired, cs.PendingOverflow, cs.FastPromotions, cs.FastDemotions, cs.FastHealthy, cs.PullActive, cs.CompatActive, cs.TxErrors)
					lastWireTx, lastWireRx = cs.WireTxBytes, cs.WireRxBytes
					base += fmt.Sprintf(" pull_feedback{data_rx=%d replies=%d outstanding=%d expired=%d budget=%.0fpps}",
						cs.PulledDataRx, cs.PullRepliesRx, cs.PullOutstanding, cs.PullRequestsExpired, cs.PullBudgetPPS)
					base += fmt.Sprintf(" health{authenticated=%t silent=%dms suspended=%t rehandshake=%d}",
						cs.PeerAuthenticated, cs.PeerSilenceMS, cs.PathSuspended, cs.RehandshakeTries)
				}
			}
			if c, ok := e.carrier.(interface{ SnapshotTuner() carrier.TunerSnapshot }); ok {
				s := c.SnapshotTuner()
				base += fmt.Sprintf(" tuner{mode=%s srtt=%.2fms rto=%.2fms window=%d pace=%.0fpps cuts=%d}", s.Mode, s.SRTTMS, s.RTOMS, s.Window, s.PacingPPS, s.CongestionCuts)
			}
			log.Print(base)
			if e.cfg.Telemetry.StatsFile != "" {
				if err := writeTelemetry(e.cfg.Telemetry.StatsFile, e.SnapshotTelemetry(now)); err != nil {
					log.Printf("stats file: %v", err)
				}
			}
			lastAt = now
			lastTxPackets, lastRxPackets = txp, rxp
			lastTxBytes, lastRxBytes = txb, rxb
		case <-ctx.Done():
			return
		}
	}
}

func mbps(bytes uint64, seconds float64) float64 {
	if seconds <= 0 {
		return 0
	}
	return float64(bytes) * 8 / seconds / 1_000_000
}

func humanBytes(n uint64) string {
	const (
		KiB = 1024
		MiB = 1024 * KiB
		GiB = 1024 * MiB
	)
	switch {
	case n >= GiB:
		return fmt.Sprintf("%.2fGiB", float64(n)/GiB)
	case n >= MiB:
		return fmt.Sprintf("%.2fMiB", float64(n)/MiB)
	case n >= KiB:
		return fmt.Sprintf("%.2fKiB", float64(n)/KiB)
	default:
		return fmt.Sprintf("%dB", n)
	}
}
