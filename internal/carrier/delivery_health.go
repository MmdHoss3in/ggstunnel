package carrier

import (
	"errors"
	"fmt"
	"sync/atomic"
	"time"
)

var ErrBIPDeliveryStalled = errors.New("BIP authenticated controls without DATA acknowledgement progress")

// The actor owns timestamps. Published status never reads them concurrently.
// A control response proves peer liveness, not delivery of our outgoing flight.
type deliveryHealth struct {
	waitingSince, lastAck, lastPullAck time.Time
	pullSince, compatUntil             time.Time
	silenceMS                          atomic.Int64
	stalled                            atomic.Bool
}

func (d *deliveryHealth) reset() {
	d.waitingSince, d.lastAck, d.lastPullAck = time.Time{}, time.Time{}, time.Time{}
	d.pullSince, d.compatUntil = time.Time{}, time.Time{}
	d.silenceMS.Store(0)
	d.stalled.Store(false)
}

func (b *BIP) deliveryGrace() time.Duration {
	grace := time.Duration(b.cfg.Transport.BIPPullTimeoutMS) * time.Millisecond
	if b.tuner != nil {
		grace = max(grace, 4*b.tuner.rto, 4*b.tuner.srtt)
	}
	return max(grace, 300*time.Millisecond)
}

func (b *BIP) maintainDeliveryProgress(now time.Time) error {
	d := &b.deliveryHealth
	b.ackMu.Lock()
	waiting := len(b.pending) > 0
	b.ackMu.Unlock()
	if !waiting {
		d.waitingSince = time.Time{}
		d.silenceMS.Store(0)
		d.stalled.Store(false)
		return nil
	}
	if d.waitingSince.IsZero() {
		d.waitingSince = now
	}
	since := maxTime(d.waitingSince, d.lastAck)
	silent := max(0, now.Sub(since))
	d.silenceMS.Store(silent.Milliseconds())
	d.stalled.Store(silent >= max(3*time.Second, b.deliveryGrace()))
	// Use the existing operator deadline. Do not repeatedly rotate during a
	// short outage, or let fresh empty controls suppress recovery indefinitely.
	if silent >= time.Duration(b.cfg.Transport.BIPDeadTimeoutSec)*time.Second {
		return fmt.Errorf("%w after %s", ErrBIPDeliveryStalled, silent.Round(time.Second))
	}
	return nil
}

// Discovery and real DATA ACKs fund PULL, not receipt of an empty peer probe.
// Retain PULL replies while probing request DATA; do not drop in-flight data or
// change identities. A hold-down prevents late ACKs from flapping paths.
func (b *BIP) requestFallback(now time.Time, fast bool) bool {
	d := &b.deliveryHealth
	b.ackMu.Lock()
	waiting := len(b.pending) > 0
	b.ackMu.Unlock()
	if fast || (!waiting && b.txBacklog() == 0) {
		d.pullSince, d.compatUntil = time.Time{}, time.Time{}
		return false
	}
	if d.pullSince.IsZero() {
		d.pullSince = now
	}
	if now.Before(d.compatUntil) {
		return true
	}
	if now.Sub(maxTime(d.pullSince, d.lastPullAck)) < b.deliveryGrace() {
		return false
	}
	d.compatUntil = now.Add(b.deliveryGrace())
	return true
}
