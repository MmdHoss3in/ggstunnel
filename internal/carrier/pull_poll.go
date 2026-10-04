package carrier

import (
	"errors"
	"math"
	"syscall"
	"time"
)

// Actor-owned feedback for the receiving direction. Local FAST health says
// nothing about whether the peer needs EchoRequest tuples to return its DATA.
type pullPoller struct {
	requests                         map[uint32]time.Time
	rate                             float64
	rtt                              time.Duration
	sampleAt, activeSince, lastReply time.Time
	accepted, sampled, expired       uint64
}

func pullTuple(id, tuple uint16) uint32 {
	return uint32(id)<<16 | uint32(tuple)
}

func (p *pullPoller) reply(id, tuple uint16, now time.Time) bool {
	key := pullTuple(id, tuple)
	sent, ok := p.requests[key]
	if !ok {
		return false
	}
	delete(p.requests, key)
	p.lastReply = now
	if sample := now.Sub(sent); sample > 0 {
		if p.rtt == 0 {
			p.rtt = sample
		} else {
			p.rtt = (7*p.rtt + sample) / 8
		}
	}
	return true
}

func (b *BIP) pollingRate(now time.Time, active bool) float64 {
	p := &b.poll
	grace := 500 * time.Millisecond
	grace = max(grace, 4*p.rtt)
	if b.tuner != nil {
		grace = max(grace, 4*b.tuner.srtt)
	}
	if p.sampleAt.IsZero() {
		p.sampleAt = now
		p.sampled = p.accepted
	}
	if !active {
		p.activeSince = time.Time{}
	} else if p.activeSince.IsZero() {
		p.activeSince = now
		// Short MORE/NEED_PULL gaps must not restart a healthy receiving rate
		// at 1000pps on every inner TCP ACK burst. Stale high rates restart
		// conservatively, while unanswered low-rate discovery stays bounded.
		if p.rate == 0 || (p.rate > 1000 && now.Sub(p.lastReply) >= grace) {
			p.rate = 1000
		}
	}
	if elapsed := now.Sub(p.sampleAt); elapsed >= 100*time.Millisecond {
		// Empty probes have no protocol response. Bound their retained tuples
		// and let a late response remain valid DATA without influencing pacing.
		expiry := max(time.Second, grace)
		for key, sent := range p.requests {
			if now.Sub(sent) >= expiry {
				delete(p.requests, key)
				p.expired++
			}
		}
		observed := float64(p.accepted-p.sampled) / elapsed.Seconds()
		if active {
			last := maxTime(p.activeSince, p.lastReply)
			switch {
			case now.Sub(last) >= grace:
				p.rate = max(50, p.rate/2)
			case observed > 0:
				p.rate = max(1000, observed*1.5)
			}
		}
		p.sampleAt, p.sampled = now, p.accepted
	}
	rate := p.rate
	if b.tuner == nil || !b.tuner.adaptive() {
		// Manual mode still honors its operator-selected rate, but unanswered
		// polling backs off. Any valid returned DATA restores that target.
		rate = float64(b.cfg.Transport.BIPPullPPS)
		if active && now.Sub(maxTime(p.activeSince, p.lastReply)) >= grace {
			rate = min(rate, p.rate)
		}
	} else if !b.tuner.cfg.UnlimitedRate {
		rate = min(rate, float64(min(b.cfg.Transport.BIPPullPPS, b.tuner.cfg.MaxPPS)))
	}
	if !active {
		rate = 0
	}
	b.pullBudgetPPS.Store(math.Float64bits(rate))
	b.pullOutstanding.Store(uint64(len(p.requests)))
	b.pullRequestsExpired.Store(p.expired)
	return rate
}

func (b *BIP) sendPullProbe(now time.Time) bool {
	p := &b.poll
	// Polls include empty requests as well as DATA in flight. A DATA-sized
	// request limit would become an accidental rate cap when empty probes
	// await expiry. Keep bounded headroom separate from the reliable flight.
	if len(p.requests) >= 4*b.window() {
		return false
	}
	if p.requests == nil {
		p.requests = make(map[uint32]time.Time)
	}
	id, tuple := b.nextTuple()
	if err := b.send(8, id, tuple, bipKindPullProbe, 0, 0, nil, b.active); err != nil {
		return false
	}
	p.requests[pullTuple(id, tuple)] = now
	return true
}

// Batch only requests whose scheduler credit has already been earned. A short
// kernel send registers only its successful prefix; unsent tuples cannot fund
// feedback or inflate wire-success counters. No DATA waits in a batch queue.
func (b *BIP) sendPullProbes(now time.Time, quota int) int {
	b.flushDataBatch()
	if b.batchEmit == nil {
		sent := 0
		for i := 0; i < quota; i++ {
			if b.sendPullProbe(now) {
				sent++
			}
		}
		return sent
	}
	quota = min(quota, 4*b.window()-len(b.poll.requests))
	if quota <= 0 {
		return 0
	}
	if b.poll.requests == nil {
		b.poll.requests = make(map[uint32]time.Time)
	}
	sent := 0
	for remaining := quota; remaining > 0; {
		count := min(remaining, 64)
		packets := make([][]byte, 0, count)
		tuples := make([]uint32, 0, count)
		for i := 0; i < count; i++ {
			id, tuple := b.nextTuple()
			ip, err := b.prepareWire(8, id, tuple, bipKindPullProbe, 0, 0, nil, b.active)
			if err != nil {
				break
			}
			packets = append(packets, ip)
			tuples = append(tuples, pullTuple(id, tuple))
		}
		if len(packets) == 0 {
			break
		}
		n, err := b.batchEmit(packets)
		if errors.Is(err, syscall.ENOSYS) {
			b.batchEmit = nil
			n = 0
			for _, packet := range packets {
				if b.emit(packet) != nil {
					break
				}
				n++
			}
		}
		n = max(0, min(n, len(packets)))
		for i, packet := range packets {
			b.recordWireResult(packet, i < n)
			if i < n {
				b.poll.requests[tuples[i]] = now
			}
		}
		sent += n
		remaining -= count
		if n < count {
			break
		}
		if b.batchEmit == nil {
			for i := 0; i < remaining; i++ {
				if b.sendPullProbe(now) {
					sent++
				}
			}
			break
		}
	}
	return sent
}
