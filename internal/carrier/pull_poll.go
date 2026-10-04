package carrier

import (
	"math"
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
		p.rate = 1000
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
	if len(p.requests) >= b.window() {
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
