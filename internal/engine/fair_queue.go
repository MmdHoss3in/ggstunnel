package engine

import (
	"context"
	"io"
	"sync"
	"time"
)

const fairFlows = 1024
const fairPacketsPerFlow = 128
const fairBytes = 8 << 20

type flowKey [38]byte

// Ports distinguish ordinary TCP/UDP flows. IP fragments and IPv6 extension
// headers use an address/protocol bucket; malformed/non-IP packets share one.
func packetFlow(p []byte) (k flowKey) {
	if len(p) >= 20 && p[0]>>4 == 4 {
		h := int(p[0]&15) * 4
		if h < 20 || h > len(p) {
			return k
		}
		k[0], k[1] = 4, p[9]
		copy(k[2:10], p[12:20])
		if p[6]&0x3f == 0 && p[7] == 0 && (p[9] == 6 || p[9] == 17) && len(p) >= h+4 {
			copy(k[34:], p[h:h+4])
		}
	} else if len(p) >= 40 && p[0]>>4 == 6 {
		k[0], k[1] = 6, p[6]
		copy(k[2:34], p[8:40])
		if (p[6] == 6 || p[6] == 17) && len(p) >= 44 {
			copy(k[34:], p[40:44])
		}
	}
	return k
}

type packetFlowQueue struct {
	packets     [fairPacketsPerFlow][]byte
	queuedAt    [fairPacketsPerFlow]time.Time
	head, count int
	ready       bool
}

type fairPacketQueue struct {
	mu                 sync.Mutex
	flows              map[flowKey]*packetFlowQueue
	ready              [fairFlows]flowKey
	head, count, bytes int
	wake               chan struct{}
	err                error
	maxAge             time.Duration
	now                func() time.Time
	expired            func()
}

func newFairPacketQueue() *fairPacketQueue {
	return &fairPacketQueue{flows: make(map[flowKey]*packetFlowQueue), wake: make(chan struct{}, 1), now: time.Now}
}

// A full flow drops its newest packet without displacing other flows. Reads
// continue during outer outages, so sparse TCP retransmissions are retained
// instead of being lost behind bulk data in the kernel TUN's finite queue.
func (q *fairPacketQueue) push(p []byte) bool {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.err != nil {
		return false
	}
	now := q.now()
	k := packetFlow(p)
	f := q.flows[k]
	if f != nil {
		q.expireFlow(f, now)
	}
	if q.bytes+len(p) > fairBytes || f == nil && q.count >= fairFlows {
		q.expireAll(now)
	}
	if q.bytes+len(p) > fairBytes {
		return false
	}
	if f == nil {
		if len(q.flows) >= fairFlows {
			for key, idle := range q.flows {
				if idle.count == 0 && !idle.ready {
					delete(q.flows, key)
					break
				}
			}
			if len(q.flows) >= fairFlows {
				return false
			}
		}
		f = &packetFlowQueue{}
		q.flows[k] = f
	}
	if f.count == fairPacketsPerFlow {
		return false
	}
	if !f.ready {
		q.ready[(q.head+q.count)%fairFlows] = k
		q.count++
		f.ready = true
	}
	f.packets[(f.head+f.count)%fairPacketsPerFlow] = append([]byte(nil), p...)
	f.queuedAt[(f.head+f.count)%fairPacketsPerFlow] = now
	f.count++
	q.bytes += len(p)
	select {
	case q.wake <- struct{}{}:
	default:
	}
	return true
}

// Expire before admission as well as before delivery. Otherwise a full flow
// during an outage rejects fresh TCP retries behind packets that are too old
// to send, potentially extending recovery to the inner TCP's maximum RTO.
func (q *fairPacketQueue) expireFlow(f *packetFlowQueue, now time.Time) {
	if q.maxAge <= 0 {
		return
	}
	for f.count > 0 && now.Sub(f.queuedAt[f.head]) >= q.maxAge {
		q.bytes -= len(f.packets[f.head])
		f.packets[f.head] = nil
		f.queuedAt[f.head] = time.Time{}
		f.head = (f.head + 1) % fairPacketsPerFlow
		f.count--
		if q.expired != nil {
			q.expired()
		}
	}
}

func (q *fairPacketQueue) expireAll(now time.Time) {
	if q.maxAge <= 0 {
		return
	}
	for _, f := range q.flows {
		q.expireFlow(f, now)
	}
	var ready [fairFlows]flowKey
	n := 0
	for i := 0; i < q.count; i++ {
		key := q.ready[(q.head+i)%fairFlows]
		f := q.flows[key]
		if f.count == 0 {
			f.ready = false
			continue
		}
		ready[n] = key
		n++
	}
	q.ready = ready
	q.head = 0
	q.count = n
}

func (q *fairPacketQueue) close(err error) {
	q.mu.Lock()
	if err == nil {
		err = io.EOF
	}
	q.err = err
	q.mu.Unlock()
	select {
	case q.wake <- struct{}{}:
	default:
	}
}

func (q *fairPacketQueue) pop(ctx context.Context) ([]byte, error) {
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		q.mu.Lock()
		if q.err != nil {
			err := q.err
			q.mu.Unlock()
			return nil, err
		}
		if q.count > 0 {
			k := q.ready[q.head]
			q.head = (q.head + 1) % fairFlows
			q.count--
			f := q.flows[k]
			f.ready = false
			if f.count == 0 {
				q.mu.Unlock()
				continue
			}
			p := f.packets[f.head]
			stale := q.maxAge > 0 && q.now().Sub(f.queuedAt[f.head]) >= q.maxAge
			f.packets[f.head] = nil
			f.queuedAt[f.head] = time.Time{}
			f.head = (f.head + 1) % fairPacketsPerFlow
			f.count--
			q.bytes -= len(p)
			if f.count > 0 {
				q.ready[(q.head+q.count)%fairFlows] = k
				q.count++
				f.ready = true
			}
			q.mu.Unlock()
			if stale {
				if q.expired != nil {
					q.expired()
				}
				continue
			}
			return p, nil
		}
		q.mu.Unlock()
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-q.wake:
		}
	}
}

func (e *Engine) fairTunToCarrier(parent context.Context) error {
	ctx, cancel := context.WithCancel(parent)
	q := newFairPacketQueue()
	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 65535)
		for {
			n, err := e.tun.Read(buf)
			if err != nil {
				q.close(err)
				return
			}
			if ctx.Err() != nil {
				q.close(ctx.Err())
				return
			}
			if n > 0 && !q.push(buf[:n]) {
				e.drops.Add(1)
				e.tunQueueDrops.Add(1)
			}
		}
	}()
	defer func() { cancel(); _ = e.tun.Close(); <-done }()
	for {
		p, err := q.pop(ctx)
		if err != nil {
			return err
		}
		if err := e.sendPacket(ctx, p); err != nil {
			return err
		}
	}
}
