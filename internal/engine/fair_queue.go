package engine

import (
	"context"
	"io"
	"sync"
	"time"
)

const fairFlows = 1024
const fairBasePacketsPerFlow = 128
const fairPacketsPerFlow = 512
const fairBytes = 8 << 20
const fairBurstAge = 20 * time.Millisecond

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
	packets     [][]byte
	queuedAt    []time.Time
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
	stats              QueueTelemetry
}

// Counters include packets rejected before tx_read_packets is incremented.
// No addresses, ports or flow identities are exported.
type QueueTelemetry struct {
	IngressPackets  uint64  `json:"tun_ingress_packets"`
	FlowLimitDrops  uint64  `json:"queue_flow_limit_drops"`
	ByteLimitDrops  uint64  `json:"queue_byte_limit_drops"`
	FlowCountDrops  uint64  `json:"queue_flow_count_drops"`
	ClosedDrops     uint64  `json:"queue_closed_drops"`
	BurstAdmissions uint64  `json:"queue_burst_admissions"`
	DepthPackets    uint64  `json:"queue_depth_packets"`
	DepthBytes      uint64  `json:"queue_depth_bytes"`
	ActiveFlows     uint64  `json:"queue_active_flows"`
	PeakPackets     uint64  `json:"queue_peak_packets"`
	PeakBytes       uint64  `json:"queue_peak_bytes"`
	PeakFlowPackets uint64  `json:"queue_peak_flow_packets"`
	MaxSojournMS    float64 `json:"queue_max_sojourn_ms"`
}

func (q *fairPacketQueue) snapshot() QueueTelemetry {
	q.mu.Lock()
	defer q.mu.Unlock()
	s := q.stats
	s.DepthBytes, s.ActiveFlows = uint64(q.bytes), uint64(q.count)
	return s
}

func newFairPacketQueue() *fairPacketQueue {
	return &fairPacketQueue{flows: make(map[flowKey]*packetFlowQueue), wake: make(chan struct{}, 1), now: time.Now}
}

// Borrow bounded capacity for a young burst, not a persistently blocked flow.
// The 8MiB shared budget and round-robin service remain unchanged. Reads
// continue during outer outages, so sparse TCP retransmissions are retained
// instead of being lost behind bulk data in the kernel TUN's finite queue.
func (q *fairPacketQueue) push(p []byte) bool {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.stats.IngressPackets++
	if q.err != nil {
		q.stats.ClosedDrops++
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
		q.stats.ByteLimitDrops++
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
				q.stats.FlowCountDrops++
				return false
			}
		}
		f = &packetFlowQueue{packets: make([][]byte, 16), queuedAt: make([]time.Time, 16)}
		q.flows[k] = f
	}
	if f.count == fairPacketsPerFlow || f.count >= fairBasePacketsPerFlow && now.Sub(f.queuedAt[f.head]) >= fairBurstAge {
		q.stats.FlowLimitDrops++
		return false
	}
	if f.count == len(f.packets) {
		// Allocate metadata only for flows that actually need a larger ring.
		n := min(2*len(f.packets), fairPacketsPerFlow)
		packets, times := make([][]byte, n), make([]time.Time, n)
		for i := 0; i < f.count; i++ {
			j := (f.head + i) % len(f.packets)
			packets[i], times[i] = f.packets[j], f.queuedAt[j]
		}
		f.packets, f.queuedAt, f.head = packets, times, 0
	}
	if f.count >= fairBasePacketsPerFlow {
		q.stats.BurstAdmissions++
	}
	if !f.ready {
		q.ready[(q.head+q.count)%fairFlows] = k
		q.count++
		f.ready = true
	}
	f.packets[(f.head+f.count)%len(f.packets)] = append([]byte(nil), p...)
	f.queuedAt[(f.head+f.count)%len(f.packets)] = now
	f.count++
	q.bytes += len(p)
	q.stats.DepthPackets++
	q.stats.PeakPackets = max(q.stats.PeakPackets, q.stats.DepthPackets)
	q.stats.PeakBytes = max(q.stats.PeakBytes, uint64(q.bytes))
	q.stats.PeakFlowPackets = max(q.stats.PeakFlowPackets, uint64(f.count))
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
		f.head = (f.head + 1) % len(f.packets)
		f.count--
		q.stats.DepthPackets--
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
			age := q.now().Sub(f.queuedAt[f.head])
			stale := q.maxAge > 0 && age >= q.maxAge
			q.stats.MaxSojournMS = max(q.stats.MaxSojournMS, float64(age)/float64(time.Millisecond))
			f.packets[f.head] = nil
			f.queuedAt[f.head] = time.Time{}
			f.head = (f.head + 1) % len(f.packets)
			f.count--
			q.stats.DepthPackets--
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
