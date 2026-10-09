package engine

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"sync"
	"testing"
	"time"

	"ggstunnel/internal/config"
)

func newBurstTestQueue() *fairPacketQueue {
	q := newFairPacketQueue()
	q.burst = true
	return q
}

func TestQueuePressureBurstAndPersistentBackpressure(t *testing.T) {
	q := newBurstTestQueue()
	now := time.Unix(10, 0)
	q.now = func() time.Time { return now }
	for i := 0; i < 400; i++ {
		if !q.push(flowPacket(1, uint16(i))) {
			t.Fatal("young burst rejected", i)
		}
	}
	now = now.Add(fairBurstAge)
	if q.push(flowPacket(1, 400)) {
		t.Fatal("persistent queue borrowed more capacity")
	}
	if !q.push(flowPacket(2, 42)) {
		t.Fatal("bulk displaced sparse flow")
	}
	first, _ := q.pop(context.Background())
	second, _ := q.pop(context.Background())
	if binary.BigEndian.Uint16(first[24:]) != 0 || binary.BigEndian.Uint16(second[20:]) != 2 {
		t.Fatal("sparse flow starved")
	}
	for i := 1; i < 400; i++ {
		p, err := q.pop(context.Background())
		if err != nil || binary.BigEndian.Uint16(p[24:]) != uint16(i) {
			t.Fatal("burst reordered", i, err)
		}
	}
	s := q.snapshot()
	if s.FlowLimitDrops != 1 || s.BurstAdmissions != 400-fairPacketsPerFlow || s.DepthPackets != 0 || s.DepthBytes != 0 || s.MaxSojournMS != 20 {
		t.Fatal("incorrect burst accounting", s)
	}
}

func TestQueuePressureWrappedRingGrowthPreservesFIFO(t *testing.T) {
	q := newBurstTestQueue()
	q.now = func() time.Time { return time.Unix(10, 0) }
	for i := 0; i < 16; i++ {
		q.push(flowPacket(1, uint16(i)))
	}
	for i := 0; i < 12; i++ {
		q.pop(context.Background())
	}
	for i := 16; i < fairBurstPacketsPerFlow+12; i++ {
		if !q.push(flowPacket(1, uint16(i))) {
			t.Fatal("ring failed to grow", i)
		}
	}
	if q.push(flowPacket(1, 999)) {
		t.Fatal("hard per-flow bound exceeded")
	}
	for i := 12; i < fairBurstPacketsPerFlow+12; i++ {
		p, err := q.pop(context.Background())
		if err != nil || binary.BigEndian.Uint16(p[24:]) != uint16(i) {
			t.Fatal("wrapped ring corrupted", i, err)
		}
	}
	if q.snapshot().PeakFlowPackets != fairBurstPacketsPerFlow {
		t.Fatal("missing peak")
	}
}

func TestQueuePressureByteAndFlowReasons(t *testing.T) {
	q := newBurstTestQueue()
	q.now = func() time.Time { return time.Unix(10, 0) }
	for i := 0; i < fairFlows; i++ {
		q.push(flowPacket(uint16(i), 0))
	}
	if q.push(flowPacket(fairFlows, 0)) {
		t.Fatal("flow count unbounded")
	}
	q.bytes = fairBytes // Simulate a full shared byte budget independently.
	if q.push(flowPacket(0, 1)) {
		t.Fatal("byte budget unbounded")
	}
	q.close(nil)
	if q.push(flowPacket(0, 2)) {
		t.Fatal("closed queue accepted data")
	}
	s := q.snapshot()
	if s.FlowCountDrops != 1 || s.ByteLimitDrops != 1 || s.ClosedDrops != 1 || s.IngressPackets != fairFlows+3 {
		t.Fatal("drop causes conflated", s)
	}
}

func TestQueuePressureActualSharedPayloadBudget(t *testing.T) {
	q := newBurstTestQueue()
	q.now = func() time.Time { return time.Unix(10, 0) }
	for port := 0; port < 32; port++ {
		p := append(flowPacket(uint16(port), 0), make([]byte, 1240)...)
		for i := 0; i < fairBurstPacketsPerFlow; i++ {
			q.push(p)
		}
	}
	s := q.snapshot()
	if s.ByteLimitDrops == 0 || s.PeakBytes > fairBytes || s.DepthBytes > fairBytes || s.PeakFlowPackets > fairBurstPacketsPerFlow {
		t.Fatal("real payload exceeded bounded reservoir", s)
	}
}

func TestQueuePressureConcurrentSnapshotAndIngress(t *testing.T) {
	q := newBurstTestQueue()
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(port uint16) {
			defer wg.Done()
			for j := 0; j < 1000; j++ {
				q.push(flowPacket(port, uint16(j)))
				q.snapshot()
			}
		}(uint16(i))
	}
	wg.Wait()
	s := q.snapshot()
	if s.IngressPackets != 8000 || s.DepthBytes > fairBytes || s.PeakFlowPackets > fairBurstPacketsPerFlow {
		t.Fatal("concurrent bounds violated", s)
	}
}

func TestQueuePressureTelemetryExportsAdmissionBeforeSend(t *testing.T) {
	q := newBurstTestQueue()
	q.push(flowPacket(1, 0))
	e := &Engine{cfg: &config.Config{Profile: "bip"}, packetQueue: q}
	b, err := json.Marshal(e.SnapshotTelemetry(time.Now()))
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]any
	if err := json.Unmarshal(b, &fields); err != nil {
		t.Fatal(err)
	}
	if fields["tun_ingress_packets"] != float64(1) || fields["queue_depth_packets"] != float64(1) || fields["tx_read_packets"] != float64(0) {
		t.Fatal("admission confused with successful transmission", string(b))
	}
}

func TestQueuePressureGenericRetainsOriginalBound(t *testing.T) {
	q := newFairPacketQueue()
	q.now = func() time.Time { return time.Unix(10, 0) }
	for i := 0; i < fairPacketsPerFlow; i++ {
		if !q.push(flowPacket(1, uint16(i))) {
			t.Fatal("early rejection")
		}
	}
	if q.push(flowPacket(1, 999)) || q.snapshot().BurstAdmissions != 0 {
		t.Fatal("generic carrier borrowed BIP burst capacity")
	}
}
