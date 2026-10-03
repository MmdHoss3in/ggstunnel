package carrier

import "testing"

func TestOrderedDeliveryRetainsSACKAndSuppressesInnerReordering(t *testing.T) {
	b := testBIP(t)
	b.rxAck.init = true
	for _, seq := range []uint32{1, 3, 4} {
		if !b.receiveOrdered(seq, []byte{byte(seq)}) {
			t.Fatal("frame rejected")
		}
	}
	if got := <-b.rx; got[0] != 1 {
		t.Fatal("wrong first frame")
	}
	if len(b.rx) != 0 {
		t.Fatal("future frames reached inner TCP before recovery")
	}
	ack, bits := b.takeAckForSend()
	if ack != 1 || bits != 0b110 {
		t.Fatal("retained future frames were not SACKed")
	}
	if !b.receiveOrdered(2, []byte{2}) {
		t.Fatal("missing frame rejected")
	}
	for want := byte(2); want <= 4; want++ {
		if got := <-b.rx; got[0] != want {
			t.Fatal("recovered frames are out of order")
		}
	}
}

func TestReorderBufferReservesRecoverySlot(t *testing.T) {
	b := testBIP(t)
	b.cfg.Performance.QueueSize = 3
	b.rxAck.init = true
	if !b.receiveOrdered(2, []byte{2}) || !b.receiveOrdered(3, []byte{3}) {
		t.Fatal("future frames rejected early")
	}
	if b.receiveOrdered(4, []byte{4}) || len(b.rxHold) != 2 {
		t.Fatal("reorder buffer did not reserve a slot")
	}
	if !b.receiveOrdered(1, []byte{1}) || len(b.rxHold) != 0 {
		t.Fatal("full reorder buffer deadlocked the missing frame")
	}
	for want := byte(1); want <= 3; want++ {
		if got := <-b.rx; got[0] != want {
			t.Fatal("reserved-slot recovery reordered frames")
		}
	}
}

func TestOrderedDeliveryWrapAndConsumerBackpressure(t *testing.T) {
	b := testBIP(t)
	b.rx = make(chan []byte, 1)
	b.rxAck.init = true
	b.rxAck.max = 0xfffffffd
	b.rxNext = 0xfffffffe
	for _, seq := range []uint32{1, 0xffffffff, 0xfffffffe, 2} {
		if !b.receiveOrdered(seq, []byte{byte(seq)}) {
			t.Fatal("wrapped frame rejected")
		}
	}
	for _, want := range []byte{254, 255, 1, 2} {
		if got := <-b.rx; got[0] != want {
			t.Fatal("wrap or consumer backpressure lost ordering")
		}
		b.drainRX()
	}
	if len(b.rxHold) != 0 {
		t.Fatal("drained receiver retained payloads")
	}
}
