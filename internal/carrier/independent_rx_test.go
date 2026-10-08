package carrier

import "testing"

func TestIndependentDeliveryDoesNotBlockUnrelatedPackets(t *testing.T) {
	b := testBIP(t)
	b.cfg.Transport.BIPDelivery = "independent"
	for _, seq := range []uint32{1, 3, 4} {
		if !b.receivePayload(seq, []byte{byte(seq)}, false) {
			t.Fatal("valid independent packet rejected")
		}
		if got := <-b.rx; got[0] != byte(seq) {
			t.Fatal("unrelated flow held behind a hole")
		}
	}
	ack, bits := b.takeAckForSend()
	if ack != 1 || bits != 0b110 || len(b.rxHold) != 0 {
		t.Fatal("independent delivery lost reliable hole tracking", ack, bits)
	}
	if !b.receivePayload(2, []byte{2}, false) {
		t.Fatal("retry not accepted")
	}
	if got := <-b.rx; got[0] != 2 {
		t.Fatal("retry lost")
	}
	ack, _ = b.takeAckForSend()
	if ack != 4 {
		t.Fatal("retained SACK horizon did not advance", ack)
	}
}

func TestIndependentPackedAdmissionIsAtomic(t *testing.T) {
	b := testBIP(t)
	b.rx = make(chan []byte, 2)
	b.rx <- []byte("busy")
	p := appendPackedFrame([]byte{2}, []byte("a"))
	p = appendPackedFrame(p, []byte("b"))
	if b.receiveIndependentPayload(1, p, true) || len(b.rx) != 1 || b.rxAck.max != 0 {
		t.Fatal("partly admitted bundle was acknowledged")
	}
	<-b.rx
	if !b.receiveIndependentPayload(1, p, true) || string(<-b.rx) != "a" || string(<-b.rx) != "b" {
		t.Fatal("retry did not deliver complete bundle")
	}
}
