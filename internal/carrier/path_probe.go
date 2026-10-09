package carrier

import (
	"context"
	"encoding/binary"
	"errors"
	"time"

	"ggstunnel/internal/pathmtu"
)

type bipPathRequest struct {
	ctx     context.Context
	payload []byte
	result  chan error
}
type bipPathPending struct {
	request bipPathRequest
	token   uint32
	peer    uint64
}

func (b *BIP) SetPathPayload(payload int) {
	if payload >= 256 && payload <= b.cfg.Performance.MaxFramePayload {
		b.pathPayload.Store(int64(payload))
	}
}

// ProbePath uses disposable control, never reliable DATA: probe loss cannot
// create an undeliverable DATA hole. The actor owns its response correlation.
func (b *BIP) ProbePath(ctx context.Context, payload int) error {
	if payload < 256 || payload > b.cfg.Performance.MaxFramePayload {
		return errors.New("invalid BIP probe payload")
	}
	p, err := pathmtu.Request(payload + 152)
	if err != nil {
		return err
	}
	req := bipPathRequest{ctx, p, make(chan error, 1)}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-b.closed:
		return ErrClosed
	case b.pathRequests <- req:
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-b.closed:
		return ErrClosed
	case err := <-req.result:
		return err
	}
}

func (b *BIP) startPathProbe(req bipPathRequest) {
	if req.ctx.Err() != nil {
		req.result <- req.ctx.Err()
		return
	}
	if b.active == 0 {
		req.result <- ErrPeerNotReady
		return
	}
	if b.pathPending != nil {
		b.pathPending.request.result <- context.Canceled
	}
	token := binary.BigEndian.Uint32(req.payload[8:12])
	for token == 0 || token == b.fastToken {
		token++
	}
	b.pathPending = &bipPathPending{req, token, b.active}
	id, tuple := b.nextTuple()
	typ := byte(8)
	if time.Now().Before(b.fastUntil) {
		typ = 0
	}
	if err := b.send(typ, id, tuple, bipKindFastProbe, 0, token, req.payload, b.active); err != nil {
		req.result <- err
		b.pathPending = nil
	}
}

func (b *BIP) acceptPathReply(p wirePacket) bool {
	probe := b.pathPending
	if probe == nil || p.token != probe.token || p.sender != probe.peer {
		return false
	}
	if pathmtu.Matches(probe.request.payload, p.payload) {
		probe.request.result <- nil
		b.pathPending = nil
		return true
	}
	if len(p.payload) == 0 {
		probe.request.result <- pathmtu.ErrUnsupported
		b.pathPending = nil
	}
	return true
}

func probePayload(p wirePacket, overhead int) []byte {
	size, ok := pathmtu.Size(p.payload)
	if !ok || p.kind != bipKindFastProbe || size < overhead+pathmtu.Header {
		return p.payload
	}
	payload := make([]byte, size-overhead)
	copy(payload, p.payload[:pathmtu.Header])
	return payload
}
