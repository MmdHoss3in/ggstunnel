package engine

import (
	"context"
	"errors"
	"fmt"
	"log"
	"time"

	"ggstunnel/internal/carrier"
	"ggstunnel/internal/frame"
	"ggstunnel/internal/pathmtu"
)

var errPathReduced = errors.New("authenticated path size reduced")

func (e *Engine) setPathPayload(size int) {
	e.effectivePayload.Store(int64(size))
	if c, ok := e.carrier.(interface{ SetPathPayload(int) }); ok {
		c.SetPathPayload(size)
	}
}

func (e *Engine) sendControl(payload []byte) error {
	if e.cfg.Transport.OpaqueSession == "challenge" {
		peer := e.carrier.(interface{ PeerSession() uint64 }).PeerSession()
		if peer == 0 {
			return carrier.ErrPeerNotReady
		}
		if err := e.codec.BindSendPeer(peer); err != nil {
			return err
		}
	}
	w, err := e.codec.Seal(frame.TypeHeartbeat, 0, 0, 1, payload)
	if err != nil {
		return err
	}
	return e.carrier.Send(w)
}

// Called only after AEAD and current-session replay verification.
func (e *Engine) receivePathControl(payload []byte) error {
	if size, ok := pathmtu.Size(payload); ok && len(payload) == size && size <= e.cfg.Performance.MaxFramePayload {
		return e.sendControl(pathmtu.Reply(payload))
	}
	if len(payload) == pathmtu.Header && payload[4] == 2 {
		select {
		case e.pathReplies <- append([]byte(nil), payload...):
		default:
		}
	}
	return nil
}

func (e *Engine) probePath(parent context.Context, size int) error {
	ctx, cancel := context.WithTimeout(parent, time.Second)
	defer cancel()
	if c, ok := e.carrier.(interface {
		ProbePath(context.Context, int) error
	}); ok {
		return c.ProbePath(ctx, size)
	}
	request, err := pathmtu.Request(size)
	if err != nil {
		return err
	}
	packet := make([]byte, size)
	copy(packet, request)
	if err := e.sendControl(packet); err != nil {
		return err
	}
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case reply := <-e.pathReplies:
			if pathmtu.Matches(request, reply) {
				return nil
			}
		}
	}
}

func (e *Engine) confirmedSize(ctx context.Context, size int) error {
	var err error
	for attempt := 0; attempt < 3; attempt++ {
		err = e.probePath(ctx, size)
		if err == nil || errors.Is(err, pathmtu.ErrUnsupported) || ctx.Err() != nil {
			return err
		}
	}
	return err
}

func waitPath(ctx context.Context, delay time.Duration) bool {
	t := time.NewTimer(delay)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

func (e *Engine) pathMTULoop(ctx context.Context) error {
	ceiling := e.cfg.Performance.MaxFramePayload
	for {
		// A total outage is not evidence of a smaller MTU.
		e.pathState.Store("searching")
		err := e.confirmedSize(ctx, 256)
		if errors.Is(err, pathmtu.ErrUnsupported) {
			e.pathState.Store("unsupported")
			e.setPathPayload(ceiling)
			log.Print("peer lacks authenticated size probes; configured local payload retained")
			<-ctx.Done()
			return ctx.Err()
		}
		if err != nil {
			if !waitPath(ctx, time.Second) {
				return ctx.Err()
			}
			continue
		}
		low, high := 256, ceiling
		if err := e.confirmedSize(ctx, high); err == nil {
			low = high
		} else {
			high--
		}
		for high-low >= 16 && ctx.Err() == nil {
			candidate := low + (high-low+1)/2
			if err := e.confirmedSize(ctx, candidate); err == nil {
				low = candidate
			} else {
				high = candidate - 1
			}
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		e.setPathPayload(low)
		e.pathState.Store("confirmed")
		log.Printf("authenticated directional path payload confirmed=%d ceiling=%d", low, ceiling)
		for waitPath(ctx, 30*time.Second) {
			current := int(e.effectivePayload.Load())
			if err := e.confirmedSize(ctx, current); err != nil {
				if e.confirmedSize(ctx, 256) == nil {
					e.setPathPayload(256)
					e.pathState.Store("reduced")
					// Old oversized encrypted DATA cannot be rewritten safely.
					return fmt.Errorf("payload %d no longer confirmed: %w", current, errPathReduced)
				}
				e.pathState.Store("unconfirmed")
				continue
			}
			e.pathState.Store("confirmed")
			if current < ceiling && e.confirmedSize(ctx, ceiling) == nil {
				e.setPathPayload(ceiling)
			}
		}
		return ctx.Err()
	}
}
