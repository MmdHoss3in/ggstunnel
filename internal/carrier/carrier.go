package carrier

import (
	"context"
	"errors"

	"ggstunnel/internal/config"
)

var ErrQueueFull = errors.New("carrier transmit queue full")

type Carrier interface {
	Start(context.Context) error
	Send([]byte) error
	Recv() <-chan []byte
	Close() error
	Name() string
}

// RuntimeStats is optional carrier telemetry used by the engine's periodic
// status line. Counters are cumulative since process start.
type RuntimeStats struct {
	WireTxBytes uint64 `json:"wire_tx_bytes"`
	WireRxBytes uint64 `json:"wire_rx_bytes"`

	FastDataTx      uint64 `json:"fast_data_tx"`
	PullDataTx      uint64 `json:"pull_data_tx"`
	BootstrapDataTx uint64 `json:"bootstrap_data_tx"`
	CompatDataTx    uint64 `json:"compat_data_tx"`
	IdleProbeTx     uint64 `json:"idle_probe_tx"`
	FastProbeTx     uint64 `json:"fast_probe_tx"`
	FastAckTx       uint64 `json:"fast_ack_tx"`
	NeedPullTx      uint64 `json:"need_pull_tx"`
	PullProbeTx     uint64 `json:"pull_probe_tx"`

	FastAckRx             uint64 `json:"fast_ack_rx"`
	NeedPullRx            uint64 `json:"need_pull_rx"`
	PullProbeRx           uint64 `json:"pull_probe_rx"`
	ReflectionsSuppressed uint64 `json:"reflections_suppressed"`
	PayloadFrameRx        uint64 `json:"payload_frame_rx"`
	HMACFail              uint64 `json:"hmac_fail"`
	MalformedWire         uint64 `json:"malformed_wire"`
	UnknownSession        uint64 `json:"unknown_session"`
	DataDuplicate         uint64 `json:"data_duplicate"`

	Pending         uint64 `json:"pending"`
	Backlog         uint64 `json:"backlog"`
	PendingExpired  uint64 `json:"pending_expired"`
	PendingOverflow uint64 `json:"pending_overflow"`
	Retransmits     uint64 `json:"retransmits"`
	FastPromotions  uint64 `json:"fast_promotions"`
	FastDemotions   uint64 `json:"fast_demotions"`
	FastHealthy     bool   `json:"fast_healthy"`
	PullActive      bool   `json:"pull_active"`
	CompatActive    bool   `json:"compat_active"`
	TxErrors        uint64 `json:"tx_errors"`

	FastRetransmits uint64 `json:"fast_retransmits"`
	ReorderBuffered uint64 `json:"reorder_buffered"`
}

type Statser interface{ SnapshotStats() RuntimeStats }

func New(c *config.Config) (Carrier, error) {
	switch c.Profile {
	case "tcp":
		return NewTCP(c), nil
	case "udp":
		return NewUDP(c), nil
	case "icmp":
		return NewRaw(c, "icmp")
	case "gre":
		return NewRaw(c, "gre")
	case "ipip":
		return NewRaw(c, "ipip")
	case "bip":
		return NewBIP(c)
	default:
		return nil, errors.New("unsupported carrier")
	}
}

func enqueue(ch chan []byte, b []byte) error {
	cp := append([]byte(nil), b...)
	select {
	case ch <- cp:
		return nil
	default:
		return ErrQueueFull
	}
}

// Reliable stream carriers can propagate pressure back to TUN instead of
// inducing an unrelated loss in the inner TCP flow. The queue stays bounded.
func enqueueContext(ctx context.Context, closed <-chan struct{}, ch chan []byte, b []byte) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-closed:
		return errors.New("carrier closed")
	default:
	}
	cp := append([]byte(nil), b...)
	select {
	case ch <- cp:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	case <-closed:
		return errors.New("carrier closed")
	}
}
