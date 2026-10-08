package engine

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"ggstunnel/internal/carrier"
)

// Telemetry contains no PSK, session identity, public address or config dump.
type Telemetry struct {
	Recoveries             uint64                 `json:"internal_recoveries"`
	Goroutines             int                    `json:"goroutines"`
	HeapAllocBytes         uint64                 `json:"heap_alloc_bytes"`
	SchemaVersion          int                    `json:"schema_version"`
	At                     time.Time              `json:"at"`
	Role                   string                 `json:"role"`
	Profile                string                 `json:"profile"`
	WireMode               string                 `json:"wire_mode,omitempty"`
	EffectivePayload       int64                  `json:"effective_frame_payload"`
	OuterMTU               int64                  `json:"local_underlay_mtu,omitempty"`
	PeerAuthenticated      bool                   `json:"peer_authenticated"`
	PeerSilenceMS          int64                  `json:"peer_silence_ms"`
	TxReadPackets          uint64                 `json:"tx_read_packets"`
	RxDeliveredPackets     uint64                 `json:"rx_delivered_packets"`
	TxReadBytes            uint64                 `json:"tx_read_bytes"`
	RxDeliveredBytes       uint64                 `json:"rx_delivered_bytes"`
	EnqueueDrops           uint64                 `json:"enqueue_drops"`
	TUNQueueDrops          uint64                 `json:"tun_queue_drops"`
	Replays                uint64                 `json:"replays"`
	AuthenticationFailures uint64                 `json:"authentication_failures"`
	Malformed              uint64                 `json:"malformed"`
	Carrier                *carrier.RuntimeStats  `json:"carrier,omitempty"`
	Tuner                  *carrier.TunerSnapshot `json:"tuner,omitempty"`
}

func (e *Engine) SnapshotTelemetry(now time.Time) Telemetry {
	e.transportMu.RLock()
	defer e.transportMu.RUnlock()
	var memory runtime.MemStats
	runtime.ReadMemStats(&memory)
	s := Telemetry{SchemaVersion: 1, At: now.UTC(), Role: e.cfg.Role, Profile: e.cfg.Profile,
		Recoveries: e.recoveries.Load(), Goroutines: runtime.NumGoroutine(), HeapAllocBytes: memory.HeapAlloc,
		TxReadPackets: e.txPackets.Load(), RxDeliveredPackets: e.rxPackets.Load(),
		TxReadBytes: e.txBytes.Load(), RxDeliveredBytes: e.rxBytes.Load(), EnqueueDrops: e.drops.Load(),
		TUNQueueDrops: e.tunQueueDrops.Load(),
		Replays:       e.replays.Load(), AuthenticationFailures: e.authFails.Load(), Malformed: e.malformed.Load()}
	s.WireMode = e.cfg.Transport.WireMode
	s.EffectivePayload, s.OuterMTU = e.effectivePayload.Load(), e.outerMTU.Load()
	if at := e.authenticatedRX.Load(); at != 0 {
		s.PeerAuthenticated = true
		s.PeerSilenceMS = max(0, now.Sub(time.Unix(0, at)).Milliseconds())
	}
	if c, ok := e.carrier.(carrier.Statser); ok {
		v := c.SnapshotStats()
		s.Carrier = &v
	}
	if c, ok := e.carrier.(interface{ SnapshotTuner() carrier.TunerSnapshot }); ok {
		v := c.SnapshotTuner()
		s.Tuner = &v
	}
	return s
}

// Rename publishes a whole JSON document. The directory must already exist.
// An existing symlink or non-regular destination is rejected. Old permissions
// are not inherited: every snapshot is created with mode 0600.
func writeTelemetry(path string, s Telemetry) error {
	if fi, err := os.Lstat(path); err == nil {
		if !fi.Mode().IsRegular() {
			return fmt.Errorf("stats destination must be a regular file")
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	b = append(b, '\n')
	f, err := os.CreateTemp(filepath.Dir(path), ".ggstunnel-stats-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if _, err = f.Write(b); err != nil {
		f.Close()
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	return os.Rename(f.Name(), path)
}
