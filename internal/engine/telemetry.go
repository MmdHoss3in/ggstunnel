package engine

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"ggstunnel/internal/carrier"
)

// Telemetry contains no PSK, session identity, public address or config dump.
type Telemetry struct {
	SchemaVersion          int                    `json:"schema_version"`
	At                     time.Time              `json:"at"`
	Role                   string                 `json:"role"`
	Profile                string                 `json:"profile"`
	TxReadPackets          uint64                 `json:"tx_read_packets"`
	RxDeliveredPackets     uint64                 `json:"rx_delivered_packets"`
	TxReadBytes            uint64                 `json:"tx_read_bytes"`
	RxDeliveredBytes       uint64                 `json:"rx_delivered_bytes"`
	EnqueueDrops           uint64                 `json:"enqueue_drops"`
	Replays                uint64                 `json:"replays"`
	AuthenticationFailures uint64                 `json:"authentication_failures"`
	Malformed              uint64                 `json:"malformed"`
	Carrier                *carrier.RuntimeStats  `json:"carrier,omitempty"`
	Tuner                  *carrier.TunerSnapshot `json:"tuner,omitempty"`
}

func (e *Engine) SnapshotTelemetry(now time.Time) Telemetry {
	s := Telemetry{SchemaVersion: 1, At: now.UTC(), Role: e.cfg.Role, Profile: e.cfg.Profile,
		TxReadPackets: e.txPackets.Load(), RxDeliveredPackets: e.rxPackets.Load(),
		TxReadBytes: e.txBytes.Load(), RxDeliveredBytes: e.rxBytes.Load(), EnqueueDrops: e.drops.Load(),
		Replays: e.replays.Load(), AuthenticationFailures: e.authFails.Load(), Malformed: e.malformed.Load()}
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
