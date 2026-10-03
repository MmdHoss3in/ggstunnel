package carrier

import (
	"math"
	"testing"
	"time"
)

func FuzzTunerEventBounds(f *testing.F) {
	f.Add([]byte{1, 4, 7, 8, 20, 40, 255, 0})
	f.Add([]byte{255, 255, 255, 1, 1, 1})
	f.Fuzz(func(t *testing.T, events []byte) {
		if len(events) > 1024 {
			events = events[:1024]
		}
		x := adaptiveTuner()
		now := time.Unix(100, 0)
		for _, e := range events {
			now = now.Add(time.Duration(int(e)+1) * time.Millisecond)
			switch e % 5 {
			case 0:
				x.onAck(int(e)+1, time.Duration(int(e)+1)*time.Millisecond, now)
			case 1:
				x.onTimeout(now)
			case 2:
				x.pathChanged()
			case 3:
				x.allow(now, true)
			case 4:
				x.reset()
			}
			s := x.snapshot()
			if s.Window < 1 || s.Window > x.maxWindow || s.RTOMS < float64(x.cfg.MinRTOMS) || s.RTOMS > float64(x.cfg.MaxRTOMS) || s.PacingPPS > float64(x.cfg.MaxPPS) || s.PacingPPS <= 0 || math.IsNaN(s.PacingPPS) || math.IsInf(s.PacingPPS, 0) {
				t.Fatalf("controller bounds %+v", s)
			}
			if x.timeout(int(e)%33) > time.Duration(x.cfg.MaxRTOMS)*time.Millisecond {
				t.Fatal("backoff exceeded bound")
			}
		}
	})
}
