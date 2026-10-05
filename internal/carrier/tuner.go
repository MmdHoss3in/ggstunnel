package carrier

import (
	"math"
	"time"

	"ggstunnel/internal/config"
)

// Actor-owned controller. It changes local scheduling, never wire identities,
// the packet MTU or global sysctls. This is not a TCP congestion implementation.
type bipTuner struct {
	cfg                             config.TunerConfig
	maxWindow                       int
	initialRTO, srtt, variance, rto time.Duration
	cwnd, threshold, credit         float64
	lastCredit, recoveryUntil       time.Time
	acked, samples, cuts, resets    uint64
	hasCleanFeedback                bool
}

type TunerSnapshot struct {
	WindowLimit    int     `json:"window_limit_frames"`
	Mode           string  `json:"mode"`
	SRTTMS         float64 `json:"srtt_ms"`
	RTTVariationMS float64 `json:"rtt_variation_ms"`
	RTOMS          float64 `json:"rto_ms"`
	Window         int     `json:"window_frames"`
	PacingPPS      float64 `json:"pacing_pps"`
	Burst          int     `json:"burst_frames"`
	AckedFrames    uint64  `json:"acked_frames"`
	RTTSamples     uint64  `json:"rtt_samples"`
	CongestionCuts uint64  `json:"congestion_cuts"`
	Resets         uint64  `json:"resets"`
}

func (t *bipTuner) resizeWindow(limit int) {
	if t.threshold >= float64(t.maxWindow) {
		t.threshold = float64(limit)
	}
	t.maxWindow = limit
	t.cwnd = math.Min(t.cwnd, float64(limit))
	t.credit = math.Min(t.credit, float64(t.burst()))
}

func newBIPTuner(c *config.Config) *bipTuner {
	maxWindow := min(c.Performance.QueueSize, 4096)
	t := &bipTuner{cfg: c.Tuner, maxWindow: maxWindow, initialRTO: time.Duration(c.Transport.BIPRTOMS) * time.Millisecond}
	t.reset()
	return t
}
func (t *bipTuner) adaptive() bool { return t.cfg.Mode == "adaptive" }
func (t *bipTuner) clampRTO(r time.Duration) time.Duration {
	if !t.adaptive() {
		return t.initialRTO
	}
	return max(time.Duration(t.cfg.MinRTOMS)*time.Millisecond, min(r, time.Duration(t.cfg.MaxRTOMS)*time.Millisecond))
}
func (t *bipTuner) reset() {
	t.srtt = 0
	t.variance = 0
	t.rto = t.clampRTO(t.initialRTO)
	t.cwnd = float64(min(16, t.maxWindow))
	t.threshold = float64(t.maxWindow)
	t.credit = float64(t.burst())
	t.lastCredit = time.Time{}
	t.recoveryUntil = time.Time{}
	t.hasCleanFeedback = false
	t.resets++
}
func (t *bipTuner) window() int {
	if !t.adaptive() {
		return t.maxWindow
	}
	return max(1, min(int(t.cwnd), t.maxWindow))
}
func (t *bipTuner) burst() int { return max(1, min(t.cfg.MaxBurst, t.window())) }
func (t *bipTuner) rate() float64 {
	rtt := t.srtt
	if rtt == 0 {
		rtt = t.rto / 3
	}
	rtt = max(rtt, time.Millisecond)
	rate := float64(t.window()) / rtt.Seconds()
	if t.cfg.UnlimitedRate {
		return rate
	}
	return math.Min(float64(t.cfg.MaxPPS), rate)
}
func (t *bipTuner) allow(now time.Time, consume bool) bool {
	if !t.adaptive() {
		return true
	}
	if !t.lastCredit.IsZero() {
		dt := max(0, now.Sub(t.lastCredit).Seconds())
		t.credit = math.Min(float64(t.burst()), t.credit+dt*t.rate())
	}
	t.lastCredit = now
	if t.credit < 1 {
		return false
	}
	if consume {
		t.credit--
	}
	return true
}

// One unambiguous sample per ACK batch; retransmitted packets are excluded by
// the caller (Karn). ACKs covering only retries do not clear recovery or grow.
func (t *bipTuner) onAck(clean int, sample time.Duration, now time.Time) {
	if !t.adaptive() || clean == 0 || sample <= 0 {
		return
	}
	t.hasCleanFeedback = true
	if t.srtt == 0 {
		t.srtt = sample
		t.variance = sample / 2
	} else {
		delta := t.srtt - sample
		if delta < 0 {
			delta = -delta
		}
		t.variance = (3*t.variance + delta) / 4
		t.srtt = (7*t.srtt + sample) / 8
	}
	t.samples++
	// Data ACK delay can exceed quiet-path RTT under load. Keep a safety margin
	// instead of an 82ms timeout on a measured ~80ms Internet path.
	t.rto = t.clampRTO(max(2*t.srtt, t.srtt+max(25*time.Millisecond, 4*t.variance)))
	if now.Before(t.recoveryUntil) {
		return
	}
	for i := 0; i < clean; i++ {
		if t.cwnd < t.threshold {
			t.cwnd++
		} else {
			// Scale recovery at large BDP; at least one packet per RTT.
			t.cwnd += math.Max(1, t.cwnd/64) / t.cwnd
		}
		t.cwnd = math.Min(t.cwnd, float64(t.maxWindow))
	}
}
func (t *bipTuner) onTimeout(now time.Time) {
	if !t.adaptive() || now.Before(t.recoveryUntil) {
		return
	}
	t.threshold = math.Max(1, t.cwnd/2)
	t.cwnd = t.threshold
	t.credit = math.Min(t.credit, float64(t.burst()))
	t.recoveryUntil = now.Add(t.rto)
	t.cuts++
}

// A SACK hole with subsequent deliveries still has a working ACK clock.
// Reduce capacity, but do not apply the same penalty and full-RTO pause as
// a stalled delivery. Pacing and the per-flight loss guard remain active.
func (t *bipTuner) onFastLoss(now time.Time) {
	if !t.adaptive() || now.Before(t.recoveryUntil) {
		return
	}
	t.threshold = math.Max(1, t.cwnd*0.8)
	t.cwnd = t.threshold
	t.credit = math.Min(t.credit, float64(t.burst()))
	delay := t.srtt
	if delay <= 0 {
		delay = t.rto
	}
	t.recoveryUntil = now.Add(max(10*time.Millisecond, delay))
	t.cuts++
}

// A path transition invalidates timing, not all learned capacity. Congestion
// cuts remain the responsibility of loss recovery, avoiding a second cut to 16.
func (t *bipTuner) pathChanged() {
	if !t.adaptive() {
		return
	}
	t.srtt = 0
	t.variance = 0
	t.rto = t.clampRTO(t.initialRTO)
	// A blocked bootstrap carrier can time out before the first usable DATA
	// acknowledgement. Do not carry its tiny loss threshold into a newly
	// authenticated working path and then crawl through additive recovery.
	// After genuine DATA feedback, retain the learned congestion threshold.
	if !t.hasCleanFeedback {
		t.threshold = float64(t.maxWindow)
	}
	// Never set the threshold to the current flight merely because timing
	// changed: that would invent a new congestion event at a tiny window.
	t.credit = math.Min(t.credit, float64(t.burst()))
	t.resets++
}
func (t *bipTuner) timeout(retries int) time.Duration {
	if !t.adaptive() {
		return t.initialRTO
	}
	return t.clampRTO(t.rto * time.Duration(1<<min(retries, 6)))
}
func (t *bipTuner) snapshot() TunerSnapshot {
	if !t.adaptive() {
		return TunerSnapshot{WindowLimit: t.maxWindow, Mode: t.cfg.Mode, RTOMS: float64(t.initialRTO) / float64(time.Millisecond), Window: t.maxWindow, AckedFrames: t.acked, Resets: t.resets}
	}
	return TunerSnapshot{WindowLimit: t.maxWindow, Mode: t.cfg.Mode, SRTTMS: float64(t.srtt) / float64(time.Millisecond), RTTVariationMS: float64(t.variance) / float64(time.Millisecond), RTOMS: float64(t.rto) / float64(time.Millisecond), Window: t.window(), PacingPPS: t.rate(), Burst: t.burst(), AckedFrames: t.acked, RTTSamples: t.samples, CongestionCuts: t.cuts, Resets: t.resets}
}
