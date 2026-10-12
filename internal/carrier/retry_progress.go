package carrier

import "time"

// Karn still excludes repaired DATA from SRTT/base RTT. Its total lifetime is
// only a conservative timeout hint, not an RTT or bandwidth measurement. This
// bounded probe lets a generation with *only* repaired ACKs obtain a clean
// sample instead of staying forever at one frame and the initial 250ms timer.
func (t *bipTuner) onRetryProgress(age time.Duration, now time.Time) {
	if !t.adaptive() || t.cfg.Algorithm != "delivery" || t.srtt != 0 || age <= 0 {
		return
	}
	if !t.lastRetryProgress.IsZero() && now.Sub(t.lastRetryProgress) < t.rto {
		return
	}
	t.lastRetryProgress = now
	t.rto = t.clampRTO(max(t.rto, 2*age))
	// This is discovery headroom, not a minimum capacity or an unlimited
	// repair-driven slow start. Ordinary pacing/flight/retry bounds still apply.
	t.cwnd = max(t.cwnd, min(float64(min(16, t.maxWindow)), t.cwnd+1))
	t.threshold = max(t.threshold, t.cwnd)
	t.credit = min(t.credit, float64(t.burst()))
}
