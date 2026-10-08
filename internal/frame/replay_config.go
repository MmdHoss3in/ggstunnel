package frame

// SetReplayWindow is a startup-only setting. Never shrink or reset an active
// replay history under the same key. Independent BIP delivery needs to cover
// its entire bounded outer flight multiplied by the packing limit.
func (c *Codec) SetReplayWindow(window uint64) {
	if c.peerSession != 0 || len(c.replay.sessions) != 0 {
		return
	}
	window = max(4096, min(window, 16*8192+4096))
	c.replayWindow = window
	c.replay = NewReplayGuard(window)
}
