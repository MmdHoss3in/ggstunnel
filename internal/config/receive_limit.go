package config

// PreserveReceiveFrameLimit separates local TX MTU protection from the peer's
// already configured receive contract. A local clamp must not reject larger
// authenticated frames arriving from a peer with a different local interface.
// Called before workers start. This runtime-only value is not serialized.
func (c *Config) PreserveReceiveFrameLimit() {
	if c.receiveFrameLimit == 0 {
		c.receiveFrameLimit = c.Performance.MaxFramePayload + 60
	}
}

func (c *Config) ReceiveFrameLimit() int {
	if c.receiveFrameLimit != 0 {
		return c.receiveFrameLimit
	}
	return c.Performance.MaxFramePayload + 60
}
