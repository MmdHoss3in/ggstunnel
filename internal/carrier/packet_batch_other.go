//go:build !linux || (!amd64 && !arm64)

package carrier

import "context"

func (b *BIP) readLoop(ctx context.Context) { b.readLoopScalar(ctx) }
