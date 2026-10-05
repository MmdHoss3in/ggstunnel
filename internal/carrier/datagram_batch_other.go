//go:build !linux || (!amd64 && !arm64)

package carrier

import "context"

func (u *UDP) readLoop(ctx context.Context)         { u.readLoopScalar(ctx) }
func (u *UDP) writeLoop(ctx context.Context)        { u.writeLoopScalar(ctx) }
func (r *rawCarrier) readLoop(ctx context.Context)  { r.readLoopScalar(ctx) }
func (r *rawCarrier) writeLoop(ctx context.Context) { r.writeLoopScalar(ctx) }
