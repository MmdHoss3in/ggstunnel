package carrier

import "container/heap"

// Indexed heap: one entry per outstanding frame. ACK removal is O(log n),
// checking for an expired frame is O(1), and stale entries never accumulate.
type pendingHeap []*pendingData

func (h pendingHeap) Len() int { return len(h) }
func (h pendingHeap) Less(i, j int) bool { return h[i].deadline.Before(h[j].deadline) }
func (h pendingHeap) Swap(i, j int) { h[i], h[j] = h[j], h[i]; h[i].index = i; h[j].index = j }
func (h *pendingHeap) Push(v any) { p := v.(*pendingData); p.index = len(*h); *h = append(*h, p) }
func (h *pendingHeap) Pop() any {
	a := *h; p := a[len(a)-1]; a[len(a)-1] = nil
	*h = a[:len(a)-1]; p.index = -1; return p
}

// Caller holds ackMu. Synthetic test entries need not be in the heap.
func (b *BIP) removePending(p *pendingData) {
	if p.index >= 0 && p.index < len(b.retryHeap) && b.retryHeap[p.index] == p {
		heap.Remove(&b.retryHeap, p.index)
	}
	delete(b.pending, p.item.seq)
}
