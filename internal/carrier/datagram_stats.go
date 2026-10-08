package carrier

import "sync/atomic"

// Byte counters describe bytes returned by/written to the IP/UDP socket,
// excluding the outer IPv4 header and UDP header, not datacenter NIC billing.
type datagramStats struct {
	rxBytes, txBytes, rxPackets, txPackets                               atomic.Uint64
	sourceRejected, formatRejected, rxDrops, txDrops, txErrors, rxErrors atomic.Uint64
}

func (s *datagramStats) receive(n int) { s.rxBytes.Add(uint64(n)); s.rxPackets.Add(1) }
func (s *datagramStats) sent(n int)    { s.txBytes.Add(uint64(n)); s.txPackets.Add(1) }
func (s *datagramStats) snapshot() RuntimeStats {
	return RuntimeStats{SocketRxBytes: s.rxBytes.Load(), SocketTxBytes: s.txBytes.Load(),
		SocketRxPackets: s.rxPackets.Load(), SocketTxPackets: s.txPackets.Load(),
		SourceRejected: s.sourceRejected.Load(), FormatRejected: s.formatRejected.Load(),
		ReceiveQueueDrops: s.rxDrops.Load(), TransmitQueueDrops: s.txDrops.Load(),
		TxErrors: s.txErrors.Load(), RxErrors: s.rxErrors.Load(), ByteAccounting: "socket_payload_excludes_outer_ip_udp"}
}
