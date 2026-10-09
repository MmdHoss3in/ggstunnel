# v0.3.5: bounded burst admission and queue diagnosis

Field v0.3.4 snapshots over approximately one minute showed 33,026 new local
TUN queue drops at the foreign endpoint and 3,244 in Iran. Both authenticated
BIP FAST paths stayed up, with no recovery, expired queue packets or new carrier
receive overflow. These snapshots identify local admission loss; they do not
identify the cause of every outer retransmission or prove a firewall fault.

The old fixed 128-packet per-flow queue is now a 128-packet base with a bounded
burst reservoir. It admits up to 512 packets only while the oldest waiting packet
is younger than 20ms. Older queues cannot borrow more capacity above the base.
The shared 8MiB payload budget, 1024-flow bound, FIFO order within each flow,
round-robin service and configured packet expiry remain in force. Ring metadata
starts at 16 slots and grows only when needed, rather than reserving 512 slots
for every sparse flow. This is not a 20ms maximum latency guarantee or a new
congestion algorithm. It absorbs transient bursts; persistent overload still drops.

No wire, cryptography, MTU, pacing, firewall or join-code changes are required.
Upgrade both binaries; saved options 16/21 persist. Legacy BIP/1280 remains the
baseline. No new tuning option or automatic host policy is added.

Telemetry is additive under schema 1. `tun_ingress_packets` counts all positive
physical TUN reads offered to the queue, including rejected packets. Historical
`tx_read_packets` counts packets processed later by the sender and keeps its
old meaning. Compare deltas over the same interval; the old counter is not an
exact ingress denominator. Drop reasons are `queue_flow_limit_drops`,
`queue_byte_limit_drops`, `queue_flow_count_drops` and `queue_closed_drops`.
Expired packets retain their separate existing counter. Current depth, active
flows, cumulative high-water packet/byte/per-flow values, burst admissions and
maximum observed dequeue sojourn are exported without identities or keys.
High-water values cover the process lifetime, including internal recoveries.

## Frozen cloud qualification

All prior release gates remain mandatory. New native amd64 and arm64 jobs retain
58 observations: 48 four-stream TCP measurements, eight paired summaries and
two deliberate overload tests. Each direction has three balanced v0.3.4/candidate
pairs at 80ms RTT, 30 measured seconds after 5s warm-up, on 200Mbps/0.15% loss
and 500Mbps/0% loss. The immutable v0.3.4 archive SHA256 is
`bfd796fc81abd294ba43b653fe0a5bbd8776cddaba926219b0678c79c78e73b8`.

Frozen gates: 100/300Mbps capacity floors; geometric paired speed >=90%, every
pair >=75%, baseline CV <=15%; median ping p95 may increase by at most the larger
of 20% or 25ms; median local drop fraction may increase by at most 0.5 percentage
points; median CPU use <= baseline*1.25+0.1 cores. RSS <=96MiB, queued payload
<=8MiB, per-flow peak <=512. These are non-regression limits, not a promise of
universal acceleration or zero local loss.

An independent 160Mbps UDP offer to a 50Mbps path must actually exercise burst
admission and local drops, retain at least 30 verified sparse TCP exchanges with
maximum gap <=3s, and keep ping p95 <=250ms. Same processes and zero internal
recoveries are required. Raw samples and iperf/ping reports are attached to the
release; publication recomputes gates and rejects missing/duplicate/wrong-source
observations. There are no automatic retries until green. These short synthetic
recipes cannot establish 95% confidence in multiday Iran WAN stability.
