# v0.3.0-rc5 — authenticated wider window, bounded recovery and installer transactions

This is the final *planned* prerelease before 0.3.0 stable. Publication is gated on the complete exact-source cloud matrix. Multi-day testing under real Iran/foreign routing and Xray users remains with the operator; short synthetic checks do not prove long-term reliability.

## Changes since rc4

- Negotiate an 8192-frame BIP SACK horizon with an authenticated receiver-issued challenge/PROOF. Keep the 4096-frame legacy limit with rc4 or smaller queues. Default new configurations to queue_size=8192 and TUN tx_queue_len=256; preserve explicit existing configuration until menu option 21 is selected.
- Recover lost retransmissions using guarded fresh authenticated SACK snapshots. Periodically repeat retained ACK state while a receive hole persists. Replays remain filtered; congestion control, pacing, reordering guards and bounded retry budgets remain active.
- Expedite stale exponential retry deadlines after a freshly verified path return without resetting retry budgets. Recover exhausted BIP delivery/identity-rotation budgets inside the same process with a new codec, sender identity, session gate and reassembly state.
- Rekey safely after the existing encryption key lifetime limit for every carrier. Never reset encryption sequence numbers under an existing key. Recovery recreates TUN/forward listeners: some application connections may need reconnecting. Unexpected kernel/configuration errors still fail for systemd supervision.
- Batch already queued TCP frames into bounded writes without waiting for another frame; cap its transmit queue and preserve Linux TCP buffer autotuning.
- Add window_limit_frames, internal_recoveries, goroutines and heap_alloc_bytes telemetry. These are additive schema fields; the heap value is a point-in-time allocation observation, not a leak proof.
- Make installation transactional: install only checksum-listed files through staging, revalidate cached versions, check manager/binary version consistency, restore the command wrapper after first-install or upgrade failure, and retain the previous systemd unit with its executable.
- Restore previous sysctl file contents/mode and unchanged live values; rollback partial tuning failure and preserve later external changes. Detect overlapping wildcard/transport/forward listeners. Make corrupt configuration visible, show the restored join code, handle empty editors and exit cleanly on EOF.
- Test all 21 menu dispatches, functional forward edits/restore, partial tuning failure, checksum/cache tampering, failed first install, offline menu entry and actual install/upgrade/rollback/STOP/OFF on amd64 and arm64.

## Cloud release gate

The network harness uses two endpoint namespaces plus an intermediary router, receiver-path netem shaping outside sender TCP Small Queues, disabled TSO/GSO/GRO and a bounded BDP queue. Numbers from the earlier endpoint-egress rc4 experiment are not a like-for-like comparison.

The gate requires vet, formatting/version consistency, race/audit, parser/controller fuzzing, real TUN/raw ICMP, concurrent simulations, native Ubuntu 22.04 amd64/Ubuntu 24.04 arm64 systemd checks and the complete extended matrix: 180 throughput observations across five carriers and 200/300Mbps with 20/80/200ms RTT, 60 short outage trials, 12 impairment scenarios including 10/30/60-second blackouts under the installed service hardening, 18 steady-loss samples, 2 mixed-version transfers, 30 lifecycle cycles and 15-minute resource probes on two architectures. Missing results and failed cases block publication. Complete systemd journals are not uploaded by these cloud experiments.

Clean BIP samples require 100Mbps; other clean carriers require 30Mbps. Lossy samples have a 1Mbps connectivity/progress floor and a 15-second flow-stall bound, not a 100Mbps guarantee. Dynamic impairment averages include a clean period; separate steady-loss measurements apply loss before warm-up. Raw intervals and telemetry remain in Actions artifacts.

## Remaining limits

- Sustained loss, real provider ICMP policing, route changes, NAT behavior and multi-day real Xray load need field validation. Ordered BIP delivery can stall unrelated inner flows while a hole is recovered.
- Automatic outer PMTU discovery is not implemented. For a smaller path, reduce both peers' TUN MTU and max_frame_payload together; the 1200-byte outer-MTU check explicitly uses 1040-byte TUN/payload.
- The conditional confidence bound from the 60 short trials assumes independent trials from a fixed distribution. It is not a probability of multi-day survival or an assurance that no bug exists.
- Larger queues/window limits cannot override bottleneck bandwidth, congestion, firewall rules or CPU/kernel constraints. Configured profile=stable is a tuning preset, not release certification.

## Install or update

Use the pinned v0.3.0-rc5 bootstrap in README.md on both peers. Download ggstunnel-linux.tar.gz and SHA256SUMS, verify using sha256sum -c SHA256SUMS, extract and run sudo bash ggstunnel/setup.sh install. No Go toolchain is required on the server. Later sudo ggstunnel or setup.sh menu opens the installed menu offline, without dependency checks. For old BIP configurations, review and apply option 21 on both peers to enable the new window defaults.
