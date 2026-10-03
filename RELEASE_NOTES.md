# Release notes

## v0.3.1-rc1 — field-test recovery candidate

- Retry authenticated HELLO/challenge exchanges after established-peer silence. Confirmation of the same identity retains ordered flight data, replay state and encryption counters, and resumes paced retry scheduling.
- Bound established-peer silence with transport.bip_dead_timeout_sec (default 90 seconds, extended beyond a longer explicit legacy FAST TTL, independent of idle_timeout_sec). On expiry, request engine recovery with a fresh codec/key identity. Kernel echo reflections cannot refresh this deadline. Hard recovery can interrupt application connections while recreating TUN/forward listeners.
- Add peer_authenticated, peer_silence_ms and rehandshake_attempts telemetry. Logs expose suspension and silence; status distinguishes a running process from peer response, initial handshake, missing health data and stale telemetry. Peer response is not an application throughput check.
- Ask for a transport port only for TCP/UDP; retain the unused join-code field for raw-carrier compatibility.
- Add a cloud before/after regression against v0.3.0, repeated race checks on amd64/arm64, reflection/deadline tests, manager checks and real TUN delay/loss/outage checks. Candidate results are separate from earlier Stable measurements.

This pre-release does not implement independent BIP streams, automatic PMTU or a validated multi-day reliability model, and cannot recover a permanently blocked path. Review docs/stability-recovery.md before field testing. It is a field-test candidate, not a new Stable release. Loss sensitivity remains severe: the focused 100Mbps / 80ms run measured 1.835–3.015Mbps with 1% injected loss. Passing connectivity checks is not a high-throughput guarantee.

## v0.3.0 — authenticated wider window, bounded recovery and installer transactions

This stable release is assessed against the complete exact-tagged-source cloud matrix, including useful throughput above 200Mbps and sustained-load screening on both architectures. Publication is gated on all required checks; failures or missing results block release creation. Multi-day testing under real Iran/foreign routing and Xray users remains with the operator; short synthetic checks do not prove long-term reliability.

## Changes since rc4

- Negotiate an 8192-frame BIP SACK horizon with an authenticated receiver-issued challenge/PROOF. Keep the 4096-frame legacy limit with rc4 or smaller queues. Default new configurations to queue_size=8192 and BIP TUN tx_queue_len=1024; preserve explicit existing configuration until menu option 21 is selected.
- Recover lost retransmissions using guarded fresh authenticated SACK snapshots. Periodically repeat retained ACK state while a receive hole persists. Replays remain filtered; congestion control, pacing, reordering guards and bounded retry budgets remain active.
- Retain the bounded encrypted flight during a fully unresponsive path while continuing authenticated path probes; suspend data retries instead of exhausting budgets in a complete blackout. Fresh verified return resumes scheduling; responsive paths with failed data remain budget-limited. Keep the unsent BIP backlog at 64 frames; a 1024-packet kernel TUN queue absorbs brief high-bandwidth bursts while the independent reader drains it into fair bounded flow queues.
- Expedite stale exponential retry deadlines after a freshly verified path return without resetting retry budgets. Recover exhausted BIP delivery/identity-rotation budgets inside the same process with a new codec, sender identity, session gate and reassembly state.
- Rekey safely after the existing encryption key lifetime limit for every carrier. Never reset encryption sequence numbers under an existing key. Recovery recreates TUN/forward listeners: some application connections may need reconnecting. Unexpected kernel/configuration errors still fail for systemd supervision.
- Apply bounded fq_codel only to the private BIP TUN interface, before encryption, to share its kernel queue among inner flows. Log a warning and retain the kernel queue if unavailable; diagnostic reports include qdisc state.
- Continue draining the BIP TUN during carrier backpressure with a bounded round-robin queue before encryption: 128 packets per inner flow, at most 1024 flow buckets and 8MiB total payload. Overflow of one flow does not evict sparse flows; IP fragments and IPv6 extension-header traffic share address/protocol buckets. Expose tun_queue_drops; global saturation remains bounded packet loss.
- Wake FAST scheduling on producer and ACK events; retain bounded per-event work, congestion pacing and authenticated path checks instead of turning the 64-frame backlog into a per-tick rate limit.
- Reply to authenticated NEED_PULL requests with retained ACK state so filtered FAST/PULL probes cannot let silence suspension deadlock the first compatibility DATA. Repeat the coincident-expiry transition 50 times under race detection.
- Seal each encrypted frame into one owned wire buffer, retaining independent ciphertext until delivery and preserving the existing wire format/key lifetime. A cloud microbenchmark on 1280-byte payloads reduced allocations from 4/2864 bytes to 1/1408 bytes; this is not an end-to-end speed guarantee.
- Batch already queued TCP frames into bounded writes without waiting for another frame; cap its transmit queue and preserve Linux TCP buffer autotuning.
- Add window_limit_frames, internal_recoveries, goroutines and heap_alloc_bytes and path_suspended telemetry. These are additive schema fields; the heap value is a point-in-time allocation observation, not a leak proof.
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

Use the pinned v0.3.0 bootstrap in README.md on both peers. Download ggstunnel-linux.tar.gz and SHA256SUMS, verify using sha256sum -c SHA256SUMS, extract and run sudo bash ggstunnel/setup.sh install. No Go toolchain is required on the server. Later sudo ggstunnel or setup.sh menu opens the installed menu offline, without dependency checks. For old BIP configurations, review and apply option 21 on both peers to enable the new window defaults.

Additional required capacity coverage: 32 measured BIP transfers over 100/200/500/1000Mbps paths with 16 direct baselines, plus two ten-minute same-process load holds on amd64/arm64. The holds require receiver interval evidence, one-minute medians >=200Mbps, late median >=75% of early median, concurrent hashed-flow progress and bounded RSS. All 508 planned observations must be present and pass. Link rate is not a tunnel-speed promise. No accelerated multi-day reliability model is claimed.
