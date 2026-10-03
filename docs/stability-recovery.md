# BIP field recovery and stability preparation

## Field symptom

The foreign-host sample contains 96 status lines spanning 190 seconds. Inner receive and payload counters stay fixed, pending=58 and backlog=64 do not drain, retransmits=382 stays fixed, FAST/PULL receive counters are zero, and verified local reflections continue increasing. The engine is alive but there is no useful tunnel progress. This is consistent with path-silence suspension; the sample alone does not identify whether the remote process, routing, filtering or session state caused the original loss of response. Both peer versions and Iran telemetry are still needed to establish that cause.

## Reference findings and evidence limits

The supplied Backhaul Premium and Dagger executables were read as ELF64 x86-64 data, never executed. Their embedded Go build information says unknown, and symbols are partly or heavily obfuscated; a filename or an installer label is not proof of the executable version. No code was copied from these executables.

The supplied Dagger installer exposes a pool of eight connections for transports other than TUN, retry/dial deadlines, heartbeat/dead timeouts, separate TUN heartbeat_sec and idle_timeout_sec, and systemd restart. Dagger symbols include KCP and SMUX functions and application methods AddSession, GetLeastLoaded, OpenStreamLatency, OnPong, OnData, State and RegisterKCPSessionWithMTUCeiling. These establish compiled capabilities, not the exact implementation, active transport, settings or comparative throughput of this binary. The installer explicitly excludes its connection pool from TUN.

The supplied file named backhaul is an obfuscated shell manager, not an ELF executable. Literal fragments were reconstructed without evaluating shell code. Its generated settings include heartbeat_interval=10, heartbeat_timeout=25, retry_interval=3, connection_pool=8, mux_concurrency=8, TUN health_port=1234 and quantum peer_idle_timeout_s=120. Settings from different transports must not be assumed to apply to BIP. The Premium executable is too obfuscated to attribute each mechanism with confidence. The public [Musixal Backhaul](https://github.com/Musixal/Backhaul) is a related architectural reference, not verified as the exact supplied Premium executable.

The public [Dagger documentation](https://github.com/itsFLoKi/daggerConnect) describes separate heartbeat/dead timeout behavior for TUN. [SMUX](https://github.com/xtaci/smux) exposes bounded stream/session buffers and scheduling, while [KCP Go](https://github.com/xtaci/kcp-go) provides retransmission/window controls and optional FEC. Their presence is not evidence that adding them unchanged will improve BIP on a policed ICMP path.

## Changes in the recovery candidate

1. Established BIP sessions previously stopped DATA retries during silence but sent HELLO only before initial authentication. A silent established peer now receives bounded periodic master-key HELLO attempts using retry_interval_sec (default two seconds), after the existing silence threshold. A fresh authenticated proof for the same peer preserves queued flight data and replay/key counters. Kernel echoes and replayed proofs do not confirm liveness.
2. Continued silence now produces a recoverable error after bip_dead_timeout_sec, default 90 seconds. The engine recreates the codec and carrier with a fresh authenticated identity; it never resets an encryption counter under an existing key. This deadline is separate from idle_timeout_sec because existing installer configs use 30 seconds there, which would prematurely reset a sixty-second outage. Raising the new deadline trades slower hard recovery for preserving longer transient outages. A permanently blocked path remains blocked.
3. Telemetry and logs expose peer authentication, silence duration, suspension and rehandshake attempts. The menu reports NO PEER RESPONSE even when systemd reports RUNNING. Fresh peer response means authenticated protocol activity, not a guarantee of successful application traffic.
4. Raw carriers no longer ask for an unused TCP/UDP port. The existing join-code port field remains for compatibility. TCP/UDP still ask for their actual outer transport port.

The regression simulates a path that stops accepting session traffic until a new master-key HELLO exchange reopens it. It requires the original queued packets to arrive in order without changing live identities. This is an intentionally constructed failure model, not proof that the user's ISP has exactly this behavior. Additional tests check bounded attempts, ignored reflections, a hard silence deadline, preserved short-outage flight state, fresh-key recovery classification and manager health states.

Hard recovery recreates TUN and forwarding listeners, so existing application connections may need to reconnect. After changing identity there is no guarantee of preserving the same application TCP connection. Short rehandshake keeps the existing identity and in-flight state when the peer can be confirmed.

## Candidate cloud results

The [focused amd64/arm64 run](https://github.com/MmdHoss3in/ggstunnel/actions/runs/37158182127) passed on source `e6fc187033e9994fde18323a92971c23a5958995`. The released 0.3.0 source failed the constructed rehandshake regression after its four-second deadline on both architectures. The repaired source passed 20 consecutive race-enabled repetitions on each architecture, normally in 1.04 seconds, retaining the original identity and delivering all 32 payloads in order. This demonstrates the repaired failure model, not population-wide or multi-day reliability.

Both native runners also passed formatting, vet, all short race/audit tests, version/configuration checks, 24 manager/installer unit tests, and real systemd install, ON, active upgrade, rollback, STOP and OFF. The unit tests intentionally inject some failures; printed FAIL diagnostics inside those passing tests are not failed cloud jobs.

Real encrypted TUN samples used a routed 100Mbps link, 80ms base RTT, eight-second samples after two seconds of warmup, and fresh sessions for each direction:

| Injected loss | amd64 forward / reverse Mbps | arm64 forward / reverse Mbps |
| --- | --- | --- |
| 0% | 80.496 / 68.817 | 81.251 / 73.667 |
| 0.2% | 6.540 / 6.684 | 10.725 / 4.195 |
| 1% | 2.481 / 1.835 | 2.006 / 3.015 |

The loss checks passed their connectivity floor of 1Mbps; they did **not** pass a high-throughput target. Loss sensitivity remains severe and makes independent ordering/recovery and queue latency the next performance priorities. These samples establish neither a fixed 10Mbps cap nor the exact cause of the user's field slowdown.

After a three-second blackhole, the existing framed TCP flow resumed 0.299 seconds after link restoration on amd64 and 0.331 seconds on arm64, with payload integrity checks. Peer restart recovered reachability in 1.189 / 1.204 seconds. An outer MTU of 1200 passed with manually matched TUN MTU 1040; this is not automatic PMTU adaptation.

The [standard short validation run](https://github.com/MmdHoss3in/ggstunnel/actions/runs/37158185911) also passed: fuzzing three authenticated parser/controller targets, real raw ICMP and TUN cancellation tests, nine concurrent BIP peers, all five carriers through the shaped TUN path, and installation/verification of the actual generated archive. Native Ubuntu 22.04 amd64 and Ubuntu 24.04 arm64 systemd/race checks passed. The longer extended release matrix and publication were intentionally skipped for this focused draft PR; they remain required on main and release tags. BIP no-loss samples in this second run were 78.092 / 58.065Mbps, again showing short-sample variation.

No supplied reference executable and no local Go/Python runtime was executed for these tests. The code remains an unpublished candidate in [draft PR #1](https://github.com/MmdHoss3in/ggstunnel/pull/1); the published Stable release remains v0.3.0. Subsequent documentation-only edits do not change the tested executable source.

## Remaining work, in priority order

1. Obtain simultaneous Iran/foreign telemetry and verify the installed versions. Test the repaired candidate with the path and traffic that triggered the freeze. Record idle and loaded ping, received throughput, retransmits, reorder_buffered, peer silence, recoveries and per-core CPU. A cloud simulation does not resolve the missing field diagnosis.
2. Bound the age of unsent inner packets before encryption and drive tuning using loaded RTT versus baseline RTT, rather than only loss and ACK rate. Expiring unsent packets can make inner TCP respond to congestion without creating a hole in BIP sequence numbers. Validate fairness and sparse-flow latency with many simultaneous Xray-like flows; do not grow queues merely to suppress drops.
3. Separate ordering/loss recovery among inner flows or authenticated independent lanes. Current BIP5 orders the entire tunnel: one missing frame can hold unrelated users. This needs explicit wire negotiation, per-lane replay/window bounds, mixed-version tests and a deliberate fallback. Running several whole TUN sessions over one interface is not a safe substitute.
4. Add authenticated path-size probes and coordinated payload/MTU adaptation. A small ping cannot establish the safe outer size at the packet rates required for bulk traffic. Start with measurement rather than choosing an arbitrary global MTU.
5. Evaluate per-flow path assignment and fallback after independent paths and health checks exist. Detect total failure and useful-data stalls separately; repeated control responses must not indefinitely hide failed data delivery. A fallback must be configured on both peers and must not oscillate.
6. Benchmark optional FEC/KCP separately with loss, reordering, bandwidth limits and ICMP policing. FEC adds wire traffic and can worsen policing; KCP/SMUX do not by themselves eliminate whole-session transport ordering. Use received useful throughput and latency as acceptance criteria.

The old 0.3.0 clean-link and steady-loss measurements remain historical. No 95% claim for multi-day Iran/foreign operation, zero bugs, or guaranteed 100–200Mbps follows from the reference binaries or short regression suite.

An omitted dead timeout is extended beyond an explicitly longer legacy FAST TTL so existing valid probe configurations still load. Explicit unsafe deadlines are rejected. Native manager package regressions now select the runner architecture instead of hard-coding amd64. The dedicated field-recovery PR runs focused checks; the full extended release gate remains enabled for release tags and main.
