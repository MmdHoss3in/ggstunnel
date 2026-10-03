# Validation and known limits

All builds and runtime tests run in GitHub Actions; no Go toolchain or test packages are installed on the user's workstation. See the workflow and the release for the exact commit and logs.

## Required rc4 release checks

- Go formatting, vet, race detector, audit tests and short parser/controller fuzzing.
- SACK evidence, duplicate/reordered ACK, sequence-wrap, bounded ordered receive and cancellation regressions.
- Manager install/update/rollback, service-unit restoration and offline menu dispatch tests.
- Privileged raw ICMP loopback and actual kernel TUN cancellation.
- Sustained FAST/PULL simulation and nine concurrent simulated peers.
- Actual amd64 binary, AES-GCM, TUN, raw sockets/kernel TCP and iperf3 across two Linux network namespaces for BIP/TCP/UDP/ICMP/GRE on Ubuntu 24.04.
- Native race/audit and real systemd installation/lifecycle checks on Ubuntu 22.04/amd64 and Ubuntu 24.04/arm64. These do not measure ARM64 WAN throughput.

The release job depends on all jobs succeeding and validates the exact source tag. It publishes measured network-results.jsonl and recovery-results.jsonl beside the package and checksums. Throughput samples use a 100Mbps netem link, 80ms base RTT, fresh tunnel/controller state per direction/loss case, four TCP streams, two warm-up seconds and eight measured seconds. BIP tests 0%, 0.2% and 1% random loss per direction; other carriers currently test the clean link. The clean floor is 30Mbps; the lossy 1Mbps floor is only a connectivity/regression gate.

Short real BIP recovery checks cover a three-second total blackout while a TCP flow is established, restart of one peer without restarting the survivor, and a 1200-byte outer MTU with a deliberately chosen 1040-byte TUN/payload. Native systemd tests cover installation, ON, upgrade while running, rollback, STOP with boot state preserved, and OFF.

## Verified rc3 baseline

[The rc3 release](https://github.com/MmdHoss3in/ggstunnel/releases/tag/v0.3.0-rc3) used sequential samples sharing controller state, without the rc4 warm-up/isolation procedure. Its exact tagged results were:

| Carrier | Loss per direction | Forward Mbps | Reverse Mbps |
|---|---:|---:|---:|
| BIP5 | 0% | 72.995 | 73.786 |
| BIP5 | 0.2% | 7.703 | 2.490 |
| TCP | 0% | 78.601 | 82.836 |
| UDP | 0% | 83.804 | 84.668 |
| ICMP | 0% | 78.496 | 84.539 |
| GRE | 0% | 82.635 | 83.491 |

Changes in test procedure and random loss mean single samples are not a statistically controlled before/after comparison. Carrier-only simulator speeds omit real sockets, TUN and inner encryption and are not end-to-end rates.

## Remaining field validation

Loss still reduces useful BIP throughput and is not a solved performance problem. Ordered delivery can hold unrelated flows behind a missing frame. Custom congestion control, retry limits, bounded queues, and provider ICMP policing remain relevant. Automatic PMTU discovery is not implemented. Exhausting retry limits can stop the carrier; systemd's on-failure restart remains the recovery mechanism for that condition.

The operator will perform multi-day real Iran/foreign WAN and connected-user/Xray tests. Short cloud checks do not establish multi-day uptime, resilience to every type or duration of outage, nine simultaneous real WAN peers, or a fixed throughput on a provider path. rc4 remains a release candidate until those observations support a stable release. Failed development runs remain in Actions history.
