# Validation and known limits

Cloud tests run on GitHub Actions Ubuntu 24.04; no toolchain or test packages are installed on the user's workstation. See the [workflow](https://github.com/MmdHoss3in/ggstunnel/actions/workflows/ci.yml) for the exact commit and full logs.

Required release checks:

- Go formatting, vet, race detector and audit tests.
- Fuzzing BIP wire decoding, frame decoding and controller events.
- Manager install/update/rollback and offline menu dispatch tests.
- Privileged raw ICMP loopback and actual kernel TUN cancellation.
- Sustained FAST/PULL simulation and nine concurrent simulated peers.
- Actual built binary, AES-GCM, TUN, raw sockets/kernel TCP, and iperf3 across two Linux network namespaces for BIP/TCP/UDP/ICMP/GRE.

## Measurements during development

[Run 37101380367](https://github.com/MmdHoss3in/ggstunnel/actions/runs/37101380367) tested commit `db9f23d` before the final TCP backpressure and socket autotuning changes. Each measured TCP transfer used four streams for eight seconds, with a netem link capped at 100Mbps and a base RTT of 80ms. Directions ran sequentially and shared tunnel/controller state; these are diagnostic samples, not statistically controlled benchmarks.

| Carrier | Applied loss per direction | Forward receive Mbps | Reverse receive Mbps |
|---|---:|---:|---:|
| BIP5 | 0% | 69.939 | 78.642 |
| BIP5 | 0.2% | 6.749 | 3.408 |
| TCP (before final TCP fixes) | 0% | 14.884 | 15.204 |
| UDP | 0% | 83.938 | 84.539 |
| ICMP | 0% | 78.911 | 84.408 |
| GRE | 0% | 82.641 | 83.483 |

The separate carrier-only simulator recorded roughly 491Mbps FAST and 319Mbps PULL in that run. It omits real TUN, raw sockets and inner encryption and must not be presented as end-to-end WAN throughput.

## Limits that remain

Loss materially reduces BIP throughput: the synthetic loss measurement above remains a performance limitation, not a successful 100Mbps result. Reliability/backpressure fixes do not remove the bounded congestion window, retransmission delay, inner TCP congestion control or provider ICMP policing. The known queue and path-reset bugs were addressed; there is no claim that all possible bugs or bottlenecks have been eliminated.

The release job repeats validation on the exact tagged source. amd64 is executed; arm64 is cross-compiled. Ubuntu 22.04 and multi-day real Iran/foreign WAN uptime have not been exercised by this workflow. A passing short test is not a stable-release or throughput guarantee.
