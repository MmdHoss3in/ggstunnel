# 0.3.0 validation and known limits

All compilation and runtime tests run in GitHub Actions. No Go/Python toolchain or test packages are installed on the user's workstation. Local inspection and artifact hash verification do not execute the release binary.

The exact tag's required jobs are defined in [.github/workflows/ci.yml](.github/workflows/ci.yml) and the reusable [extended matrix](.github/workflows/extended.yml). A release is created only after all jobs succeed. The extended summary rejects missing observations, duplicate recovery trial numbers, boundary-package failures and recorded case failures. Development failures remain visible in Actions history.

## Required observations

| Experiment | Count / coverage | Criterion |
|---|---|---|
| Carrier performance | 180; 5 carriers, 200/300Mbps, 20/80/200ms RTT, both directions, 3 repeats | 30 measured seconds after 5 warm-up; BIP >=100Mbps; other carriers >=30Mbps |
| Direct baselines | 60; same routed paths/directions | Receiver Mbps, retained for comparison |
| BIP short outage | 60; 3-second blackout, 200Mbps/80ms | Existing hashed TCP flow resumes within 15s; >=3 post-fault completions, consecutive post-fault gaps <=15s; bulk >=1Mbps |
| Dynamic impairments | 12; loss, burst, reorder, duplicate, asymmetry, 5Mbps rate, peer restart, 10/30/60s blackout | Same integrity/progress criteria; installed systemd unit for long-outage tests |
| Steady loss | 18; 0.2/1/3% loss each direction, both directions, 3 repeats | Apply before warm-up; >=1Mbps, >=10 verified frames, largest measured completion gap <=15s |
| Real rc4 compatibility | 2; old server/new client and new server/old client | Verified downloaded rc4 release, existing flow integrity, >=30Mbps clean 100Mbps path |
| Resource load/idle | 90 cycles across amd64/arm64 | Fixed PIDs for 15min; 1/4/16 TCP streams, alternate direction, small UDP datagrams |
| Resource integrity / summary | 2 integrity + 4 peer summaries | Hashed same socket; peak RSS <256MiB, late FD median <= early+8 |
| Capacity scaling | 32 transfers + 16 direct baselines; 100/200/500/1000Mbps, 20/80ms, both directions, 2 repeats | 20s measured after 5s warm-up, 8 streams and concurrent integrity; >=200Mbps on high-capacity paths when baseline permits |
| Constant-load holds | 2, amd64 and arm64; 500Mbps/80ms path | Same installed processes, 600s measured after 15s warm-up, receiver interval JSON, every one-minute median >=200Mbps, late median >=75% early, hashed flow progress, peak RSS <256MiB |
| Lifecycle | 30 | Fresh start/stop and verified payload |
| Boundaries | 50 repetitions of selected Go tests under race/audit | Sequence wrap, expiry, retry budget, retirement/key lifetime, wide SACK and shutdown |

The 14-case shorter tagged binary test checks all carriers at 100Mbps/80ms and BIP at 0/0.2/1% loss, plus a three-second blackout, peer restart and manually configured outer MTU=1200. Native Ubuntu 22.04/amd64 and Ubuntu 24.04/arm64 tests install actual releases and exercise ON, active upgrade, unit/executable rollback, temporary STOP and OFF. All 21 menu dispatches and functional configuration/forward/installer/tuning regressions run separately; mocked dispatch coverage alone is not end-to-end coverage of every interactive input.

## Harness and interpretation

Two endpoint namespaces route through a third namespace. netem acts on the intermediary router's egress toward the receiver, outside sender TSQ; TSO/GSO/GRO are disabled. Its packet queue is one full RTT bandwidth-delay product (minimum 256, maximum 20000 packets). This is a disposable Linux topology, not a reproduction of every public network. Complete systemd journals are not uploaded.

iperf values are useful receiver throughput. Raw interval JSON, warm-up omission markers, source/binary hashes, telemetry and /proc resource observations are retained in Actions artifacts. Injected-impairment averages contain a clean period and are not steady-loss speed. The separate loss matrix avoids that ambiguity. Empty/missing results cannot demonstrate passing behavior.

For 60/60 successes, the exact one-sided 95% lower bound is 95.13% **only for the specified short experiment**, assuming independent trials and a fixed distribution. Seeds and multiple runners do not prove those assumptions. This is not a 95% prediction of multi-day uptime or a probability that the code has no bugs.

## Remaining field validation

The operator will test multi-day Iran/foreign traffic and real Xray users. Cloud release assessment is scoped to the listed automated gates; multi-day field behavior remains unmeasured even if the release is designated stable. Sustained loss remains a material BIP throughput constraint; ordered delivery can hold other inner flows behind a missing frame. ICMP policing, asymmetric congestion, NAT and provider routing changes can impose further limits. Automatic outer PMTU discovery is not implemented: coordinate both peers' smaller TUN/payload configuration when needed.

0.3.0 handles exhausted BIP retry/identity budgets and safe data-key lifetime limits using fresh transport/codec identity in the same process. It recreates TUN and forwarding listeners; individual user connections may need reconnecting. Unexpected kernel/configuration failures still rely on systemd. Short RSS/heap/FD/goroutine observations screen for defects but cannot exclude slow leaks.

## Historical evidence

[The rc4 extended report](EXTENDED_VALIDATION.md) and [Persian report](EXTENDED_VALIDATION-fa.md) retain the earlier unchanged rc4 results and their limits. Their endpoint-egress topology and offload behavior differ from 0.3.0; its TCP high-RTT numbers are not a controlled runtime comparison. Previous releases retain their own exact-build JSONL assets. Current results are appended to the 0.3.0 GitHub Release with extended-report.md and extended-summary.json.

The 508 observations are heterogeneous scenario checks, not 508 independent samples of multi-day reliability. Confidence is reported only for the specified 60 short recovery trials. An extrapolation to another mission time or server population would require a validated usage/failure model; none is claimed. See [NIST reliability projection guidance](https://www.itl.nist.gov/div898/handbook/apr/section4/apr43.htm).
