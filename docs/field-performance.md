# v0.3.1-rc2 field performance repairs

The supplied field logs show FAST in Iran and COMPAT at the foreign endpoint, with no confirmed foreign FAST ACK reception. Iran emitted 82,066 PULL probes versus 55,407 FAST DATA frames in an 18-second interval. These are directional control/data transmission counts, not a PULL response ratio. The operator reports concurrent Xray users and that neither menu option 16 nor 21 had been applied.

## Implemented changes

The old actor derived adaptive PULL rate from all received payload frames. Successful FAST/COMPAT reception could therefore pay for more polling even when that polling path did not return DATA. The repaired actor requires an authenticated PULLED EchoReply matching an outstanding local ICMP tuple. Only newly retained DATA contributes to growth; duplicate responses cannot multiply yield. All DATA keeps the existing authentication, anti-replay and ordered acceptance rules.

Request memory is bounded by the negotiated receive window. Unanswered requests expire after max(1s, response grace); expiry affects feedback, not acceptance of late DATA. Response grace is max(500ms, four times measured PULL RTT, four times available DATA ACK RTT). Active polling halves after grace without a response, down to 50pps; the independent configured idle probe remains. Valid returned DATA restores growth. Local FAST health does not suppress the opposite direction's need for PULL. Adaptive unlimited_rate can exceed the configured max_pps when genuine returned DATA supports it; bounded flight, memory, scheduling bursts and congestion control remain.

Each new engine stats sampler starts at current inner/outer totals. Lifetime counters survive transport recovery, while first-interval rates include only new traffic. Telemetry adds valid PULL response/yield, outstanding/expired requests and budget, control versus DATA wire bytes and real socket buffer sizes. Linux SO_RCVBUF/SO_SNDBUF values include doubled accounting; they are not comparable one-for-one to the requested value.

Option 21 additionally requests at least 4MiB BIP socket buffers, preserves larger requests and other transports, saves configuration backups and restarts active services. Option 16 raises host ceilings to at least 16MiB while preserving higher settings. Run 16 before 21, or restart after 16 if 21 was already applied. Installing an updated binary preserves explicit old configuration, and opening the menu does not rerun dependency checks.

## Short cloud validation

No local Go/Python tooling or reference binary is executed. Tests run on disposable GitHub-hosted Linux amd64 and arm64 runners.

- The actual engine sampler restarts with 8GiB TX/70GiB RX historical traffic, then measures controlled new increments in two epochs. The same regression is required to fail on rc1, with its expected historical-rate error, before accepting repaired sampling.
- Repeat asymmetric bidirectional transfer under race detection; verify ordered, uncorrupted DATA in both directions and low unanswered polling despite unrelated successful payload reception.
- Real TUN A/B: rc1 versus candidate, 80ms RTT, 200/500Mbps links, forward/reverse, 16 inner TCP streams, 2s warm-up and 10s measured traffic. Each sample starts fresh endpoints. Reverse samples alternate version order. Retain all observations and errors.
- Cases: clean; Iran request kinds 1-6 filtered while authenticated bootstrap and reply DATA pass; router conntrack rejecting unsolicited EchoReplies with kernel automatic echo disabled at the endpoints; and independent 8000pps directional policers including all ICMP control/retry/DATA.
- Candidate clean transfers require >=100Mbps and no >35% A/B drop. Impaired cases require >=1Mbps progress, not high-speed certification. Asymmetric unanswered Iran polling must average <=200pps across the whole measured operation including startup. Stateful transfers must actually receive PULLED DATA. Process PIDs must remain unchanged, and additional kernel/application state is retained in artifacts.
- Full tagged-source race/audit, fuzz, raw socket/TUN, manager/installer/systemd, five-carrier, compatibility, capacity and resource gates remain required before release creation. Raw new field results are attached separately to the release.

These short synthetic checks cannot predict multi-day survival on a different provider path with 95% confidence. Field feedback still determines whether this specific Iran/foreign deployment benefits.

## Reference interpretation and subsequent protocol work

[Dagger's own README](https://github.com/itsFLoKi/daggerConnect) advertises a proprietary DagMux core. It does not publish enough implementation detail here to conclude that DagMux is a modified SMUX, or that its TUN uses the same stream multiplexer. Compiled legacy SMUX/KCP symbols and installer values are evidence of capabilities/configuration, not active algorithms. GGSTunnel adds no SMUX dependency and does not claim to copy DagMux.

Backhaul's 8-way MUX, 4MiB session receive buffer and 2MiB stream buffers, and Dagger's resource profiles, motivate independent flow budgets and bounded scheduling. Their stream frame sizes and pool count must not be copied as raw ICMP MTU or eight conflicting TUN interfaces.

Independent authenticated delivery lanes, a shared aggregate wire budget, pre-encryption queue age control, negotiated small-packet aggregation and confirmed outer MTU discovery remain subsequent work. Each needs compatibility, loss/reorder, memory/replay and cryptographic nonce tests before activation. The current reliable BIP ordering can still block unrelated inner flows while recovering a missing frame, and delivery-budget recovery can interrupt application connections.
