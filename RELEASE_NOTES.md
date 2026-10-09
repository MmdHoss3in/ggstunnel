# v0.3.6 — bounded BIP burst queues

BIP receives a bounded young-burst reservoir to absorb transient queue pressure; sustained overload still drops. Generic carriers retain the original 128-packet bound. The BIP base remains 128 packets per flow; up to 512 are admitted only while the oldest waiting packet is younger than 20ms. Shared queued payload remains bounded by 8MiB. Metadata rings grow on demand, FIFO and round-robin service are retained, and sustained overload still drops.

Additive telemetry separates per-flow, byte-budget, flow-count and closed-queue rejection, counts physical TUN ingress before admission, and exposes queue high-water values, burst admission and dequeue sojourn. No wire, MTU, cryptographic, firewall, join-code or tuning-policy changes. Upgrade both endpoints; saved options 16/21 remain valid. [Behavior and frozen qualification](docs/queue-pressure.md). [Retained failed v0.3.5 candidate and qualification correction](docs/queue-validation-history.md).

Published 2026-10-09 from exact source `d8d88f7b89dc25660f318fb4f6d0617db86c464f` after all 63 final jobs passed. All 58 native pressure observations passed. Initial 4s compact and 30s ARM 1% loss comparisons failed; independent compact and repeated longer loss gates passed. Only the two failed jobs and release dependencies were rerun once with unchanged code and criteria. Original failures and the unpublished v0.3.5 study are retained as [queue-validation-history.zip](https://github.com/MmdHoss3in/ggstunnel/releases/download/v0.3.6/queue-validation-history.zip). See [qualification history](docs/queue-validation-history.md). Passing short cloud recipes does not guarantee acceleration on every WAN or multiday stability.

# Release notes

## v0.3.4 — stable runtime, optional experimental path discovery

Published 2026-10-09 from immutable source
`ac5f73d013b51a574335e5e4bd301e73505d01d6`: all 61 jobs passed in
[tagged attempt 1](https://github.com/MmdHoss3in/ggstunnel/actions/runs/37919838754/attempts/1).
All 512 extended and 164 RC6 observations were complete. The 10-minute 500Mbps
BIP hold measured 419.906/419.904Mbps amd64/arm64, maximum RSS30.621/27.344MiB,
unchanged processes and no late decline. Both 15-minute resource gates passed.
AMD short 500Mbps paired comparisons still showed a 3.36–4.10% decrease against
RC5; ARM was essentially unchanged. No universal improvement is claimed.
The earlier failed comparison is retained as `stable-validation-history.zip`.

Keep TUN/routes/forwards across transport generations, renew BIP/challenge
identities every six hours, and discard expired queue entries before admitting
fresh retries. Remove the extra TUN transmit copy and reuse receive write buffers
and completion channels only after both caller and physical writer release them;
cancellation cannot recycle a buffer still used by blocked I/O. Installer upgrade
and rollback journals restore interrupted transactions on the next invocation.
Option26/GGS6 exposes explicit settings while older join codes remain supported.

Publication requires every old and new gate on this exact source commit, plus
fail-closed verification of all164 RC6 native observations. Loss comparisons now
use15-second warmup,45 measured seconds and five balanced pairs; clean cases keep
the original recipe. Thresholds and the immutable RC5 baseline are unchanged.
The previous failed baseline-variance comparison and measured AMD performance
decrease remain in [validation history](docs/stable-validation-history.md).
Actual tagged-build rates are appended automatically below after validation.

Stable names the supported runtime and installer; authenticated PMTU remains
off by default and experimental, as does DCPI. Renewal briefly pauses delivery
and can lose in-flight UDP. No95%multiday stability, universal speed or firewall
passage guarantee is claimed. Upgrade both peers; saved options16/21 persist.
See [installation and tuning](README.md) and [behavior](docs/rc6-stability.md).

## v0.3.4-rc6 — unpublished validation candidate

Retain the physical TUN, routes and forwarding listeners during authenticated
transport recovery. BIP/challenge sessions renew every six hours by default,
using fresh identities and keys, with a bounded authentication pause. This is
transport renewal, not dual-key seamless rekey; in-flight UDP may be lost.
Bound the outgoing fair queue to 8MiB, 1024 flows, 128 packets per flow and a
default five-second age. Expiry is counted separately in telemetry.

Optional authenticated directional packet-size discovery for BIP and UDP is
available in option 26/GGS6. Probes do not enter BIP's reliable DATA sequence;
compact probes cover the exact IPv4 size including SACK, and UDP uses DF.
Old GGS2–GGS5 formats remain accepted. Installer upgrades/rollbacks now retain
a durable rollback journal and recover interrupted updates on the next manager
invocation. See [criteria and limits](docs/rc6-stability.md).

## v0.3.4-rc5 — prerelease candidate with challenge-bound sessions

Published from immutable source `aab18976517393dc87a1437eceaca63169ccee66` after
all 51 jobs succeeded in [tagged attempt 2](https://github.com/MmdHoss3in/ggstunnel/actions/runs/37856122779/attempts/2).
Attempt 1 failed two individual loss-rate comparisons; independent RC4 self-controls
showed up to 17.6% variation. Exactly one confirmation retained the original
source and thresholds. [Full failure/confirmation history](docs/rc5-validation-history.md)
and `rc5-validation-history.zip` preserve those observations. Passing the second
attempt does not prove statistical nonregression or multiday stability.

The exact-tag 10-minute 500Mbps BIP case on amd64 delivered 403.446Mbps, with
31.832MiB maximum RSS, zero kernel TUN drops and no late speed decline. Six
challenge carriers on both architectures delivered clean TCP 157.601–181.732Mbps
on 200Mbps/80ms paths, with ten alternating peer restarts each (maximum 2.483s).
Candidate loss A/B measured 104.084–148.932Mbps at 1% and 48.347–51.730Mbps at 3%;
120-second 3% cases delivered 49.389/49.398Mbps. Outer TCP at 0.15% loss measured
only 3.670–7.537Mbps. These are synthetic observations, not universal rate promises.

Explicit opaque challenge lifecycle (GGS5) binds data keys to sender AND receiver
identities; GGS4/v1 remains unchanged. Add UDP/raw socket counters, accurate
generic peer health and option 25 for reversible transport changes preserving
TUN addresses/routes/PSK/forwards. Delivery-controller experiments preserve
application-limited peak estimates, probe low-queue self-limited flight and
bound repair delay only while authenticated delivery continues. No measured
performance improvement, multiday guarantee or completed PLPMTUD is claimed yet.

The [focused native run](https://github.com/MmdHoss3in/ggstunnel/actions/runs/37853656027)
passed all four jobs on amd64/arm64 before the final manager-only correction.
All six challenge carriers survived ten alternating one-sided restarts and
bidirectional TCP/UDP transfers. Generic clean TCP measured 155.680–181.925Mbps
on 200Mbps/80ms links. These are preflight observations, not final-tag evidence;
the tagged pipeline reruns every existing and new gate before publication.

Initial [c565b4b validation](https://github.com/MmdHoss3in/ggstunnel/actions/runs/37851224898)
found that an idle-epoch reset could defer a fresh queue reduction. Idle is now
recognized only at a new original burst after an empty flight; the original
regression remains unchanged. Intermediate generic TCP capacity tests wrongly
applied a clean-path 30Mbps floor to a 0.15% lossy outer TCP path. The clean floor
is preserved; impaired TCP is separately measured with a connectivity floor and
does not certify high loss throughput. An intermediate ARM A/B rate of
102.335Mbps vs RC4 116.215Mbps failed the unchanged 90% criterion and remains
retained. Later passing runs do not erase it or prove a statistical improvement.

Option 25 and foreign REPLACE retain the existing inner addresses, routes and
forwards. Old GGS4/v1 remains explicitly separate from GGS5. Recovery at retired
identity/key limits can interrupt traffic; there is no seamless rekey or PFS.

The final [manager and repeated race checks](https://github.com/MmdHoss3in/ggstunnel/actions/runs/37855689206)
passed on both architectures. An earlier ARM job exposed a temporary-port reuse
race in the nine-peer test harness (bind: address already in use), not a runtime
transport failure. Each test pair now has isolated loopback addresses; 50 race
repetitions retain the original bidirectional integrity and shutdown assertions.
This repair changes only the test and its CI invocation.

## v0.3.4-rc4 — published prerelease with retained validation history

Published [RC4](https://github.com/MmdHoss3in/ggstunnel/releases/tag/v0.3.4-rc4)
uses the original validated archive from immutable source
`5fa738b343000c6744a87fdae0c82a5967402f83`. All 46 validation jobs passed in
[tagged attempt 2](https://github.com/MmdHoss3in/ggstunnel/actions/runs/37821774549/attempts/2).
One amd64 iperf accounting observation was retried once with unchanged criteria;
the initial one-block reporting discrepancy remains documented in the release.
The original publication job failed on a flattened artifact directory. A
[publication-only repair](https://github.com/MmdHoss3in/ggstunnel/actions/runs/37830715884)
verified all existing gates and archive checksums, preserved observation counts,
and published without rebuilding or changing runtime code.

Ten-minute 500Mbps runs measured 400.774Mbps / 30MiB maximum RSS on amd64 and
420.581Mbps / 26.723MiB on arm64. The longer 30-second 1% loss samples measured
22.125–34.440Mbps; 3% measured 10.562–12.759Mbps. These limits and experimental
opaque/raw/DCPI identity exhaustion prevent treating this as a Stable,
multiday or DPI-resistance certification. Full raw reports are release assets.

rc3 kept passing compilation, race/unit and ARM smoke checks, but the Ubuntu
22.04 four-second compact startup sample still measured 75.568Mbps, below the
unchanged 100Mbps gate. It is not eligible for publication. rc4 removes startup
BDP clipping from application-limited delivery estimates: authenticated original
ACKs grow the window within the configured flight and pacing bounds, until fresh
queue or repair evidence ends clean startup. All rc3 timing/queue fixes remain.

A short three-platform diagnosis checks the exact cold compact gate, repeated
controller tests, established-flow reordering, a 200-to-5Mbps step and 1/3% loss.
It passed on Ubuntu 22.04, Ubuntu 24.04 and Ubuntu 24.04 ARM64 in
[run 37820599893](https://github.com/MmdHoss3in/ggstunnel/actions/runs/37820599893).
Cold compact samples measured 105.673–177.223Mbps. The short 1% loss samples
measured 47.299–160.693Mbps; 3% samples measured 25.686–54.261Mbps. Reordering
kept verified progress without internal recovery. The 200-to-5Mbps capacity step
recovered with one internal transport recovery per run; this can interrupt
existing application connections and is still an area for improvement.
These focused observations are tied to code commit ce8cffb; subsequent edits
before tagging only remove duplicated documentation and add these results.
They do not publish releases and cannot substitute for full exact-tagged gates.

## v0.3.4-rc3 — bounded startup and fresh timing for queue decisions

rc2's first native amd64 observations measured 83–84Mbps at 1% loss and
34–50Mbps at 3% loss versus about 2Mbps and 0.3–1.5Mbps with the old recipe.
The 500Mbps ten-minute amd64 case measured 375.806Mbps and 31.43MiB maximum RSS.
These gains did not qualify rc2 for publication: short compact startup samples
fell below 100Mbps, and sustained reordering/capacity-step cases stalled.

- Keep clean startup until queue or repair evidence instead of turning its
  first delivery epoch into a permanent capacity ceiling. Bound clean growth
  by measured BDP; exit startup on loss/policer evidence.
- Estimate lower RTT from a confirmed rolling median so transient accelerated
  or reordered ACKs cannot poison an 80ms path with a sub-ms baseline. Permit
  upward recalibration only after a verified sparse flight, never aging alone.
- Queue cuts require clean original sends after the previous cut. Retry-only
  and pre-cut ACKs cannot repeatedly collapse the old flight's repair pacing.
  A still-working delivery clock repairs loss even with queue delay; fresh queue
  evidence controls backoff separately, and a genuinely stalled clock backs off.
- Add focused regression tests for these failure patterns. Keep all cloud gates
  and original thresholds; preserve the failed rc2 tag/run rather than rerunning
  it selectively or moving its tag. Every rc3 observation must use rc3 source.

This remains a candidate with the experimental carrier limitations below.

## v0.3.4-rc2 — loss-path candidate and experimental opaque/DCPI

The previous rc1 run passed the captured directional control checks but failed
two retained 3% loss samples below the existing 1Mbps floor. It was not released.
This candidate preserves the control fix and targets the loss bottleneck; no
measured speed improvement is claimed before the exact-tagged run finishes.

- Add explicit independent BIP receive delivery, atomic packed admission and a
  matching bounded inner replay span. New samples/menu installations select it;
  old configs without the field keep ordered. Option 21 adopts the new recipe.
- Add a delivery/queue adaptive controller with clean RTT, bounded epoch peaks,
  queue backoff and paced isolated-loss repair. Explicit loss-controller rollback
  and rate ceilings remain available. This is experimental custom code, not BBR.
- Add explicit opaque non-BIP frames (37-byte envelope vs 60), encrypted metadata,
  masked sequence and separate domain keys; remove public raw markers/TCP greeting
  only in this incompatible mode. Add GGS4 join codes and option 23.
- Add experimental DCPI over IPv4 protocol 58, opaque only, no TCP/UDP port or
  Dagger wire compatibility. Existing carrier settings keep their wire format.
- Clamp frame payload against the local underlay MTU without lowering the TUN
  MTU; improve root authentication/payload telemetry and add diagnostic option 24.
- Preserve every existing gate and add native amd64/arm64 opaque carrier, MTU,
  and loss-controller A/B observations plus authenticated parser fuzzing.

See [candidate limitations](docs/next-candidate.md). Opaque UDP/raw currently fail
closed after four peer identities; generic fresh-challenge rotation and complete
PLPMTUD remain follow-up work. Stable publication, multiday reliability, DPI
resistance and a universal 15% cost ceiling are not certified by these changes.

## v0.3.4-rc1 — authenticated ICMP control return-path fallback

This candidate addresses the captured failure where Iran-originated EchoRequest controls were visible at the source but absent at the foreign endpoint, while EchoReply DATA and probes continued to arrive. Upgrade both endpoints to obtain the new negotiated behavior. The capture evidence is specific to that path; it does not identify the filtering device or certify long-term capacity.

- Retry an unanswered FAST probe with its original live token and deadline while asking for an authenticated EchoReply control response. Reuse the formerly ignored MORE bit on FAST_PROBE; old peers continue their existing response behavior. Retain the traditional response alongside the requested alternative. Only a fresh matching authenticated token can promote FAST; reflections, replay and expired responses cannot.
- Return standalone DATA ACKs over the requested control path, keeping a traditional request ACK backup. One-way UDP does not depend on application return DATA to acknowledge delivery. Keep wide SACK, successful-send-only ACK coalescing, fresh packet counters, pacing and finite delivery retry budgets. Normal EchoRequest tuples remain paired for stateful paths; preferences expire and reset on authenticated identity changes.
- Back off continuously unanswered active PULL discovery from 50pps to 5pps after at least five seconds and ten response-grace intervals. Keep periodic discovery and restore adaptive polling on authenticated correlated useful DATA. This does not set a DATA bandwidth limit.
- Expose reply_control_tx, reply_control_rx and explicit legacy/compact wire mode in telemetry. No new sysctl, menu option, MTU increase or firewall rule is required. Existing installation, offline menu and options 16/21/22 remain compatible.
- Add repeated race/security/one-way regressions and 64 exact-tagged native amd64/arm64 observations reproducing blocked directional EchoRequests, 100/200Mbps shaped paths, 94ms RTT, one-way TCP/UDP and small loss. Existing release gates are retained; publication requires every gate to succeed.

This is a prerelease for field confirmation. Whole-tunnel ordered delivery remains loss-sensitive; the low-loss connectivity gate is not a 100–200Mbps loss-throughput guarantee. Compact stays optional and experimental, legacy/payload 1280 stay defaults, and existing v0.3.3 observations remain historical below. No local runtime tests were run; validation is performed on disposable Linux GitHub runners.

## v0.3.3 — preserve FAST health and useful retry budgets

- Retry an unanswered FAST probe at its configured interval with the same live token, a fresh outer tuple/counter and an unchanged expiry. A single lost probe no longer delays the next attempt for an entire token lifetime and needlessly expires a usable FAST carrier. Expired or unauthenticated responses cannot promote a path.
- Do not accelerate EchoRequest retries using SACKs received over another carrier until a clean request DATA acknowledgement has proved the request route. Keep ordinary backoff, peer-PULL delivery and authenticated FAST-return recovery, with unchanged retry budgets, sequence identities and memory bounds.
- Retain separate per-case tunnel logs and optional private loss-only traces. Cloud export transfers trace ownership to the disposable runner while preserving runtime 0600 permissions.
- Recover small SACK flights with guarded time-based evidence from a clean later transmission instead of requiring three later frames that may never arrive. Preserve a longer RTT/jitter-based settling interval, ambiguous-retry exclusions, request-route proof, duplicate-evidence filtering and ordinary RTO. This is a bounded BIP-specific mechanism inspired by [RFC 8985](https://www.rfc-editor.org/rfc/rfc8985.html), not a full TCP RACK-TLP implementation.

The v0.3.2 tag failed its independent release gates and was not published: an ARM asymmetric 200Mbps observation measured 96.404Mbps with an internal recovery, and one 3% loss observation measured 0.943Mbps below the existing 1Mbps progress floor. The earlier successful PR run does not certify that tag. Diagnostic repeats reproduced unwanted recoveries on both architectures. Retained trace evidence showed FAST expiry followed by repeated blocked request retries (up to six attempts), then successful PULL/FAST delivery. No failed observations were removed or acceptance floors lowered.

The compact scoped echo filter, native IO, installer/menu and per-carrier controller changes below are included. Legacy/1280 remains the default and compact remains experimental. Publication still requires all exact-tagged-source gates; this change does not solve global ordered-delivery throughput under persistent loss or certify multi-day WAN reliability.

## v0.3.2 — unpublished candidate: transport IO and bounded startup recovery

The `feature/compact-wire` branch adds bounded initial BIP authentication, correct carrier shutdown, queued TCP writev and native UDP/raw mmsg batching, successful-send ACK coalescing, an explicit encrypted compact BIP format and manager option 22/GGS3. IPIP is available in the manager. Legacy remains the default. See [transport-improvements.md](docs/transport-improvements.md) for exact-source observations and protocol details.

Legacy BIP remains the stable default; compact is an explicitly experimental option requiring matching settings on both updated endpoints. The release is created only after every exact-tagged-source gate passes. See the tagged measurements appended below for the final source, rather than treating earlier branch runs as release certification.

- Bound initial authentication waiting and recover with a fresh identity; reuse only live unconsumed challenges without extending their expiry.
- Join carrier workers on close, reject sends after shutdown, and close TCP connections still waiting for authentication. Preserve TCP autotuning and use queued writev without a batching timer.
- Use native Linux recvmmsg/sendmmsg for UDP and raw carriers on amd64/arm64, preserving datagram boundaries and retrying only the unsent suffix. Verify actual syscall batching and retain scalar fallbacks.
- Coalesce current ACK/SACK only after a successful send, preserving stale, missing wide-SACK, failed and partial-send cases.
- Learn loss thresholds separately for FAST, PULL and compat. A newly selected authenticated carrier keeps the current flight/credit and learns its own capacity; revisiting a carrier restores its congestion threshold. Old-path ACKs still release delivery state, and old-path timeouts still retry, but neither supplies RTT/growth/loss evidence for the new carrier. Expose path_mode and slow_start_threshold_frames in tuner telemetry.
- Add explicit compact BIP with a smaller authenticated inner header and an encrypted outer envelope. Randomize ICMP tuples without allocating a new conntrack flow for every packet; retain counter exhaustion, replay and tamper guards. No silent format downgrade.
- Filter compact kernel EchoReply copies by the authenticated remote session alias and exact outer IP pair, preserving real local replies and ordinary ping. Replace the rule only after fresh proof for an active peer rotation. Persist private cleanup metadata before insertion; remove the exact rule on close or systemd ExecStopPost, including after SIGKILL or config replacement. Keep failed cleanup recipes for retry and back off unavailable firewall commands.
- Add IPIP to the menu and option 22 for explicit wire mode and payload/TUN MTU. GGS3 carries compact settings; GGS2 legacy codes remain supported. Preserve stopped services and configuration rollback. Menu entry stays offline.

Traffic cost is balanced with connection quality. Earlier corrected short accounting samples without compact echo filtering measured about 18–24% compact NIC/application overhead; final tagged observations appear below. This is not a universal billing multiplier or a 15% guarantee. Compact uses its own alias-scoped echo filter; unavailable iptables retains connectivity with additional kernel echoes. Loss-sensitive ordered BIP delivery, automatic PMTU and multiday field certification remain limitations. Changing packet appearance cannot restore a generally blocked ICMP path.

Upgrade both endpoints, foreign first then Iran. Existing legacy configurations remain compatible and keep their format. Options 16 and 21 are explicit; neither enables compact. Use option 22 on both sides only for an intentional compact trial, and retain payload 1280 unless the outer path MTU supports 1348. Short synthetic checks do not establish 95% multiday reliability.

## v0.3.1 — directional PULL feedback, native batching and negotiated packet packing

This Stable update reduces unanswered PULL polling, redundant kernel echoes and small-frame packet overhead, and repairs directional retries and recovery rate reporting. It includes rc1 authenticated rehandshake and bounded hard recovery. Publication requires the complete exact-tagged-source cloud gates; short synthetic tests do not certify multi-day Iran/foreign WAN reliability.

- Drive adaptive polling from newly retained, authenticated PULLED DATA correlated with our own outstanding ICMP request tuple. FAST/COMPAT DATA no longer inflate PULL rate. Do not disable receiving PULL based on local FAST sending health.
- Back off unanswered active polling to a 50pps rediscovery budget after a response grace period. Retain independent periodic discovery and restore growth when returned DATA is confirmed. Bound outstanding tuple memory to four negotiated receive windows and expire unanswered requests; late DATA remains deliverable.
- Retransmit over a still-confirmed FAST EchoReply path rather than forcing every retry into an EchoRequest direction that can be blocked. Keep congestion pacing and bounded retry budgets.
- Start SACK reordering grace when evidence arrives so ordinary RTT does not consume it before a reordered original can return. Keep retry guards/frozen deadlines. Stop the actor before closing its raw sender descriptor.
- Suppress redundant kernel EchoReplies only for BIP5 PULL/NEED_PULL/HELLO kinds 3, 4 and 7 between the configured outer IP pair. Keep DATA, ACK, FAST and ordinary ping untouched. Add an instance-tagged iptables OUTPUT rule at startup, remove its exact specification on close, and run best-effort systemd ExecStopPost cleanup after abnormal exit. Expose kernel_echo_filter; unavailable tooling logs a warning and retains the previous behavior. Test scope and normal/SIGKILL cleanup in disposable namespaces.
- Allocate local tuples for originated EchoRequest response controls; mirror peer tuples only for EchoReplies. Exercise a strict one-reply-per-tuple handshake model in addition to real Linux conntrack. ICMP-ID-rewriting NAT is not certified.
- Initialize inner and outer rate baselines at sampler start. Process-lifetime counters remain intact through recovery, without producing fictitious hundreds-of-Gbps first samples.
- Expose pulled_data_rx, pull_replies_rx, pull_outstanding, pull_requests_expired, pull_budget_pps, control_tx_bytes, data_wire_tx_bytes and actual Linux socket buffer sizes. Warn on failed buffer requests.
- Option 21 now raises old BIP socket requests to at least 4MiB while preserving larger values. Option 16 remains explicit host tuning; restart sockets afterwards. Menu entry stays offline.
- Match -gen samples to the installer performance defaults. Reuse actor-owned keyed HMAC state, remove the second full wire-buffer copy, and use bounded nonblocking Linux receive/send batches. Authenticate identical wire fields and retain unsent DATA for paced retries; register/count only the kernel's successful send prefix. Unsupported batch syscalls retain scalar fallback.
- Add repeated race regressions, a failing-before/passing-after rate test, and real TUN A/B transfers against rc1 on amd64/arm64: clean, directional control filtering, stateful ICMP and separate 8000pps directional policers, with 16 inner TCP streams.
- Hand each completed native receive batch to the actor as one bounded event, preserving reply batching without waiting for more input. Restrict persistent-hole lookup to the cheaper of the advertised SACK range and pending flight, retaining retransmission age/evidence guards and wrap handling. Exercise filter cleanup with actual service SIGKILL on Ubuntu 22.04 as well as 24.04.
- Negotiate small-frame packing through authenticated READY offers/accepts from the already verified active peer. Coalesce up to 16 already queued encrypted frames within the configured physical payload limit. Preserve each frame's independent AEAD nonce, identity and replay sequence, FIFO lookahead, partial receive progress and the packed flag on retries. Legacy peers keep ordinary single-frame DATA. Expose peer_packet_packing and packed_data/frames counters; GGS_BIP_PACKET_PACKING=0 can disable capability advertisement for a controlled comparison. Fuzz length/count bounds and reject malformed bundles before delivery ACK or PULL feedback.

- Verify mixed peers against published v0.3.0-rc4, Stable v0.3.0 and v0.3.1-rc1 in both roles, with legacy packing disabled. Require all six unique compatibility observations in the extended summary.

Upgrade both endpoints using the pinned v0.3.1 installer in README.md, foreign first, then Iran. Existing configurations are preserved; run option 16 before option 21 (or restart after 16) to adopt the socket recipe. Menu entry remains offline and rollback is available.

The tagged-source release gate retains the full earlier validation matrix and additionally requires the field-pattern checks. Release notes append actual measurements from that run. Ordered BIP head-of-line blocking, independent lanes and automatic outer PMTU remain separate protocol work. No long-term 95% reliability claim is made. Dagger's public documentation advertises DagMux; old SMUX symbols do not establish its active architecture or prove DagMux is an improved SMUX fork. See docs/field-performance.md.

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
