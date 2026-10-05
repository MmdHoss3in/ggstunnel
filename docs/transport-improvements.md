# Transport development for v0.3.2

This report records development observations behind v0.3.2. For release certification, use the exact-tagged-source measurements attached to the [v0.3.2 release](https://github.com/MmdHoss3in/ggstunnel/releases/tag/v0.3.2), which is created only after all required gates pass. The legacy format remains the default; compact is experimental and requires an explicit matching choice on both ends.

**CI correction:** earlier workflow step successes did not establish a complete race/audit pass. An ACK wide-SACK test fixture wrote into a nil map; `go test | tee` concealed that failure because the implicit shell did not enable pipefail. Raw logs from runs 37267721847 through 37273743286 retain the panic. The fixture now exercises `recordRXSeq` to create real receiver state, and the workflow explicitly selects Bash with pipefail. Prior network observations, direct compact tests and manager/native-socket checks remain separate evidence; the complete suite must pass again before release. Earlier claims of a complete code-test pass are withdrawn.

## Reference evidence

The supplied Dagger setup script separates TCP encapsulation from TUN/IPX profiles ICMP/GRE/IPIP/BIP. Its TUN configuration requests a 4 MiB socket buffer, MTU 1420 and heartbeat/idle deadlines. Connection pool 8 is offered for non-TUN transports, not for TUN. Compiled smux and batched IO symbols cannot establish whether DagMux is active or reveal its algorithm. No supplied binary or script was executed or uploaded.

GGSTunnel TCP and UDP already carry encrypted IP packets from the same TUN interface. GRE and IPIP have native outer encapsulation. IPIP is now selectable in the manager, with the correct IPv4 protocol 4 firewall hint and duplicate-peer checks. TLS is outside this change.

## Implemented

- HELLO retries reuse a live receiver challenge without extending its 10-second expiry. Accepted nonces are consumed; role, identity and retired-peer protections remain.
- Initial BIP authentication has a configurable 90-second deadline (`transport.bip_handshake_timeout_sec`). `handshake_wait_ms` distinguishes bootstrap waiting from an authenticated connection. Recovery uses a fresh identity. A blocked outer IP/ICMP path still cannot connect.
- UDP, raw and TCP shutdown joins workers, serializes Start/Close and rejects sends after shutdown. TCP also closes unauthenticated handshakes.
- TCP uses native `writev` for already queued frames, with a complete-write fallback for injected connections. It preserves kernel TCP autotuning and adds no batching timer.
- Linux amd64/arm64 UDP and raw ICMP/GRE/IPIP use `recvmmsg`/`sendmmsg`, preserve datagram boundaries and validate source, truncation and frame bounds. Partial sends retry only the unsent tail; unsupported platforms use scalar IO. UDP remains unconnected so an early ICMP unreachable does not permanently kill startup.
- A delayed ACK is coalesced only after a successful transmission with current ACK/SACK, matching direction and no missing wide SACK extension. Failed, partial and stale sends retain the ACK.
- Legacy raw ICMP starts with random identifier/sequence values.

## Optional compact BIP

Set `transport.bip_wire_mode` to `compact` on both peers, or use menu 22. Menu 22 separately selects payload/TUN MTU (576..1348). It preserves stopped services and uses the existing config transaction/rollback. Compact join codes use `GGS3`; legacy `GGS2` stays supported. There is no silent downgrade. Menu 21 does not silently enable compact mode or increase the MTU.

The compact inner frame header is 13 bytes rather than 32. It reconstructs the exact original 32-byte AEAD associated data using the authenticated outer sender identity. The existing nonce, ciphertext, tag, replay guard and fragmentation limits are preserved; this saves 19 bytes per inner frame.

The outer envelope uses AES-GCM with independent HKDF domains for each sender identity and role. A session alias replaces clear session IDs; the packet counter is protected using ciphertext sampling and AES, the primitive described in [RFC 9001 section 5.4.3](https://www.rfc-editor.org/rfc/rfc9001.html#section-5.4.3). This is a private PSK format, not QUIC or TLS. Fresh identities produce fresh keys. Both tuple and outer packet counters have explicit exhaustion handling before reuse. EchoReplies still mirror the matching request tuple. Controls receive bounded random padding; DATA does not wait for padding or packing.

Kind, target identity, ACK/SACK, handshake messages and inner headers are encrypted. A session alias is still linkable within a session, and packet sizes/timing remain visible. Removing fixed markers does not prove resistance to classification or overcome a general ICMP block.

Ordinary compact DATA has 115 bytes of IPv4/ICMP/carrier/inner overhead, versus 152 in legacy mode; nonzero SACK adds 8. At payload 1348, compact outer IPv4 packets are 1463 or 1471 bytes; legacy reaches 1500. This is a packet budget, not a guarantee about billing overhead. Small packets, reverse ACKs, kernel echoes and retransmissions matter too. The default payload remains 1280. Use 1348 only with a sufficient outer path MTU.

The legacy filter still matches only its clear-text kinds. With explicit user authorization, compact now has a separate OUTPUT rule matching both 32-bit words of the authenticated remote alias, EchoReply and the exact outer IP pair. Genuine local replies use our own alias; ordinary ping is unaffected. A live authenticated bootstrap may install a rule; replacing an active peer's rule requires fresh challenge proof. Private durable metadata records the exact recipe before insertion, scoped by instance and network namespace. Close, peer rotation and ExecStopPost remove only owned rules; failed cleanup retains its recipe. Unavailable tooling backs off and keeps connectivity. Native scope, ping, real DATA/ACK transfer, rotation, normal stop and SIGKILL tests are required before release.

The optimization goal is balanced useful throughput, connection quality and traffic cost. A 15% application-overhead figure is a target, not a condition that justifies dropping ACKs, weakening authentication or exhausting retransmission budgets. Choose the format using measured path throughput and NIC/application bytes; the larger legacy header can be preferable when its filtered behavior gives a better result. Neither format has a universal billing multiplier.

## Verified cloud observations

All execution uses disposable GitHub Linux runners; no local Go/Python toolchain or reference binary was installed or executed. Both amd64 and arm64 have direct compact tamper/replay/packing/recovery, fuzz, privileged raw socket and manager/installer evidence. The corrected aggregate race/audit and repeated ACK/lifecycle steps passed on the exact source recorded below; each subsequent source change requires its own checks.

| Exact source | Run | Network observations |
| --- | --- | --- |
| `d8d788a9b634370f403e74e9b19e0706bff88fe9` | [37267721847](https://github.com/MmdHoss3in/ggstunnel/actions/runs/37267721847) | 40 legacy/native cases, both architectures |
| `b21817f5790499b96469ed0bb227c53fd3297d75` | [37269182560](https://github.com/MmdHoss3in/ggstunnel/actions/runs/37269182560) | Compact semantic/security regressions; 40 legacy/native cases |
| `e2547ba0e6e413ba068be6f9e6fb681b8dbbccb6` | [37269867449](https://github.com/MmdHoss3in/ggstunnel/actions/runs/37269867449) | 60 cases including compact, all passed |

The third run used real encrypted TUN interfaces, an 80 ms RTT, 200/500 Mbps shaped links, both directions, 16 application TCP streams and 8 seconds of useful measurement after 2 seconds of warmup. Compact payload 1348 delivered 146.7..168.4 Mbps on 200 Mbps links and 394.2..426.4 Mbps on 500 Mbps links. These samples show no fixed 10 Mbps or 100 Mbps carrier cap. CPU and raw receiver reports are retained in each workflow artifact.

In clean 1348-byte cases, actual NIC receive bytes divided by delivered inner IP bytes fell from about 1.130..1.132 in legacy to 1.102..1.106 in compact. **This denominator includes inner IP/TCP headers, not just downloaded file bytes.** A subsequent run measures NIC bytes against actual application receiver bytes and exercises asymmetric/stateful paths; its results must be reviewed before a billing or 15% overhead claim.

The fourth run, [37270835983](https://github.com/MmdHoss3in/ggstunnel/actions/runs/37270835983), tested exact source `ff37920069505879d4196510e9c29536231b3abc`. Both architectures passed native syscall verification (100 queued UDP datagrams in four sendmmsg calls), security/lifecycle/manager tests and the clean/asymmetric legacy and compact cases. All four compact stateful cases failed: one timed out, the others delivered 31.0, 59.1 and 82.4 Mbps below the 100 Mbps gate. Legacy stateful cases passed at 145.3..151.5 Mbps. This is a release blocker, not a passing result.

The fourth run also exposed an accounting defect in the test: iperf warmup omission resets counters between interval boundaries, so even summing retained omitted intervals can miss application bytes. Its NIC/application ratios are invalid for whole-transfer billing comparisons. The test now uses separate zero-omit accounting cases and rejects receiver interval totals that do not equal the end-of-transfer receiver total. Earlier NIC/inner-IP comparisons are unaffected.

The fifth run, [37273743286](https://github.com/MmdHoss3in/ggstunnel/actions/runs/37273743286), completed 92 network observations from `2c3564345fdba063d69514405780c96530160e5b`. Manager and native socket checks passed; the aggregate code-test pass was invalid as explained in the CI correction. Four compact stateful cases failed at 27.2..82.1 Mbps; one arm64 compact asymmetric case also failed at 10.3 Mbps. The corrected zero-omit accounting cases passed receiver-byte consistency checks: NIC/application ratios were 1.214..1.271 for legacy and 1.189..1.241 for compact. Thus even clean samples do not support a 15% whole-application overhead guarantee. The latest change retains one randomized ICMP identifier per 65536-sequence epoch and permutes the sequence within it, rather than allocating a different conntrack flow for each packet. Its native effect still needs measurement.

The focused sixth run, [37275706904](https://github.com/MmdHoss3in/ggstunnel/actions/runs/37275706904), measured 24 compact network cases from `b1b96a5fb6d58a260f2ffdaaa1e9b1305ca1b02e`. All four stateful cases now passed at 108.2..114.3 Mbps with four router conntrack entries at the end of each sample. Clean 500 Mbps cases reached 388.2..424.9 Mbps. The arm64 asymmetric forward case still failed at 10.3 Mbps; the other asymmetric cases passed at 142.4..156.7 Mbps. Whole-application ratios remained 1.189..1.256. This run also predates the pipefail/test-fixture correction and is not a complete code-suite pass. Identifier stabilization improved these stateful observations but did not resolve every path or the overhead goal.

### First complete pass with corrected CI

[37280367334](https://github.com/MmdHoss3in/ggstunnel/actions/runs/37280367334) tested exact source `debc340f12d9feafae83eb0fd8db18f2e07bacfd`. Both architectures passed vet, the complete race/audit suite, ten lifecycle/handshake/ACK repetitions, compact tests, three fuzz targets, native raw sockets, syscall verification and all 41 manager/installer tests. Raw logs have no FAIL, panic or race reports; failures now propagate through tee. The cloud formatting patch is empty.

All 24 focused native observations passed. A blocked bootstrap can shrink the controller threshold before any usable DATA ACK arrives. A confirmed path transition now restores bounded slow start only when this identity has not received clean DATA feedback; it keeps the current flight/credit and preserves learned congestion thresholds otherwise. After this change, asymmetric samples reached 130.8..152.3 Mbps on 200 Mbps links, including the previously slow arm64 forward case. Stateful samples reached 110.2..112.3 Mbps with four conntrack entries; clean 500 Mbps cases reached 395.1..410.1 Mbps. Whole-application accounting remained 1.183..1.236. The 15% goal is still unmet.

This focused pass did not replace the full final-source release matrix, lossy-capacity work or field validation. Compact kernel echo filtering was absent from this historical source.

The full matrix on the same source, [37280372200](https://github.com/MmdHoss3in/ggstunnel/actions/runs/37280372200), exposed a legacy asymmetric forward case on arm64 at 10.33 Mbps. A few successful setup-ping ACKs could mark startup capacity as learned before the bulk transfer. The follow-up source `a286bab` counts clean frame acknowledgements, restores bounded startup growth during an authenticated path change only before 64 clean frame ACKs, and preserves learned thresholds thereafter. Boundary tests cover 0, 1, 16, 63, 64 and 128 clean acknowledgements. This fix requires the full matrix again; the earlier focused compact pass does not validate it.

That 64-ACK heuristic is insufficient. On source `903482d`, [37283713389](https://github.com/MmdHoss3in/ggstunnel/actions/runs/37283713389) passed all 92 native observations, including legacy asymmetric forward at 152.6..153.9 Mbps. The independent matrix [37283720361](https://github.com/MmdHoss3in/ggstunnel/actions/runs/37283720361) reproduced the same arm64 legacy case at 10.33 Mbps. Its controller had two congestion cuts, a 194-frame window and only four retransmissions, while FAST was healthy. A passing rerun does not resolve this intermittency.

The replacement learns a loss threshold per FAST/PULL/compat carrier. Selecting a carrier for the first time permits bounded slow start without inflating current flight or credit; revisiting one restores its learned threshold. Late ACKs from the old carrier still release pending DATA, but do not set the new carrier's RTT or growth. Old-carrier timeouts retain retries and flight/pacing budgets but do not cut the new carrier's window. Tests exercise bootstrap with zero, 16 and 256 clean ACKs, revisiting lossy carriers, old ACK delivery and old-versus-current timeout penalties. Additive tuner telemetry exposes path_mode and slow_start_threshold_frames. This replacement still requires native validation.

[37292251003](https://github.com/MmdHoss3in/ggstunnel/actions/runs/37292251003) tested this replacement on `b11ca84902cf27544d06f4f417421d2d5e0aa28b`: complete race/audit, repeated lifecycle/ACK, iteration-budget fuzzing, native sockets, syscall batching and 41 manager/installer tests passed on both architectures. All 48 native observations passed (eight legacy/compact asymmetric/stateful cases, three fresh repetitions, two architectures). Legacy asymmetric samples were 137.2..155.0 Mbps; compact asymmetric 131.3..158.6 Mbps. Stateful legacy was 145.5..160.7 Mbps and compact 105.9..115.0 Mbps. No 10 Mbps stall appeared in these samples. Cloud formatting changed one test-only expression's spacing and was applied in `7a7b4f7`. These repetitions do not replace full final-source and exact-tagged-source gates or establish multiday reliability.

The pre-tag field-pattern gate uses the v0.3.1 legacy simulation helper when reproducing rc1 failures: the current helper calls compact-only methods absent from the historical runtime. This keeps baseline behavior failures distinct from compilation failures. Both the pre-tag and final tag matrices must pass.

Run 37283720361 also ended timed packed-frame fuzzing with a coordinator context deadline error after 417887 executions, without an assertion or failing corpus. The behavior matches [golang/go#75804](https://github.com/golang/go/issues/75804). The final workflow uses iteration budgets with separate two-minute hang timeouts and explicit Bash throughout; no failure is ignored. The new source must pass these gates as well.

## Remaining limits and release requirements

### Compact echo-filter validation

[37299509110](https://github.com/MmdHoss3in/ggstunnel/actions/runs/37299509110) tested `d0f24b7` with the authorized compact filter. Both architectures passed the complete race/audit suite, compact regressions, fuzzing, 41 manager tests, raw socket checks and actual syscall verification. Native scope tests preserved ordinary ping, genuine local-alias replies, inner DATA/ACK transfers and unrelated peers/rules. Peer rotation removed the old alias rule; normal stop and actual systemd SIGKILL removed the owned rule and metadata.

All 48 fresh repeated asymmetric/stateful observations passed on 200 Mbps links with 80 ms RTT. Whole-transfer accounting and the full exact-source release matrix still require their own final run. The preceding unfiltered source `50f0cae` passed its full 92-observation network matrix but one independent compact/stateful arm64 repetition delivered 99.689 Mbps below the 100 Mbps floor. That miss was retained and the floor was not lowered. The new filter removes redundant traffic without reducing authentication, ACK, retry or delivery guarantees.

At 0.2% random loss, compact useful throughput in the third run was only 6.3..9.6 Mbps. Legacy samples also degraded severely. These checks passed a connectivity floor; they do not demonstrate 100..200 Mbps under loss. Ordered delivery shared by all BIP traffic still causes head-of-line blocking. Removing that ordering blindly would also violate the inner replay-window/fragmentation assumptions. Independent delivery lanes need a separate protocol design and representative tests.

Before a new release: pass the full asymmetric/stateful matrix with the latest startup fix and compact filter, verify cloud formatting, run every release gate against the final tagged source, and explicitly document compact's experimental status and measured overhead. Preserve exact source hashes and raw results. Keep legacy interoperability and rollback documented. Further overhead reductions must preserve quality; no universal 15% guarantee is established.

Short cloud tests cannot establish 95% confidence for multiday Iran/foreign deployments without a sampling model and representative field data. A stable label must not imply those unperformed tests.
