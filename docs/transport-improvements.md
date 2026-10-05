# Transport changes after v0.3.1

This work is on `feature/compact-wire`; it is not a published stable release. The installed v0.3.1 format remains the default. The new compact format requires an explicit choice on both ends.

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

The existing kernel echo filter matches legacy clear-text kinds. It is deliberately not applied to compact packets. A separately scoped compact filter needs authorization and native cleanup tests; until then `kernel_echo_filter` is false in compact mode. Do not treat this as equivalent to the legacy filtered deployment, especially on a path that only admits replies to tracked requests.

## Verified cloud observations

All execution uses disposable GitHub Linux runners; no local Go/Python toolchain or reference binary was installed or executed. Both amd64 and arm64 have passed vet, race/audit tests, repeated startup/shutdown/handshake/ACK tests, compact tamper/replay/packing/recovery tests, three compact parser fuzz targets, privileged raw sockets, and manager/installer checks.

| Exact source | Run | Network observations |
| --- | --- | --- |
| `d8d788a9b634370f403e74e9b19e0706bff88fe9` | [37267721847](https://github.com/MmdHoss3in/ggstunnel/actions/runs/37267721847) | 40 legacy/native cases, both architectures |
| `b21817f5790499b96469ed0bb227c53fd3297d75` | [37269182560](https://github.com/MmdHoss3in/ggstunnel/actions/runs/37269182560) | Compact semantic/security regressions; 40 legacy/native cases |
| `e2547ba0e6e413ba068be6f9e6fb681b8dbbccb6` | [37269867449](https://github.com/MmdHoss3in/ggstunnel/actions/runs/37269867449) | 60 cases including compact, all passed |

The third run used real encrypted TUN interfaces, an 80 ms RTT, 200/500 Mbps shaped links, both directions, 16 application TCP streams and 8 seconds of useful measurement after 2 seconds of warmup. Compact payload 1348 delivered 146.7..168.4 Mbps on 200 Mbps links and 394.2..426.4 Mbps on 500 Mbps links. These samples show no fixed 10 Mbps or 100 Mbps carrier cap. CPU and raw receiver reports are retained in each workflow artifact.

In clean 1348-byte cases, actual NIC receive bytes divided by delivered inner IP bytes fell from about 1.130..1.132 in legacy to 1.102..1.106 in compact. **This denominator includes inner IP/TCP headers, not just downloaded file bytes.** A subsequent run measures NIC bytes against actual application receiver bytes and exercises asymmetric/stateful paths; its results must be reviewed before a billing or 15% overhead claim.

The fourth run, [37270835983](https://github.com/MmdHoss3in/ggstunnel/actions/runs/37270835983), tested exact source `ff37920069505879d4196510e9c29536231b3abc`. Both architectures passed native syscall verification (100 queued UDP datagrams in four sendmmsg calls), security/lifecycle/manager tests and the clean/asymmetric legacy and compact cases. All four compact stateful cases failed: one timed out, the others delivered 31.0, 59.1 and 82.4 Mbps below the 100 Mbps gate. Legacy stateful cases passed at 145.3..151.5 Mbps. This is a release blocker, not a passing result.

The fourth run also exposed an accounting defect in the test: iperf warmup omission resets counters between interval boundaries, so even summing retained omitted intervals can miss application bytes. Its NIC/application ratios are invalid for whole-transfer billing comparisons. The test now uses separate zero-omit accounting cases and rejects receiver interval totals that do not equal the end-of-transfer receiver total. Earlier NIC/inner-IP comparisons are unaffected.

The fifth run, [37273743286](https://github.com/MmdHoss3in/ggstunnel/actions/runs/37273743286), completed 92 network observations from `2c3564345fdba063d69514405780c96530160e5b`. All code, manager and native socket checks passed. Four compact stateful cases failed at 27.2..82.1 Mbps; one arm64 compact asymmetric case also failed at 10.3 Mbps. The corrected zero-omit accounting cases passed receiver-byte consistency checks: NIC/application ratios were 1.214..1.271 for legacy and 1.189..1.241 for compact. Thus even clean samples do not support a 15% whole-application overhead guarantee. The latest change retains one randomized ICMP identifier per 65536-sequence epoch and permutes the sequence within it, rather than allocating a different conntrack flow for each packet. Its native effect still needs measurement.

## Remaining limits and release requirements

At 0.2% random loss, compact useful throughput in the third run was only 6.3..9.6 Mbps. Legacy samples also degraded severely. These checks passed a connectivity floor; they do not demonstrate 100..200 Mbps under loss. Ordered delivery shared by all BIP traffic still causes head-of-line blocking. Removing that ordering blindly would also violate the inner replay-window/fragmentation assumptions. Independent delivery lanes need a separate protocol design and representative tests.

Before a new release: finish the asymmetric/stateful and application-accounting run, validate the latest receive-path optimization, apply the cloud gofmt patch, run the complete release matrix against the final source, and make the compact filter status explicit. Preserve exact source hashes and raw results. Keep legacy interoperability and rollback documented.

Short cloud tests cannot establish 95% confidence for multiday Iran/foreign deployments without a sampling model and representative field data. A stable label must not imply those unperformed tests.
