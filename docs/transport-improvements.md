# Transport work after v0.3.1

Status: work in progress on feature/compact-wire. These changes are not a published stable release.

## Scope and reference evidence

The user means the TUN -> IPX selection in Backhaul. The supplied Dagger setup script separates TCP encapsulation from IPX profiles ICMP/GRE/IPIP/BIP. Its TUN configuration requests a 4 MiB socket buffer, MTU 1420 and independent heartbeat/idle deadlines. Connection pool 8 is offered for non-TUN transports, not for TUN. Compiled smux and batched IO symbols do not establish whether DagMux is active or how it works. No supplied binary/script was executed or uploaded.

TCP and UDP in GGSTunnel already carry encrypted IP packets from the same TUN interface. Raw GRE/IPIP use standards-shaped outer encapsulation. This work improves those implementations; it does not introduce TLS or pretend that UDP is TCP.

## Implemented, awaiting cloud verification

- Reuse a live receiver challenge on HELLO retries without extending its 10-second expiry. Consume accepted nonces and retain role/identity/retired-peer protection.
- Bound initial BIP authentication to a configurable 90-second deadline, report handshake_wait_ms and recover with a fresh authenticated identity. A permanently blocked outer path still cannot connect.
- Join UDP/raw/TCP workers during Close, serialize Start/Close, reject repeated Start and sends after shutdown, and close unauthenticated TCP handshakes during shutdown.
- Native TCP writev for already queued frames, with short-write fallback for injected connections and no timer delay. Preserve TCP kernel autotuning.
- Coalesce a delayed ACK into an actually transmitted packet only when ACK/SACK are current, direction matches, and no wide SACK extension is needed. Failed/partial/stale sends retain the ACK.
- Randomize legacy raw ICMP identifier/initial sequence. Keep peer/checksum/frame-size validation.

## Remaining protocol stage

Optional compact BIP must preserve the inner AEAD, session authentication, replay and ordered-delivery invariants. Both ends must explicitly opt in; no silent downgrade leaking legacy markers. Use independent key domains and standard AES-GCM, protect visible counter fields, and fuzz authenticated malformed packets. Fixed text/signature removal does not prove resistance to traffic classification or fix a general ICMP block.

A smaller inner header can reconstruct the exact original AEAD associated data from the authenticated outer sender identity. Keep nonce/tag sizes and fragment bounds. Measure both app wire counters and actual NIC receive bytes, including automatic kernel echo replies.

The existing narrowly scoped kernel echo filter matches legacy clear-text kinds. Compact mode needs a separate reviewed rule strategy; do not silently broaden the user's existing permission or claim the old filter covers the new format.

## Cloud acceptance

GitHub Linux amd64/arm64: formatting artifact, vet/race/audit, repeated lifecycle/handshake/ACK regressions, real privileged sockets, manager/installer tests and TUN throughput. Compare payload 1280 vs 1348 at 200/500 Mbps with 80 ms RTT, each direction, plus short loss and outage tests. Retain exact source SHA, useful receiver throughput, CPU/RSS, actual NIC bytes and logs. Default payload remains 1280 until evidence supports changing it; 1348 with legacy BIP requires an outer MTU of 1500.

Short cloud tests cannot establish 95% confidence for multiday Iran/foreign deployments without a sampling model and representative field data.