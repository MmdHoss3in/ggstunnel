# v0.3.0-rc5 — short recovery validation and SACK loss recovery

This release candidate prepares for field stability testing. Multi-day tests on the real Iran/foreign path remain with the operator. The BIP5 wire format is retained; upgrade both peers.

## Changes since rc3

- Detect delivery holes from newly acknowledged SACK frames. Duplicate acknowledgements cannot manufacture loss evidence. A short reordering allowance precedes the paced retry.
- Retain accepted BIP frames in a bounded receive reorder buffer and deliver them in sequence. Reserve room for the missing frame so a full future window cannot deadlock recovery. This avoids exposing outer reordering to inner TCP, but can delay other flows on the same BIP tunnel during loss.
- Distinguish SACK recovery with an active ACK clock from a delivery timeout: reduce the window by 20% and pause growth for one measured RTT for fast loss; retain the stronger timeout response, pacing, bounded flight window and exponential retry backoff.
- Expose fast_retransmits and reorder_buffered in JSON telemetry.
- Restore the previous systemd unit on failed upgrade and explicit release rollback, alongside the previous executable and manager. Preserve stopped/enabled states and configuration.
- Read the binary and manager version from one embedded version file; validate standalone bootstrap/documentation pins and tag consistency before publication.
- Require native ARM64/Ubuntu 24.04 and amd64/Ubuntu 22.04 race/audit tests plus real systemd install, active upgrade, rollback, temporary stop and disable checks.
- Measure each throughput sample with fresh tunnel processes and controller state, two seconds of warm-up, and eight measured seconds. Require at least 30Mbps in the clean 100Mbps/80ms synthetic case; lossy checks have a 1Mbps connectivity/regression floor, not a stable performance target.
- Exercise BIP with 0%, 0.2% and 1% loss per direction, a three-second complete blackout during an established TCP transfer, peer restart, and a deliberately configured 1200-byte outer MTU.

## Validation and limits

The release waits for formatting/vet, race/audit, parser/controller fuzzing, manager/offline-menu tests, real kernel TUN/raw sockets, concurrent FAST/PULL simulations, all five real encrypted carrier throughput checks, and both native platform jobs. Exact tagged-build measurements and short recovery results follow below and are attached as JSONL assets.

Short synthetic samples establish the exercised behavior only. Loss remains a material BIP performance limitation. Outer-MTU testing uses a 1040-byte TUN/payload configuration; automatic PMTU discovery is not implemented. Exhausted retries can still terminate a carrier and trigger systemd restart. Longer outages, real provider ICMP policing, multi-day resource behavior and real Xray load need field validation before a stable release.

## Install or update

Use the pinned rc4 bootstrap in README.md on both peers. Alternatively download ggstunnel-linux.tar.gz and SHA256SUMS, verify with sha256sum -c SHA256SUMS, extract, and run sudo bash ggstunnel/setup.sh install. No Go toolchain is needed on the server. Later sudo ggstunnel opens the installed menu offline, without dependency checks.
