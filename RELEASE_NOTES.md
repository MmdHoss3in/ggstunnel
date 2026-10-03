# v0.3.0-rc4 — BIP5 recovery, bounded backpressure and offline menu

This release candidate keeps the BIP5 wire format. Upgrade both peers to benefit from the new sender and receiver behavior.

## Changes

- Keep a probe-verified FAST path through individual data timeouts; retain congestion control without repeatedly discarding learned capacity on path changes.
- Bound congestion reductions to a transmitted flight, so staggered deadlines for the same loss episode cannot repeatedly halve the window. PULL-based loss recovery uses the same controller.
- Apply cancellable, bounded BIP and TCP backpressure to the real TUN reader instead of dropping frames on a full userspace send queue.
- Preserve Linux TCP receive/send buffer autotuning instead of forcing socket sizes that may be capped by global socket limits. Datagram carriers retain their configured socket buffers.
- Separate BIP's unsent backlog (at most 256 frames) from its 4096-frame flight window. New/default TUN queues use 256 packets; menu option 21 applies this to existing BIP configurations. This bounds queueing delay without capping the bandwidth-delay product at 256 frames.
- Batch dedicated ACKs while preserving authenticated ICMP reply tuples and immediate duplicate acknowledgements.
- Replace full pending-map timeout scans with an indexed deadline heap. Remove acknowledged entries immediately.
- Use current time, rather than an aged ticker timestamp, for scheduling.
- Keep slow start across healthy path transitions, stop sustaining PULL polling once FAST works, and use nonblocking raw sends so socket pressure cannot block ACK processing.
- Validate the complete release manifest before executing the candidate binary.
- Open the installed menu offline with `sudo ggstunnel`, `setup.sh menu`, or `install.sh menu`. Plain setup opens the existing menu; explicit install/update handles packages only when missing.
- Publish both Linux amd64 and arm64 binaries, full source, and SHA256 manifests in one release archive.

## Validation and limits

The release workflow requires race/audit tests, manager/installer tests, privileged raw ICMP and TUN tests, concurrent/sustained carrier simulations, and a real encrypted TUN throughput test through two Linux network namespaces at 80ms base RTT with and without synthetic loss. See the linked Actions run for actual measured results.

These tests do not establish multi-day uptime or 100/200Mbps on an Iran–foreign WAN. No fixed 10Mbps cap is added or removed; throughput remains dependent on congestion, ICMP handling, RTT, loss and the hosts. The queue and 4096-frame flight span remain bounded.

## Install

Download `ggstunnel-linux.tar.gz` and `SHA256SUMS`, run `sha256sum -c SHA256SUMS`, extract, then `sudo bash ggstunnel/setup.sh install` on both servers. Use the README for the GitHub bootstrap command, Xray forwarding, upgrade and rollback instructions. The GitHub-generated source archives do not contain built binaries.
