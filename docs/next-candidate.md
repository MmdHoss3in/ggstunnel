# v0.3.4-rc2 candidate: loss recovery and experimental carriers

This is a release candidate. All changes require exact-source Linux amd64/arm64
validation before publication. Short synthetic samples do not provide a 95%
multi-day Iran/foreign reliability guarantee or prove resistance to DPI.

## BIP

New installations/examples use `transport.bip_delivery="independent"`. Reliable
ACK/SACK and finite retries remain, but a lost carrier sequence no longer holds
all subsequent IP flows in the receive reorder queue. Packed frames are admitted
atomically and the inner replay window covers the negotiated outer flight.
This permits IP packet reordering; TCP handles its own stream ordering. An
existing config without this field retains `ordered`; option 21 selects the new
recipe, saves a backup, and restarts only services that were running.

The adaptive `tuner.algorithm="delivery"` controller uses clean RTT samples,
RTT-sized delivery epochs and bounded learned capacity. Continuing delivery at
low queue delay permits paced repair without cutting the window for every SACK
hole. Persistent queue or a stalled delivery clock backs off. This is a custom
experimental controller, not BBR; ACK compression is not fully modeled.
`tuner.algorithm="loss"` retains the previous controller for rollback. Explicit
PPS limits still work; `unlimited_rate=true` removes the configured PPS ceiling,
and retains congestion pacing. It is not an unlimited-throughput guarantee.

## Opaque and DCPI

Option 23 selects `transport.wire_mode="opaque"` for TCP/UDP/ICMP/GRE/IPIP.
This is incompatible with legacy format: update/configure both peers together,
or use the SECRET GGS4 join code from the Iran endpoint. There is no automatic
downgrade. Existing non-BIP configs keep legacy. BIP compact remains option 22
and GGS3; GGS2 legacy join codes still work.

Opaque v1 uses an authenticated encrypted metadata header and masked sequence,
reducing frame overhead from 60 to 37 bytes. It removes GGS1 and raw IPX markers
and the TCP GGT2 greeting. The alias is stable per sender session and timing,
lengths and raw IP protocol remain observable. This is neither TLS nor QUIC,
and PSK compromise has no forward secrecy. Do not assume firewall invisibility.
Generic ICMP still has kernel echo overhead; the BIP echo filter does not apply
to it. Do not assume less than 15% NIC overhead for every profile or payload mix.

DCPI uses opaque packets over **IPv4 protocol 58**, with no TCP/UDP port and no
public marker. IANA assigns number 58 to IPv6-ICMP; this experimental use in an
IPv4 envelope is not ordinary ping or a standardized transport. Both endpoints
and their provider firewalls must pass it. Our format is not wire-compatible
with Dagger. DCPI has no outer reliable retransmission; inner TCP handles loss.

Opaque UDP/raw replay histories currently admit four authenticated sender
identities and then fail closed. More peer restarts require restarting both
endpoints; silently evicting replay history would be unsafe. BIP's authenticated
challenge lifecycle is separate. Fresh challenge-bound generic rotation must
be completed before recommending opaque/DCPI for unattended production.

## MTU and operations

Startup checks the local IPv4 route/interface MTU and conservatively reduces
frame payload to fit authenticated envelopes. It retains the TUN MTU and lets
the engine fragment inner packets, preserving IPv6's minimum TUN MTU. This is
**local MTU protection**, not authenticated end-to-end PLPMTUD. A remote smaller
link or blackhole still requires a smaller payload setting. Do not send oversized
reliable DATA as a size probe: losing that sequence can stall the tunnel.

Keep payload 1280 initially. Option 24 sends a few bound-interface TUN pings
with several inner sizes and shows telemetry without changing firewall/config.
It cannot distinguish filtering from PMTU failure by itself. For throughput,
use listener 14 on the peer and test 15 locally. Option 16 persists host sysctls;
restart sockets afterwards. Option 21 persists the BIP recipe and restarts active
instances. Neither needs repeating after a normal restart. Menu entry remains
offline with `/usr/local/bin/ggstunnel`.

## Release evidence

Keep every existing CI gate, plus native opaque/DCPI real-TUN tests in both
directions, local MTU clamp checks and ordered/loss vs independent/delivery A/B
tests at 0/1/3% packet loss. Retain raw measurements, exact commit/binary identity
and unchanged-process/verified-progress evidence. Publication must stop on any
failed gate. Multiday field trials, generic authenticated rotation and full
PLPMTUD remain required follow-up work for the new experimental modes.
