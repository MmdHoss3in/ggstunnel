# RC5 challenge mode and transport changes

Implementation candidate; publication and measured results are pending CI.
RC4/GGS4 remains the previously published opaque v1 format. Upgrading a binary
does not silently change existing configurations. No DPI or multiday guarantee.

## Opaque challenge lifecycle

The new mode explicitly sets both `transport.wire_mode="opaque"` and
`transport.opaque_session="challenge"`. Its SECRET join code starts **GGS5** and
requires RC5 or newer on both endpoints. Old GGS4 codes remain opaque v1; they
do not opt into this incompatible lifecycle. BIP legacy/compact is separate.

Receiver-generated, expiring challenges authenticate each new peer identity.
Data/header keys depend on both authenticated endpoint identities. Ciphertext
addressed to the old receiver identity cannot become valid after its restart.
Retired identities are rejected rather than forgotten. After 256 peer identity
retirements or before the per-sender 2^32-frame nonce limit, recovery creates a
fresh local identity. This recovery can interrupt traffic; it is not seamless
rekeying. PSK compromise still has no forward secrecy. The 37-byte data envelope
is retained; encrypted control frames, timing and the IP protocol remain visible.

For an existing non-BIP instance, upgrade BOTH endpoints first. In Iran use
option **23**, select opaque, and obtain the new SECRET GGS5 code. On the foreign
server use option **2** and **REPLACE** with the same instance name and this code.
REPLACE keeps that endpoint's existing custom TUN addresses, routes and forwards;
it does not renumber an existing inner network. For a fresh instance with custom
inner addresses, configure the matching addresses on both peers explicitly.
Switching only one side interrupts traffic. Verify actual authenticated peer
health and option **24** before sending users through it. Options **14/15** test
useful capacity. Do not publish or share the SECRET join code.

## Option 25: change transport

Option **25** retains TUN addresses, routes, PSK and forwarding rules. It validates
and backs up the changed config; stopped services remain stopped and an active
service is restarted. Restart failure restores the prior config. On Iran it
prints a new SECRET join code to apply with option 2/REPLACE abroad. Changing
carrier-specific options and coordinating both endpoints is still necessary.

TCP/UDP require an outer port. Raw ICMP/GRE/IPIP/DCPI do not. The menu does not
open provider firewalls. DCPI is experimental IPv4 protocol 58: opaque encryption
cannot fix an upstream rule that drops that protocol. A failed ping alone does
not identify filtering or remote MTU. The project remains incompatible with
Dagger wire formats.

## Telemetry and tuning

UDP/raw now expose successful socket TX/RX bytes and packet counts, source and
format rejection, bounded queue drops, and socket errors. These counts exclude
outer IP/UDP headers and are not datacenter/NIC billing totals. Challenge mode
also exposes control rejection/reflections and handshake waiting time. An active
service alone is not evidence of an authenticated, responsive peer.

Option **16** persists host network settings; restart sockets afterwards. Option
**21** persists the BIP independent/delivery recipe and restarts active instances.
They do not need repeating after a normal restart. Existing custom configs are
retained. Payload 1280 remains the starting recommendation. Full authenticated
end-to-end PLPMTUD is not implemented; the existing safeguard checks the local
route/interface MTU only. Increasing queue size does not enlarge the negotiated
flight window, and one tunnel is not guaranteed to consume all CPU cores.

## Validation

Focused native amd64/arm64 gates cover forged/replayed/wrong-role challenges,
receiver-bound data, alternating one-sided restarts for all six carriers, TCP/UDP
capacity, and RC4/candidate BIP A/B at 1%/3% loss for 30/120 measured seconds.
Restarts use 0.15% loss. Generic clean-path TCP capacity retains the original
30Mbps floor; separate impaired TCP observations require only 1Mbps connectivity,
and explicitly do not certify high-throughput outer TCP under loss.
Existing reorder/capacity-step checks and every full release gate remain. Release
publication additionally requires complete, unique, exact-source RC5 artifacts.
Failures are retained and fixed under a new source commit, never relabeled passes.
