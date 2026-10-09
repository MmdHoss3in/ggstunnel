# v0.3.4-rc6: stability candidate, not yet published

The published RC5 baseline remains immutable. This branch has not yet qualified
as a release; cloud results must identify the exact source commit. No local
Windows runtime tests or builds are needed.

## Runtime behavior

The physical TUN, configured routes and forwarding listeners now survive an
internal recoverable transport error or scheduled renewal. All old transport
workers join before a fresh identity/codec starts. Encryption counters are never
reset with the same key. This is **renewal with a short pause**, not seamless
dual-key rekey: old encrypted in-flight DATA is discarded and inner TCP must
retransmit; UDP may lose packets. Process shutdown still removes owned routes.

BIP and opaque challenge sessions default to renewal every 21600 seconds (six
hours); `transport.session_max_age_sec` accepts 30–86400, where zero selects the
default. Legacy generic/GGS4 sessions are not scheduled for renewal. Hard cipher
limits remain enforced regardless of timers. Outer BIP compact counter exhaustion
also requires fresh identity; it is never bypassed.

The process reader continues draining during handshake/recovery. Its fair queue
is bounded by 8MiB, 1024 flows and 128 packets per flow. Default maximum age is
5000ms; `performance.queue_max_age_ms` accepts 100–30000. Expired packets are
counted in `queue_expired_packets` and `tun_queue_drops`. This limits stale burst
delivery, not throughput: there is no new Mbps rate cap.

## Optional directional size discovery

Option **26** configures renewal, queue age, and `transport.path_mtu`. Discovery
is initially off; it currently supports BIP legacy/compact and UDP opaque with
challenge. Upgrade both peers before enabling. It starts with a 256-byte frame
payload and only raises the effective payload after a fresh authenticated probe
response. A normal supported path can confirm the configured ceiling immediately.
UDP sends DF packets without relying on unauthenticated ICMP PTB. BIP uses
disposable control packets, with complete IPv4 size equal to payload +152 even
in compact mode/SACK. Packet packing obeys the confirmed ceiling.

Failed large probes alone never prove MTU reduction: a small probe must succeed.
The simplified controller checks every 30 seconds, uses up to three attempts
per size, and cautiously probes the ceiling again. Reduction renews the carrier
to discard oversized encrypted in-flight packets while retaining TUN/forwards.
This is an experimental conservative controller, not a claim of complete
RFC 8899 conformance or zero loss during MTU change. `path_mtu_state` reports
disabled/searching/confirmed/unconfirmed/reduced/unsupported. An old BIP peer can
explicitly expose unsupported; an old UDP peer may remain searching. A blocked
carrier will not become reachable through size discovery.

GGS6 join codes carry these explicit settings and reject older managers. Existing
GGS2–GGS5 codes retain their wire meanings. Changing to another carrier via option
25 clears carrier-specific discovery/renewal overrides. Options 16/21 keep their
existing behavior; option 26 is independent of network tuning.

## Installer transactions

Upgrade and rollback save a durable installation journal before changing the
service unit, wrapper, current/previous pointers or active processes. Interrupted
transactions restore the prior generation at the next locked menu/install/rollback
invocation, then restart only previously active instances. The journal is retained
if recovery fails. This is recovery on the next invocation, not an automatic boot
repair service. Full manifests/version checks still precede execution of a new
package. Running/staying-active alone does not certify remote connectivity.

## Frozen cloud validation plan

Native amd64 and arm64 run identical fixed cases. Every result, including failed
rows and runner variance, is retained; no automatic rerun until green.

- Race/audit suite, repeated fresh-identity/cancellation/replay/probe regressions,
  both architecture builds, all installer and 26 menu dispatch tests.
- Seven carriers: staggered 30/45-second renewals over a 70-second persistent
  hashed TCP connection through a forwarding listener, at 200Mbps/80ms/0.15%
  loss. Same PIDs, unchanged TUN ifindex/routes, at least 2/1 renewals, at least
  20 verified frames and maximum progress gap ≤15s.
- BIP legacy/compact and UDP: silently drop outer packets >1200 bytes while
  local interfaces stay 1500; confirm safe payload, ≥15Mbps each direction;
  remove the limit and require upward confirmation; shrink to 1000 and require
  recovery with unchanged TUN/routes. No PTB feedback is delivered.
- Immutable RC5 archive SHA-256 `fd14bed5120c5d609bebd389d3999b5d132eeaa8430759bfc490ab898852da12`.
  Three fixed balanced A/B pairs for each direction and 200Mbps clean, 500Mbps
  clean, 200Mbps 1% loss and 200Mbps 3% loss, all at 80ms. Measure 20s after 2s
  warmup; retain cold readiness separately. Absolute receiver floors: respectively
  150/300/30/15Mbps. Require same processes, zero internal recoveries, ≥10 verified
  integrity frames and gap ≤5s. Paired geometric ratio ≥0.90, no pair <0.75,
  baseline coefficient of variation ≤0.15. Excess baseline variance makes a case
  inconclusive/failing; it does not authorize lowering criteria.

These are synthetic short gates. They cannot establish a 95% probability of
multi-day stability or prove resistance to the Iranian upstream firewall. DCPI
remains experimental; outer TCP's loss sensitivity remains documented. A later
stable decision still needs field observations and successful exact-tag gates.
