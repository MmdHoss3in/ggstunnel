# v0.3.7: DATA progress, PULL discovery and existing installation upgrades

Field reports from seven peers on 2026-10-12 exposed a failure that an
authenticated-peer flag cannot describe: control packets still arrived while
DATA delivery slowed to a trickle or stopped. Some new generations had no clean
RTT sample, a one-frame window, and continuous repaired acknowledgements.
These observations do not prove what initially disrupted the WAN path.

Empty incoming PULL probes now fund replies without renewing DATA path
confidence. If outgoing DATA cannot obtain a PULL acknowledgement within the
larger of four current RTT/RTO periods or the configured PULL deadline, the
sender probes request DATA (COMPAT). Existing flight and identities remain;
unproven adaptive request DATA admits one fresh request flight at a time.
Healthy PULL remains available and real PULL acknowledgements renew confidence.

Karn's rule remains: repaired DATA never supplies a clean RTT or base RTT.
Before the first clean sample, a repaired acknowledgement can conservatively
extend the startup timer from total original-flight age and admit bounded
discovery headroom (at most 16 frames). It cannot invent bandwidth, bypass
pacing, exceed the configured window, or alter manual mode. A subsequent clean
acknowledgement establishes normal timing.

PULL feedback scales with correlated delivered packets. One sparse reply no
longer implies 1000 requests/second. Short MORE gaps cannot continuously reset
the unanswered-discovery clock. Initial discovery remains bounded and useful
high-rate feedback can still grow without a new fixed DATA throughput cap.

`carrier.delivery_silence_ms` and `carrier.delivery_stalled` distinguish control
liveness from outstanding DATA progress. The existing peer-dead deadline also
causes recoverable transport renewal when authenticated controls keep arriving
but retained outgoing DATA obtains no acknowledgement. Idle tunnels do not
trigger this deadline. The existing retry budget may cause recovery earlier.
Transport recovery retains TUN, routes and forwarding listeners.

## Upgrade

After publication, run the pinned v0.3.7 `install.sh install` on foreign peers,
then Iran. Do not delete tunnels or generate new join codes. Configurations,
keys, addresses, forwards and enabled/stopped service states remain unchanged;
only active services are restarted. Saved options 16/21 need no repetition.
If old configs have never adopted independent delivery and the delivery tuner,
apply option 21 once on both peers after upgrading; this is a separate setting.

Option 19 restores the previous installed executable/manager/unit. A failed
upgrade restores the durable installation transaction, including already
restarted services. Configuration rollback is separate and is not performed by
binary upgrade. Direct `sudo ggstunnel` opens the menu without dependency checks.

## Qualification

All previous release gates remain unchanged. Added cloud checks repeat the
field-stall race regressions on native amd64/arm64, exercise real systemd
upgrade/rollback of seven 0.3.6 configurations (five active, one enabled but
stopped, one disabled), inject failure during the third restart, and measure
both upgrade orders/directions with old, mixed and new peers on a synthetic
200Mbps/80ms path. Release publication requires all 26 native observations from
the tagged source; raw records are retained in `field-stall-results.tar.gz`.
Passing these tests is not a 95% extrapolation to multiday WAN behavior or a
guarantee against upstream filtering. Wire modes, crypto, default payload,
queue limits, host tuning and firewall policy are unchanged.
