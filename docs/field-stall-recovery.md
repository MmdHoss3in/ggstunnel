# v0.3.7: DATA progress, PULL discovery and existing installation upgrades

Published 2026-10-12 from `9faa13d5dc8bc3f0a04a7bcd3f6125b0701f681a` after
all **65 final jobs** passed:
[exact-source run](https://github.com/MmdHoss3in/ggstunnel/actions/runs/38235510413).
All 26 native upgrade/mixed-peer observations passed. The 600-second
500Mbps/80ms BIP hold measured **415.517Mbps amd64 / 419.320Mbps arm64**;
maximum process RSS was **36.539 / 28.023MiB**. Early/late receiver medians were
419.703/418.607 and 421.525/421.531Mbps, respectively; processes remained the
same, with verified concurrent flow maximum gaps of 0.214/0.196s. Both
900-second resource gates passed with unchanged processes and 8 early/late
file descriptors; maximum RSS was 33.547/27.121MiB in those separate scenarios.
These are synthetic measurements, not multiday WAN or filtering guarantees.
The first fixture failure and correction are retained as an
[authored history summary](https://github.com/MmdHoss3in/ggstunnel/releases/download/v0.3.7/field-stall-validation-history.zip).
Raw initial runner logs remain local; the archive contains no raw environment
data. Final measurements are available in the release validation archives.


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

The first qualification run at source `f26dba0ee84da1373def736a262443ce3d1aff08`
passed native runtime/race and manager checks but both new real-upgrade jobs
rejected the fixture's loopback addresses before creating tunnels. The manager's
existing unicast guard is intentional. The fixture was corrected to use a
disposable private dummy interface; production code and pass criteria were not
changed. The original run is retained at
https://github.com/MmdHoss3in/ggstunnel/actions/runs/38234942255.
