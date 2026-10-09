# v0.3.4 preparation: preserved failures and comparison recipes

Published RC5 remains immutable: source aab18976517393dc87a1437eceaca63169ccee66,
archive SHA256 fd14bed5120c5d609bebd389d3999b5d132eeaa8430759bfc490ab898852da12.
Its existing failure/confirmation history is in rc5-validation-history.md.

## Initial RC6 experiments

Run37914368143 stopped on a new installer test fixture missing theggs01 config;
recovery correctly refused to restart an unknown instance. Sourcefcfbcdd fixed
the fixture and cold-readiness timing. Run37914594253 was deliberately cancelled
when review found a genuine stale-full-flow admission issue;36acbef expires old
entries before fresh retries and added repeated regressions.

[Final original RC6 run](https://github.com/MmdHoss3in/ggstunnel/actions/runs/37915184790)
on36acbef1002bd7f2c7687cb47ca7ec9abc9954e5 passed all14 renewal and6 size-discovery
cases. All96 individual capacity/integrity/process runs passed;15/16 paired
summaries passed. The amd64 performance job remained failed, not ignored.

The sole failed summary was reverse1%loss at200Mbps. RC5 rates were
92.488/145.331/127.613Mbps versus candidate119.855/110.365/126.831Mbps. Geometric
ratio99.264%, minimum pair75.940%; baseline coefficient of variation22.079%
exceeded the fixed15%maximum. The baseline's first sample increased from
75.751Mbps first-quarter to116.126 last-quarter, exposing transient behavior.
These observations are inconclusive A/B evidence, not a proved candidate crash
or corruption and not a pass. No retry-until-green or weaker criteria was used.

On clean500Mbps, the original candidate measured352.270–361.180Mbps amd64 and
417.011–419.806Mbps arm64. AMD geometric ratios95.59/95.26% showed a real4.4–4.7%
decrease within the predeclared10% allowance. Source review identified an extra
transmit copy and per-packet receive-buffer/completion-channel allocations in
the persistent bridge. The stable preparation removes these costs while retaining
the bounded queues and safe cancellation ownership; new native measurements,
not this source inference, determine their effect.

## Prespecified steady-v2 comparison

Before observing its new results, freeze: three balanced pairs on clean200/500Mbps
with20 measured seconds/2-second warmup; five balanced pairs at1%/3%loss in both
directions with45 measured seconds/15-second warmup. All use16 inner TCP streams,
80ms RTT, independent random netem loss and a hashed side stream spanning the
entire warmup/measurement. Record cold readiness separately, all endpoint metrics,
both executable source identities and receiver intervals. No deterministic loss
is substituted for random loss. Split directions into jobs to bound wall time.

Unchanged floors:150/300Mbps clean,30Mbps at1%,15Mbps at3%; unchanged A/B gates:
geometric ratio>=0.90, every pair>=0.75, baselineCV<=0.15. Every sample retains
verified progress, maximum gap<=5s, same PIDs and zero internal recoveries.
If this longer recipe also fails or remains noisy, preserve the failure and
diagnose it; publication is blocked, not authorized by changed criteria.

The full release pipeline reruns all historical gates and the164-observation
RC6 gate on one exact commit, revalidates the raw results before creating assets,
and attaches them to the release. Passing remains short synthetic evidence;
real Iran–outside multi-day behavior and firewall blocking need field observations.
