# Retained v0.3.5 candidate failures

Tag v0.3.5 remains immutable at e5993e760e78d71f734923e3fdd041b8589617fd.
It has no published release. Run37937296864 retains all original gates and raw
observations; no failed rows are changed to passes and no acceptance floors are
reduced. Latest installable stable remains v0.3.4 until a later tag passes.

The first queue study attempted a 100Mbps per-sample floor on a four-stream
200Mbps/80ms path with independent random 0.15% loss. On AMD64, immutable
v0.3.4 itself ranged33.917..130.583Mbps; candidate24.152..114.508Mbps. Neither
provides a stable baseline or a reliable claim of 100Mbps under this recipe.
Some slow samples had zero local queue drops and never borrowed burst capacity.
This is a retained limitation of low-stream-count TCP on an impaired path, not
evidence that a larger queue removes all throughput constraints. Longer warmup
alone has not been demonstrated to fix it. The original measurements are retained.

Clean500Mbps paired results on AMD64: candidate417.693..420.948Mbps; geometric
ratios1.031/1.015 in forward/reverse. Median local drop fraction was slightly
higher by0.144/0.137 percentage points; p95 ping increased3.39/1.51ms. These
samples do not establish universal drop reduction. Deliberate160Mbps UDP offered
to50Mbps retained sparse progress at pingp95=246.3ms and bounded memory.
Ten-minute500Mbps hold delivered418.315Mbps AMD64 and419.839Mbps ARM64.

Two additional historical gates failed: AMD RC5 single-pair1% forward100.422Mbps
versus104.5881Mbps required (RC4 reference116.209); candidate queue drops0 and
burst admissions0, with slower initial progression. ARM opaque ICMP reverse
failed verified continuity. Neither failure is silently waived or blamed on the
environment. Candidate burst admission had originally been enabled for every
carrier. The follow-up narrows the new behavior to BIP; generic carriers retain
their original128-packet bound and get additive diagnostics only.

Follow-up qualification isolates queue-pressure changes with four-stream clean
200/500Mbps paired cases, while all historical random-loss, reordering, recovery,
compatibility and16-stream loss comparisons stay mandatory and unchanged.
This does not certify four-stream100Mbps performance on the failed loss recipe.
The new clean study keeps the same100/300Mbps floors, paired90%/75% gates,
baselineCV15%, latency/drop/CPU and resource limits. A controlled queue study
cannot stand in for a lossy-WAN guarantee. The next tag requires a full new
exact-source cloud run, with all raw reports published.
