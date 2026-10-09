# Retained v0.3.5 candidate failures

Tag v0.3.5 remains immutable at e5993e760e78d71f734923e3fdd041b8589617fd.
It has no published release. Run37937296864 retains all original gates and raw
observations; no failed rows are changed to passes and no acceptance floors are
reduced. The subsequent installable stable is v0.3.6; its first-attempt failures and one unchanged rerun are retained below.

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

## v0.3.6 publication and retained initial failures



Source d8d88f7b89dc25660f318fb4f6d0617db86c464f, run37941078025.
The new controlled queue study isolates clean200/500Mbps four-stream comparisons
against immutable v0.3.4. All historical random-loss gates remain unchanged.
All58 new pressure observations passed on native AMD64/ARM64.

Two historical speed gates failed in the initial attempt:

- Ubuntu22.04 compact smoke:81.209Mbps vs unchanged100Mbps floor in4 measured
  seconds after1s warmup. Authentication, FAST and kernel filter were healthy,
  with no TUN drops or recovery. Independent compact regressions on native
  AMD64/ARM64 passed, including the same smoke recipe.
  The single unchanged rerun passed at142.159Mbps forward and163.481Mbps reverse.
- ARM RC5 loss comparison:1%forward108.581Mbps vs120.2094 required (RC4 reference
  133.566Mbps). Queue drops and burst admissions were0. Same processes,0recovery,
  358 verified side-stream messages, maximum gap0.652s. Early/late quarter speeds
  were80.878/128.972Mbps. Five independent longer ARM1% pairs passed with geometric
  speed ratio0.9893 versus immutable RC5; baselineCV3.04%.

These observations justify one manual unchanged-code/unchanged-criteria rerun
of the two failed jobs after attempt1 completes. They do not prove that the
failures were solely runner noise, or guarantee every cold30s run exceeds the
reference floor. No retry-until-green policy, lowered acceptance formula or replaced tag is used.
GitHub rejected early rerun requests because attempt1 was still running; no
test execution was started by those requests.

The clean200Mbps study reduced median local drop fractions in all four native
direction/architecture cases. On clean500Mbps some medians increased slightly,
while speed increased approximately3–5%. Universal drop reduction is not claimed.
All58 pressure rows, raw samples and original failed-study artifacts are retained.
Short synthetic tests do not certify95% multiday Iran WAN/firewall reliability.

## Final outcome

Published v0.3.6 on2026-10-09T15:05:05Z; draft=false, prerelease=false and latest.
All63 final jobs passed in attempt2, reusing every previously successful job.
Only the two failed jobs and their dependent release execution were rerun once.
https://github.com/MmdHoss3in/ggstunnel/actions/runs/37941078025/attempts/2

ARM rerun candidate speeds were113.949/133.064Mbps at1%forward/reverse,
48.801/50.052Mbps at3%forward/reverse, and48.018Mbps for120s at3%forward.
The1%forward RC4 reference in this independent rerun was107.359Mbps rather than
the initial133.566; the unchanged90% formula therefore required96.6231Mbps.
The candidate itself increased from108.581 to113.949Mbps, not to120Mbps.
Passing this relative rerun does not erase the initial failure or establish an
absolute120Mbps cold-run guarantee. Recovery/reordering/progress gates also passed.

The exact published Linux archive SHA256 is
7533905bf96deb8ec998569861831ee9a93add9be4bc2c6565c0825ae0c48701.
Local inspection verified209 archive files and210 manifest checks with no binary
execution. Builds, races, fuzzing, native sockets, real TUN/systemd and pressure
tests ran only in GitHub cloud. The twelve qualification assets plus this retained
history are attached to https://github.com/MmdHoss3in/ggstunnel/releases/tag/v0.3.6.
