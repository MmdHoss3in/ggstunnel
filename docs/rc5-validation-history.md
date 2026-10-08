# RC5 retained release validation history

Runtime/source candidate: aab18976517393dc87a1437eceaca63169ccee66,
immutable tag v0.3.4-rc5. RC4 baseline:
5fa738b343000c6744a87fdae0c82a5967402f83, original verified archive.

## Original exact-tag attempt

https://github.com/MmdHoss3in/ggstunnel/actions/runs/37856122779/attempts/1

48 successful validation jobs, two failed RC5 sustained-loss A/B jobs; publication
was skipped. Same processes, integrity/progress and zero internal recovery passed
in all ten candidate A/B cases. Two individual speed nonregression gates failed:

| Architecture | Path | RC4 Mbps | RC5 Mbps | Required Mbps |
|---|---|---:|---:|---:|
| amd64 | 1% loss, forward, 30 measured seconds | 138.419 | 106.072 | 124.5771 |
| arm64 | 3% loss, forward, 30 measured seconds | 54.377 | 48.415 | 48.9393 |

These observations remain failures. Later observations cannot erase them or prove
statistical performance improvement/nonregression. Passing a retry does not certify
multiday stability, DPI resistance or 95% confidence for real-world links.

## Independent variance diagnosis

https://github.com/MmdHoss3in/ggstunnel/actions/runs/37858601676

Diagnostic source `0916f179fc85daf7c15e30afbe4988dd536d171e` builds the same immutable
candidate runtime; no runtime edits. Three order-balanced RC4-A/RC4-B/RC5 sets for
each failed pattern, unchanged 30-second/16-stream/2-second-warmup recipe. No
release qualification or relaxed gate is performed by this diagnostic.

| Arch | Trial | RC4 A Mbps | RC4 B Mbps | RC5 Mbps | RC4 min/max | RC5/RC4 mean |
|---|---:|---:|---:|---:|---:|---:|
| amd64 | 0 | 111.783 | 114.740 | 122.034 | 0.9742 | 1.0775 |
| amd64 | 1 | 113.623 | 122.476 | 111.674 | 0.9277 | 0.9460 |
| amd64 | 2 | 97.213 | 117.988 | 120.740 | 0.8239 | 1.1221 |
| arm64 | 0 | 48.695 | 49.987 | 49.115 | 0.9742 | 0.9954 |
| arm64 | 1 | 51.730 | 49.393 | 53.505 | 0.9548 | 1.0582 |
| arm64 | 2 | 49.881 | 52.740 | 49.324 | 0.9458 | 0.9613 |

All 18 diagnostic measurements retain verified progress, original processes and
zero internal recoveries. The 17.6% RC4 self-variation on amd64 demonstrates noise
in a single paired speed observation. This supports one bounded exact-source
confirmation, not repeated retries until green or a statistically proven benefit.

## Bounded confirmation

Exactly one rerun-failed-jobs was requested after attempt1 completed. Successful
jobs are retained. Original source and every criterion are unchanged.
[Attempt 2](https://github.com/MmdHoss3in/ggstunnel/actions/runs/37856122779/attempts/2)
completed SUCCESS: all 51 jobs, including publication. The ten candidate A/B
cases passed: 1% loss 104.084–148.932 Mbps; 3% loss 48.347–51.730 Mbps; 120-second
3% cases 49.389/49.398 Mbps. No further performance retry was used. This does not
erase the first failures or establish statistical nonregression.

## Retained raw evidence

The four ZIPs inside the release asset
[rc5-validation-history.zip](https://github.com/MmdHoss3in/ggstunnel/releases/download/v0.3.4-rc5/rc5-validation-history.zip)
contain complete original failed loss results and independent controls.
SHA256 values match GitHub's artifact digests:

```text
b53c972ba8192270d87577e787694120caaf52bcdc512dfa6fa33ba2247ba2aa  rc5-attempt1-amd-loss.zip
e291b55ebd16258e616559e50a20062822bb9145e186e34f0c9edf53672188ee  rc5-attempt1-arm-loss.zip
b34d1a56997113e66626f5de317822070c08fd2b0511da09e25e603324925ead  rc5-variance-amd.zip
d85f48169d922a429f120deb45c37c9291f9736bd01648abd7d2ad2635ae03b3  rc5-variance-arm.zip
```
