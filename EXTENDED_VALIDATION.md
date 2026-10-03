# rc4 extended short cloud validation

This report describes short synthetic tests of the unchanged rc4 runtime. It does not establish multi-day uptime or Iran/foreign WAN reliability. All failures and target misses are retained.

Recovery trials: 60/60 passed; 60 planned runs complete: True.

Conditional exact one-sided 95% lower confidence bound: 95.130% success for the specified short experiment, assuming independent trials and a fixed distribution. Seed changes and separate runners do not prove those assumptions. This is not a multi-day survival probability.

Reviewed completion evidence: all 15 experiment jobs and the boundary job passed. The planned 438 observations are present (60 direct baselines, 180 tunnel throughput samples, 72 recovery/impairment trials, 90 resource cycles, 2 integrity results, 4 resource summaries and 30 lifecycle cycles). No failed or target-missed rows were discarded. Raw Go logs were inspected for package successes and absence of FAIL/panic/data race, because the original workflow tee pipelines did not explicitly enable pipefail. Future runs use an explicit Bash shell.

The tested binaries match the published rc4 package by SHA256 on both architectures. All 17 downloaded artifacts have been verified against their GitHub digests. Read [the reviewed Persian report](EXTENDED_VALIDATION-fa.md) for workload, acceptance criteria and remaining limitations.


## Throughput

| Carrier | Link Mbps | RTT ms | Direction | Samples | Min / median / max Mbps | Median direct baseline Mbps | Target misses/errors |
|---|---:|---:|---|---:|---|---:|---:|
| bip | 200 | 20 | forward | 3 | 168.67/169.08/170.00 | 191.24 | 0 |
| bip | 200 | 20 | reverse | 3 | 168.65/168.68/169.52 | 191.35 | 0 |
| bip | 200 | 80 | forward | 3 | 168.64/168.66/168.66 | 191.34 | 0 |
| bip | 200 | 80 | reverse | 3 | 168.65/168.65/168.68 | 191.17 | 0 |
| bip | 200 | 200 | forward | 3 | 154.93/166.09/166.32 | 188.85 | 0 |
| bip | 200 | 200 | reverse | 3 | 156.94/165.40/165.64 | 190.12 | 0 |
| bip | 300 | 20 | forward | 3 | 253.03/253.04/253.08 | 287.02 | 0 |
| bip | 300 | 20 | reverse | 3 | 253.02/253.06/253.06 | 287.00 | 0 |
| bip | 300 | 80 | forward | 3 | 253.04/253.06/253.08 | 286.79 | 0 |
| bip | 300 | 80 | reverse | 3 | 253.02/253.06/253.09 | 286.89 | 0 |
| bip | 300 | 200 | forward | 3 | 159.63/168.90/176.13 | 279.07 | 0 |
| bip | 300 | 200 | reverse | 3 | 167.95/183.88/189.51 | 282.17 | 0 |
| gre | 200 | 20 | forward | 3 | 175.13/175.18/175.19 | 191.36 | 0 |
| gre | 200 | 20 | reverse | 3 | 173.75/174.27/174.84 | 191.16 | 0 |
| gre | 200 | 80 | forward | 3 | 175.15/175.19/175.39 | 191.21 | 0 |
| gre | 200 | 80 | reverse | 3 | 175.15/175.18/175.21 | 191.26 | 0 |
| gre | 200 | 200 | forward | 3 | 175.13/175.76/175.88 | 188.10 | 0 |
| gre | 200 | 200 | reverse | 3 | 175.60/175.71/175.81 | 190.41 | 0 |
| gre | 300 | 20 | forward | 3 | 262.76/263.00/263.32 | 287.03 | 0 |
| gre | 300 | 20 | reverse | 3 | 262.74/263.37/263.47 | 286.91 | 0 |
| gre | 300 | 80 | forward | 3 | 262.72/262.76/263.85 | 286.92 | 0 |
| gre | 300 | 80 | reverse | 3 | 262.77/262.99/263.37 | 287.01 | 0 |
| gre | 300 | 200 | forward | 3 | 252.10/252.94/257.50 | 279.31 | 0 |
| gre | 300 | 200 | reverse | 3 | 249.88/257.15/258.69 | 282.17 | 0 |
| icmp | 200 | 20 | forward | 3 | 165.43/165.87/166.45 | 191.36 | 0 |
| icmp | 200 | 20 | reverse | 3 | 166.34/166.90/167.81 | 191.26 | 0 |
| icmp | 200 | 80 | forward | 3 | 166.31/166.63/166.67 | 191.32 | 0 |
| icmp | 200 | 80 | reverse | 3 | 165.43/165.92/166.34 | 191.37 | 0 |
| icmp | 200 | 200 | forward | 3 | 165.96/166.09/167.35 | 188.90 | 0 |
| icmp | 200 | 200 | reverse | 3 | 166.27/166.65/166.97 | 189.90 | 0 |
| icmp | 300 | 20 | forward | 3 | 250.28/250.88/250.89 | 286.83 | 0 |
| icmp | 300 | 20 | reverse | 3 | 250.12/250.26/250.37 | 286.79 | 0 |
| icmp | 300 | 80 | forward | 3 | 250.60/250.67/250.91 | 287.05 | 0 |
| icmp | 300 | 80 | reverse | 3 | 250.99/251.34/251.59 | 286.89 | 0 |
| icmp | 300 | 200 | forward | 3 | 246.28/246.39/248.58 | 279.45 | 0 |
| icmp | 300 | 200 | reverse | 3 | 225.58/236.31/245.23 | 282.08 | 0 |
| tcp | 200 | 20 | forward | 3 | 172.12/172.17/172.18 | 191.33 | 0 |
| tcp | 200 | 20 | reverse | 3 | 172.14/172.14/172.28 | 191.36 | 0 |
| tcp | 200 | 80 | forward | 3 | 149.44/150.69/150.74 | 191.18 | 0 |
| tcp | 200 | 80 | reverse | 3 | 150.47/150.65/150.72 | 191.38 | 0 |
| tcp | 200 | 200 | forward | 3 | 61.57/62.67/64.10 | 188.66 | 0 |
| tcp | 200 | 200 | reverse | 3 | 61.59/62.81/63.05 | 190.23 | 0 |
| tcp | 300 | 20 | forward | 3 | 258.70/258.77/259.34 | 286.94 | 0 |
| tcp | 300 | 20 | reverse | 3 | 258.69/258.79/258.79 | 286.79 | 0 |
| tcp | 300 | 80 | forward | 3 | 159.00/159.07/159.15 | 287.00 | 0 |
| tcp | 300 | 80 | reverse | 3 | 159.21/161.13/161.31 | 286.79 | 0 |
| tcp | 300 | 200 | forward | 3 | 64.78/65.89/66.04 | 279.30 | 0 |
| tcp | 300 | 200 | reverse | 3 | 64.38/65.12/65.15 | 282.50 | 0 |
| udp | 200 | 20 | forward | 3 | 177.56/177.57/177.72 | 191.29 | 0 |
| udp | 200 | 20 | reverse | 3 | 176.82/177.21/177.28 | 191.28 | 0 |
| udp | 200 | 80 | forward | 3 | 177.62/177.70/177.74 | 191.28 | 0 |
| udp | 200 | 80 | reverse | 3 | 177.52/177.70/177.70 | 191.38 | 0 |
| udp | 200 | 200 | forward | 3 | 176.81/177.33/177.88 | 188.91 | 0 |
| udp | 200 | 200 | reverse | 3 | 177.28/177.59/177.87 | 190.11 | 0 |
| udp | 300 | 20 | forward | 3 | 266.53/266.58/267.05 | 286.88 | 0 |
| udp | 300 | 20 | reverse | 3 | 266.58/266.58/267.22 | 287.00 | 0 |
| udp | 300 | 80 | forward | 3 | 266.60/266.74/266.99 | 287.02 | 0 |
| udp | 300 | 80 | reverse | 3 | 266.52/266.55/266.72 | 287.00 | 0 |
| udp | 300 | 200 | forward | 3 | 219.50/228.76/249.42 | 279.22 | 0 |
| udp | 300 | 200 | reverse | 3 | 216.04/239.78/249.31 | 281.75 | 0 |

## Impairments and failures

- 0.2%: pass; first existing-flow response=0.027s; longest response gap=1.665s; supervisor restarts=0/0.
- 1%: pass; first existing-flow response=0.244s; longest response gap=4.047s; supervisor restarts=0/0.
- 3%: pass; first existing-flow response=0.006s; longest response gap=11.563s; supervisor restarts=0/0.
- burst: pass; first existing-flow response=0.149s; longest response gap=0.838s; supervisor restarts=0/0.
- reorder: pass; first existing-flow response=0.175s; longest response gap=6.134s; supervisor restarts=0/0.
- duplicate: pass; first existing-flow response=0.176s; longest response gap=1.055s; supervisor restarts=0/0.
- asymmetric: pass; first existing-flow response=0.424s; longest response gap=17.422s; supervisor restarts=0/0.
- policing: pass; first existing-flow response=0.012s; longest response gap=40.388s; supervisor restarts=0/0.
- peer_restart: pass; first existing-flow response=0.729s; longest response gap=0.767s; supervisor restarts=0/0.
- blackhole10: pass; first existing-flow response=8.35s; longest response gap=18.477s; supervisor restarts=0/0.
- blackhole30: pass; first existing-flow response=0.859s; longest response gap=30.985s; supervisor restarts=0/0.
- blackhole60: pass; first existing-flow response=1.378s; longest response gap=61.513s; supervisor restarts=1/1.

## Resource observations

- {"kind": "resource_integrity", "status": "pass", "verified_frames": 8333, "duration_sec": 900, "same_processes": true, "binary_version": "ggstunnel 0.3.0-rc4", "architecture": "amd64"}
- {"kind": "resource_summary", "peer": 0, "samples": 937, "max_rss_mib": 25.98828125, "early_rss_mib": 11.34765625, "late_rss_mib": 19.98828125, "early_fds": 8.0, "late_fds": 8.0, "status": "pass", "binary_version": "ggstunnel 0.3.0-rc4", "architecture": "amd64"}
- {"kind": "resource_summary", "peer": 1, "samples": 937, "max_rss_mib": 26.65625, "early_rss_mib": 15.20703125, "late_rss_mib": 13.109375, "early_fds": 8.0, "late_fds": 8.0, "status": "pass", "binary_version": "ggstunnel 0.3.0-rc4", "architecture": "amd64"}
- {"kind": "resource_integrity", "status": "pass", "verified_frames": 8646, "duration_sec": 900, "same_processes": true, "binary_version": "ggstunnel 0.3.0-rc4", "architecture": "arm64"}
- {"kind": "resource_summary", "peer": 0, "samples": 937, "max_rss_mib": 24.37109375, "early_rss_mib": 10.1328125, "late_rss_mib": 11.5390625, "early_fds": 8.0, "late_fds": 8.0, "status": "pass", "binary_version": "ggstunnel 0.3.0-rc4", "architecture": "arm64"}
- {"kind": "resource_summary", "peer": 1, "samples": 937, "max_rss_mib": 22.89453125, "early_rss_mib": 12.14453125, "late_rss_mib": 10.0625, "early_fds": 8.0, "late_fds": 8.0, "status": "pass", "binary_version": "ggstunnel 0.3.0-rc4", "architecture": "arm64"}

RSS/FD measurements are short screening observations, not a proof of absence of leaks. In-process Go heap/goroutine tests, if present, are separate from measurements of the exact release executable.

Impairment passes indicate first-response recovery and data integrity under the specified connectivity floor; they do not establish steady speed or a bound on subsequent stalls. These averages include the clean pre-injection period. The 5Mbps case used netem shaping of all outer traffic with a large queue; it was not an ICMP-specific policer. The 60-second outage required one automatic systemd restart on each endpoint. BIP's 300Mbps/200ms throughput was 159.635–189.513Mbps; telemetry reached the 4096-frame window ceiling. TCP's 200ms throughput was 61.568–66.044Mbps. These remaining performance limits were not repaired or hidden by this validation run.
