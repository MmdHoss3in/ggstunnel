"""Attach exact tagged-build measurements to the GitHub release description."""
import json
from pathlib import Path

root=Path(__file__).resolve().parents[1]
rows=[json.loads(line) for line in (root/'artifacts/network-results.jsonl').read_text().splitlines()]
notes=(root/'RELEASE_NOTES.md').read_text()
notes+='\n## Tagged-build cloud measurements\n\n'
notes+='Two endpoints and an intermediary Linux router, offloads disabled, receiver-path netem, 100Mbps link, 80ms base RTT, four TCP streams for eight measured seconds after a two-second warm-up. Each direction/loss sample starts fresh tunnel processes and controller state. Results are synthetic, not WAN guarantees.\n\n'
notes+='| Carrier | Loss per direction | Direction | Received Mbps |\n|---|---|---|---:|\n'
for row in rows:
    direction='reverse' if row['reverse'] else 'forward'
    notes+=f"| {row['profile']} | {row['loss']} | {direction} | {row['received_mbps']:.3f} |\n"
notes+='\n## Short real recovery checks\n\n'
for line in (root/'artifacts/recovery-results.jsonl').read_text().splitlines():
    row=json.loads(line)
    notes+='- `'+row['case']+'`: '+row['status']
    if 'recovery_sec' in row:notes+=f"; reachable {row['recovery_sec']:.3f}s after restoration/restart"
    notes+='\n'
notes+='\n## Extended exact-source validation\n\n'
notes+=(root/'artifacts/extended-report.md').read_text()
field=[]
for path in sorted((root/'field-collected').glob('*/field-artifacts/field-results.jsonl')):
    field.extend(json.loads(line) for line in path.read_text().splitlines() if line.strip())
if field:
    candidates=[r for r in field if r['version_label']=='candidate']
    if len(field)!=56 or len(candidates)!=28 or any(r['status']!='pass' for r in candidates):
        raise SystemExit('Missing or failed tagged field observations')
    notes+='\n## Directional field-pattern A/B checks\n\n'
    notes+='56 retained observations (28 rc1, 28 candidate), 16 TCP streams, 80ms RTT, 10 measured seconds after 2s warm-up. Clean/asymmetric/stateful candidate floors: 100Mbps on 200Mbps links and 200Mbps on 500Mbps links; PPS-policed floor: 30Mbps. Both versions use host socket ceilings >=16MiB. Full raw observations for this tagged run are in field-performance-results.tar.gz; earlier failed experiments are documented separately.\n\n'
    notes+='| Arch | Case | Link Mbps | Direction | Version | Received Mbps | Iran PULL probe pps | Status |\n|---|---|---:|---|---|---:|---:|---|\n'
    for r in field:
        direction='reverse' if r['reverse'] else 'forward'
        polls=r.get('feedback',[{}])[0].get('pull_probe_pps','n/a')
        notes+=f"| {r['architecture']} | {r['case']} | {r['link_mbps']} | {direction} | {r['version_label']} | {r.get('received_mbps','n/a')} | {polls} | {r['status']} |\n"
elif (root/'field-collected').exists():
    raise SystemExit('Tagged field observation files missing')
transport=[]
for path in sorted((root/'transport-collected').glob('*/extended-results/transport-results.jsonl')):
    transport.extend(json.loads(line) for line in path.read_text().splitlines() if line.strip())
if (root/'transport-collected').exists():
    if len(transport)!=92 or any(r['status']!='pass' for r in transport):
        raise SystemExit('Missing or failed tagged transport observations')
    notes+='\n## Native IO and compact wire checks\n\n'
    notes+='92 observations on amd64/arm64: all six carriers, payload 1280/1348, clean 200/500Mbps links, 80ms RTT, short loss and asymmetric/stateful paths. Low-loss cases have only a connectivity floor; ordered-delivery throughput under loss is not fixed. Accounting cases use no iperf omission and require receiver interval bytes to equal whole-transfer bytes. Raw NIC totals include link headers and idle control.\n\n'
    notes+='| Arch | Wire | Payload | Direction | Received Mbps | NIC rx / application bytes |\n|---|---|---:|---|---:|---:|\n'
    for r in transport:
        if r['case']!='accounting':continue
        ratio=r.get('nic_to_application_ratio')
        if ratio is None or r.get('warmup_sec')!=0:raise SystemExit('Tagged application accounting missing')
        notes+=f"| {r['architecture']} | {r['wire']} | {r['payload']} | {'reverse' if r['reverse'] else 'forward'} | {r['received_mbps']} | {ratio} |\n"
retry=[]
control=[]
# A single upload-artifact directory is flattened, whereas multi-directory
# uploads retain extended-results/. Support both without accepting duplicates.
control_paths = set((root/'transport-collected').glob('*/control-path-results.jsonl'))
control_paths.update((root/'transport-collected').glob('*/extended-results/control-path-results.jsonl'))
for path in sorted(control_paths):
    control.extend(json.loads(line) for line in path.read_text().splitlines() if line.strip())
if (root/'transport-collected').exists():
    expected={(arch,trial) for arch in ('amd64','arm64') for trial in range(32)}
    if len(control)!=64 or {(r['architecture'],r['trial']) for r in control}!=expected or any(r['status']!='pass' for r in control):
        raise SystemExit('Missing or failed captured directional control observations')
    notes+='\n## Captured directional ICMP control path\n\n'
    notes+='64 native amd64/arm64 observations: legacy/compact, all EchoRequests blocked in one direction, both blocked sides, 100/200Mbps links, 94ms RTT, one-way TCP and UDP, and 0.15%/1% loss. Clean TCP floors are half the shaped link rate; UDP sends 20Mbps and requires 15Mbps received. Loss cases retain a 1Mbps connectivity floor and do not certify high-throughput loss tolerance. Both FAST directions, authenticated alternative responses, unchanged processes and zero internal recoveries are required.\n\n'
    notes+='| Arch | Wire | Blocked side | Link Mbps | Direction | Loss | UDP | Received Mbps |\n|---|---|---:|---:|---|---|---|---:|\n'
    for r in control:
        notes+=f"| {r['architecture']} | {r['wire']} | {r['blocked_request_side']} | {r['link_mbps']} | {'reverse' if r['reverse'] else 'forward'} | {r['loss']} | {r['udp']} | {r['received_mbps']} |\n"
loss=[]
for path in sorted((root/'retry-collected').glob('*/extended-results/field-results.jsonl')):
    retry.extend(json.loads(line) for line in path.read_text().splitlines() if line.strip())
for path in sorted((root/'retry-collected').glob('*/extended-results/results.jsonl')):
    loss.extend(json.loads(line) for line in path.read_text().splitlines() if line.strip())
if (root/'retry-collected').exists():
    expected={(arch,repeat) for arch in ('amd64','arm64') for repeat in range(20)}
    if len(retry)!=40 or {(r['architecture'],r['repeat']) for r in retry}!=expected or any(r['status']!='pass' for r in retry):
        raise SystemExit('Missing or failed tagged repeated asymmetric retry observations')
    expected_loss={(arch,reverse,repeat) for arch in ('amd64','arm64') for reverse in (False,True) for repeat in range(3)}
    if len(loss)!=12 or {(r['architecture'],r['reverse'],r['repeat']) for r in loss}!=expected_loss or any(r['status']!='pass' or r['loss']!='3%' for r in loss):
        raise SystemExit('Missing or failed tagged repeated steady-loss observations')
    notes+='\n## Repeated retry-budget regression\n\n'
    notes+='40 fresh asymmetric 200Mbps/80ms observations (20 per architecture), using the original 100Mbps floor and zero internal-recovery requirement; plus 12 fresh 3% loss observations using the original 1Mbps/verified-progress gate. Earlier independent tag failures remain documented above. Passing these samples is not a multi-day or 100Mbps loss-path guarantee. Private metadata traces and per-case logs are retained in retry-validation-results.tar.gz.\n\n'
    notes+='| Arch | Asymmetric Mbps min/max | 3% loss Mbps min/max |\n|---|---:|---:|\n'
    for arch in ('amd64','arm64'):
        speeds=[r['received_mbps'] for r in retry if r['architecture']==arch]
        lossy=[r['received_mbps'] for r in loss if r['architecture']==arch]
        notes+=f"| {arch} | {min(speeds):.3f} / {max(speeds):.3f} | {min(lossy):.3f} / {max(lossy):.3f} |\n"
else:
    raise SystemExit('Tagged repeated retry artifacts missing')
(root/'artifacts/release-notes.md').write_text(notes)

# The new candidate must carry native feature evidence as well as all old gates.
import os
candidate=[]
for path in sorted((root/'transport-collected').glob('*/candidate-results.jsonl')):
    candidate.extend(json.loads(line) for line in path.read_text().splitlines() if line.strip())
expected={(arch,trial) for arch in ('amd64','arm64') for trial in range(32)}
if len(candidate)!=64 or {(r['architecture'],r['trial']) for r in candidate}!=expected:
    raise SystemExit('Missing native candidate feature observations')
for r in candidate:
    reference=r.get('recipe') in ('ordered-loss','independent-loss')
    if r['status'] != ('observed' if reference else 'pass') or r.get('source_commit')!=os.environ['GITHUB_SHA']:
        raise SystemExit('Failed or wrong-source candidate feature observations')
notes+='\n## Candidate native feature and loss-controller checks\n\n'
notes+='64 retained amd64/arm64 cases: opaque TCP/UDP/ICMP/GRE/IPIP/DCPI in both directions, three BIP recipes at 0/1/3% loss, and local MTU 1200 with TUN MTU retained. Reference recipes are measurements, not candidate success gates. Candidate clean/1%/3% floors are 100/3/2Mbps on a 200Mbps, 80ms path, with verified concurrent progress and unchanged processes. This is not high-loss 100Mbps or multiday certification. Full observations are included in transport-validation-results.tar.gz.\n\n'
notes+='| Arch | Recipe | Loss | Direction | Received Mbps | Status |\n|---|---|---|---|---:|---|\n'
for r in candidate:
    if r['kind']=='controller':
        notes+=f"| {r['architecture']} | {r['recipe']} | {r['loss']} | {'reverse' if r['reverse'] else 'forward'} | {r.get('received_mbps','n/a')} | {r['status']} |\n"
from rc5_report import report as rc5_report
notes += rc5_report(root/'rc5-collected', os.environ['GITHUB_SHA'])
from rc6_report import report as rc6_report
notes += rc6_report(root/'rc6-collected', os.environ['GITHUB_SHA'])
(root/'artifacts/release-notes.md').write_text(notes)
