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
(root/'artifacts/release-notes.md').write_text(notes)
