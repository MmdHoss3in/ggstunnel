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
(root/'artifacts/release-notes.md').write_text(notes)
