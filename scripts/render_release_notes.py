"""Attach exact tagged-build measurements to the GitHub release description."""
import json
from pathlib import Path

root=Path(__file__).resolve().parents[1]
rows=[json.loads(line) for line in (root/'artifacts/network-results.jsonl').read_text().splitlines()]
notes=(root/'RELEASE_NOTES.md').read_text()
notes+='\n## Tagged-build cloud measurements\n\n'
notes+='Two Linux namespaces, 100Mbps netem link, 80ms base RTT, four TCP streams for eight seconds. Tests run sequentially; results are synthetic, not WAN guarantees.\n\n'
notes+='| Carrier | Loss per direction | Direction | Received Mbps |\n|---|---|---|---:|\n'
for row in rows:
    direction='reverse' if row['reverse'] else 'forward'
    notes+=f"| {row['profile']} | {row['loss']} | {direction} | {row['received_mbps']:.3f} |\n"
(root/'artifacts/release-notes.md').write_text(notes)
