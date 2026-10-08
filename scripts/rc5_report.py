"""Fail-closed validation of exact-source RC5 lifecycle and loss evidence."""
import json
from pathlib import Path

ARCHES = ('amd64', 'arm64')
PROFILES = ('tcp', 'udp', 'icmp', 'gre', 'ipip', 'dcpi')
BASELINE = '5fa738b343000c6744a87fdae0c82a5967402f83'
CASES = (('1%', 30, False), ('1%', 30, True), ('3%', 30, False),
         ('3%', 30, True), ('3%', 120, False))


def validate_rows(rows, source):
    expected = {('rc5-lifecycle', arch, profile) for arch in ARCHES for profile in PROFILES}
    expected.update(('rc5-loss-ab', arch, version, loss, seconds, reverse)
                    for arch in ARCHES for version in ('rc4', 'candidate')
                    for loss, seconds, reverse in CASES)
    indexed = {}
    for row in rows:
        kind = row.get('kind')
        if kind == 'rc5-lifecycle':
            key = (kind, row['architecture'], row['profile'])
        elif kind == 'rc5-loss-ab':
            key = (kind, row['architecture'], row['version'], row['loss'], row['seconds'], row['reverse'])
        else:
            raise ValueError('Unknown RC5 evidence type')
        if key in indexed or key not in expected:
            raise ValueError('Duplicate or unexpected RC5 observation')
        baseline = row.get('version') == 'rc4'
        if row.get('source_commit') != source or row.get('runtime_source_commit') != (BASELINE if baseline else source):
            raise ValueError('Wrong-source RC5 evidence')
        if row.get('status') != ('observed' if baseline else 'pass'):
            raise ValueError('Failed RC5 observation')
        indexed[key] = row
    if indexed.keys() != expected:
        raise ValueError('Incomplete RC5 observations')
    for row in rows:
        if row['kind'] == 'rc5-lifecycle':
            if row.get('restart_loss') != '0.15%' or row.get('capacity_loss') != '0%':
                raise ValueError('Wrong restart/capacity recipe')
            recovery = row.get('restart_recovery_sec', [])
            if len(recovery) != 10 or any(not 0 <= value <= 20 for value in recovery):
                raise ValueError('Missing or slow one-sided restart evidence')
            speeds, udp = row.get('speeds', []), row.get('udp_speeds', [])
            if len(speeds) != 2 or any(s.get('received_mbps', 0) < 30 for s in speeds):
                raise ValueError('Missing TCP capacity evidence')
            if len(udp) != 2 or any(s.get('received_mbps', 0) < 15 or (s.get('lost_percent') or 0) > 1 for s in udp):
                raise ValueError('Missing UDP capacity/loss evidence')
            impaired = row.get('impaired_speeds', [])
            if len(impaired) != 2 or any(s.get('received_mbps', 0) < 1 for s in impaired):
                raise ValueError('Missing impaired TCP connectivity observations')
            peers = row.get('end_snapshot', {}).get('peers', [])
            if len(peers) != 2 or any(not p.get('telemetry', {}).get('peer_authenticated') or
                                     p['telemetry'].get('internal_recoveries', 0) or
                                     p['telemetry'].get('carrier', {}).get('session_mode') != 'challenge' for p in peers):
                raise ValueError('Missing authenticated lifecycle evidence')
        elif row['version'] == 'candidate':
            old = indexed[('rc5-loss-ab', row['architecture'], 'rc4', row['loss'], row['seconds'], row['reverse'])]
            floor = max(3 if row['loss'] == '1%' else 2, .9 * old['received_mbps'])
            progress = row.get('progress', {})
            if row.get('received_mbps', 0) < floor or not row.get('same_processes') or row.get('recoveries') != [0, 0] or progress.get('verified_frames', 0) < 10 or progress.get('max_gap_sec', float('inf')) > 5:
                raise ValueError('RC5 loss throughput/progress/recovery evidence failed')
    return rows


def report(directory, source):
    rows = []
    for path in sorted(Path(directory).rglob('rc5-focus-results.jsonl')):
        rows.extend(json.loads(line) for line in path.read_text().splitlines() if line.strip())
    validate_rows(rows, source)
    notes = '\n## Challenge lifecycle and RC4 loss A/B\n\n'
    notes += ('32 retained observations on native amd64/arm64. Six opaque challenge carriers each survive '
              'ten alternating one-sided restarts, retain the other process, and carry TCP and UDP in both '
              'directions on clean paths. Restarts and separate low-loss TCP observations use 0.15% loss; '
              'the latter retain only a 1Mbps connectivity floor, not a high-throughput guarantee. '
              'BIP uses the same independent/delivery configuration for RC4 and candidate, '
              'on 200Mbps/80ms paths at 1%/3% loss for 30/120 measured seconds. Candidate gates require '
              'at least 90% of the paired RC4 rate, unchanged processes, zero internal recoveries and '
              'concurrent verified progress. These are short synthetic checks, not multiday or DPI guarantees. '
              'Raw data and capacity-step/reordering evidence are in rc5-validation-results.tar.gz.\n\n')
    notes += '| Arch | Loss | Seconds | Direction | RC4 Mbps | Candidate Mbps |\n|---|---|---:|---|---:|---:|\n'
    indexed = {(r['architecture'], r.get('version'), r.get('loss'), r.get('seconds'), r.get('reverse')): r for r in rows if r['kind'] == 'rc5-loss-ab'}
    for arch in ARCHES:
        for loss, seconds, reverse in CASES:
            old = indexed[(arch, 'rc4', loss, seconds, reverse)]
            new = indexed[(arch, 'candidate', loss, seconds, reverse)]
            notes += f"| {arch} | {loss} | {seconds} | {'reverse' if reverse else 'forward'} | {old['received_mbps']:.3f} | {new['received_mbps']:.3f} |\n"
    return notes
