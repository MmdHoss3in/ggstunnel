"""Diagnostic only: retain A/A noise controls, never qualify or publish releases."""
import hashlib
import json
import os
from pathlib import Path
import statistics
import tarfile
import tempfile
import time

from cloud_extended import ARCH, BIN, OUT, SOURCE, Pair, run
from rc5_focus import transfer

CANDIDATE = 'aab18976517393dc87a1437eceaca63169ccee66'
BASELINE = '5fa738b343000c6744a87fdae0c82a5967402f83'


def main():
    if os.geteuid() != 0 or os.environ.get('GITHUB_ACTIONS') != 'true':
        raise RuntimeError('Disposable privileged cloud runner required')
    if run('git', '-C', SOURCE, 'rev-parse', 'HEAD').stdout.strip() != CANDIDATE:
        raise RuntimeError('Wrong candidate source')
    OUT.mkdir(exist_ok=True)
    for key in ('net.core.rmem_max', 'net.core.wmem_max'):
        run('sysctl', '-qw', f'{key}={max(int(run("sysctl", "-n", key).stdout),16 << 20)}')
    loss = '1%' if ARCH == 'amd64' else '3%'
    observations = []
    failures = 0
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary); archive = root / 'rc4.tar.gz'
        run('curl', '-fL', '--retry', '3', 'https://github.com/MmdHoss3in/ggstunnel/releases/download/v0.3.4-rc4/ggstunnel-linux.tar.gz', '-o', archive)
        if hashlib.sha256(archive.read_bytes()).hexdigest() != '962ebfa526fd5a36719619e63ac39ccdf555cc2845edc151e3651c752d2a4dcb':
            raise RuntimeError('RC4 checksum mismatch')
        with tarfile.open(archive) as package:
            package.extractall(root, filter='data')
        baseline = root / 'ggstunnel' / 'dist' / ('ggstunnel-linux-' + ARCH)
        baseline.chmod(0o755)
        orders = [('rc4-a', 'rc4-b', 'candidate'), ('candidate', 'rc4-b', 'rc4-a'), ('rc4-a', 'candidate', 'rc4-b')]
        for trial, order in enumerate(orders):
            for label in order:
                row = dict(kind='rc5-variance', architecture=ARCH, trial=trial,
                           version=label, loss=loss, seconds=30, reverse=False,
                           runtime_source_commit=CANDIDATE if label == 'candidate' else BASELINE,
                           status='fail')
                try:
                    executable = BIN if label == 'candidate' else baseline
                    with Pair(label=f'variance-{trial}-{label}-') as pair:
                        pair.executables = [executable, executable]
                        pair.baseline_preserve_config = True
                        pair.shape(200, 80, loss); pair.restart(); time.sleep(1.2)
                        row.update(transfer(pair, 30, False))
                    progress = row['progress']
                    if not row['same_processes'] or any(row['recoveries']) or progress['verified_frames'] < 10 or progress['max_gap_sec'] > 5:
                        raise RuntimeError('Integrity/progress/recovery failed')
                    row['status'] = 'observed'
                except Exception as exc:
                    row['error'] = str(exc); failures += 1
                observations.append(row)
                with (OUT / 'loss-variance.jsonl').open('a') as output:
                    output.write(json.dumps(row) + '\n')
                print(json.dumps({key: row[key] for key in ('trial', 'version', 'loss', 'status', 'received_mbps', 'error') if key in row}), flush=True)
    summary = dict(architecture=ARCH, candidate_source=CANDIDATE, baseline_source=BASELINE,
                   loss=loss, diagnostic_only=True, failures=failures, trials=[])
    for trial in range(3):
        values = {r['version']: r['received_mbps'] for r in observations if r['trial'] == trial and r['status'] == 'observed'}
        if len(values) == 3:
            old = [values['rc4-a'], values['rc4-b']]
            summary['trials'].append(dict(trial=trial, rates=values,
                baseline_self_ratio=min(old) / max(old),
                candidate_to_baseline_mean=values['candidate'] / statistics.mean(old)))
    (OUT / 'loss-variance-summary.json').write_text(json.dumps(summary, indent=2))
    print(json.dumps(summary), flush=True)
    if failures:
        raise RuntimeError('Diagnostic progress/integrity failed; retain all observations')


if __name__ == '__main__':
    main()
