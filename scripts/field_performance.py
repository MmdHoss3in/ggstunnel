"""A/B real encrypted TUN checks for the observed asymmetric field pattern."""
import json
import os
from pathlib import Path
import time

from cloud_extended import ARCH, BIN, OUT, Pair, run


def firewall(pair, mode):
    router = ['ip', 'netns', 'exec', pair.router, 'iptables']
    run(*router, '-F', 'FORWARD')
    run(*router, '-P', 'FORWARD', 'ACCEPT')
    if mode == 'asymmetric':
        run(*router, '-A', 'FORWARD', '-s', pair.outer[0], '-p', 'icmp',
            '--icmp-type', 'echo-request', '-m', 'u32', '--u32',
            '0>>22&0x3C@12>>24=1:6', '-j', 'DROP')
    elif mode == 'stateful':
        # Make both versions exercise PULL. Legacy reused cross-direction
        # identifiers can otherwise let FAST probes match stale conntrack.
        run(*router, '-A', 'FORWARD', '-p', 'icmp', '--icmp-type', 'echo-reply',
            '-m', 'u32', '--u32', '0>>22&0x3C@12>>24=1', '-j', 'DROP')
        run(*router, '-A', 'FORWARD', '-p', 'icmp', '--icmp-type', 'echo-reply',
            '-m', 'conntrack', '--ctstate', 'INVALID,NEW', '-j', 'DROP')
    elif mode == 'pps':
        for i, address in enumerate(pair.outer):
            chain = f'GGS_PPS_{i}'
            run(*router, '-N', chain, check=False)
            run(*router, '-F', chain)
            run(*router, '-A', chain, '-m', 'limit', '--limit', '8000/second', '--limit-burst', '256', '-j', 'RETURN')
            run(*router, '-A', chain, '-j', 'DROP')
            run(*router, '-A', 'FORWARD', '-s', address, '-p', 'icmp', '-j', chain)


def main():
    if os.geteuid() != 0 or os.environ.get('GITHUB_ACTIONS') != 'true':
        raise RuntimeError('Disposable privileged GitHub Actions runner required')
    OUT.mkdir(exist_ok=True)
    # Same ceilings as menu option 16; both A/B versions receive the same host
    # resources. Do not disable kernel echo globally: that also disables the
    # inner TUN ping used to establish application reachability.
    for key in ('net.core.rmem_max', 'net.core.wmem_max'):
        current = int(run('sysctl', '-n', key).stdout.strip())
        run('sysctl', '-qw', f'{key}={max(current, 16<<20)}')
    base = Path(os.environ['GGS_FIELD_BASE']) / 'dist' / ('ggstunnel-linux-' + ARCH)
    failures = []
    rows = []
    modes = (os.environ['GGS_FIELD_MODE'],) if os.environ.get('GGS_FIELD_MODE') else ('clean', 'asymmetric', 'stateful', 'pps')
    if any(mode not in ('clean', 'asymmetric', 'stateful', 'pps') for mode in modes):
        raise ValueError('Unknown field case')
    for mode in modes:
        for rate in ((200,) if mode == 'pps' else (200, 500)):
            for reverse in (False, True):
                versions = [('rc1', base), ('candidate', BIN)]
                if reverse: versions.reverse()
                samples = {}
                for label, executable in versions:
                    row = dict(case=mode, link_mbps=rate, base_rtt_ms=80, reverse=reverse,
                               version_label=label, architecture=ARCH, sample_sec=10, warmup_sec=2)
                    try:
                        with Pair('bip') as pair:
                            pair.executables = [executable, executable]
                            firewall(pair, mode)
                            pair.shape(rate, 80)
                            pair.restart()
                            before = pair.sample(); began = time.monotonic()
                            result = pair.finish_iperf(*pair.iperf('10.77.1.2', 10, 2, reverse, 16), 45)
                            time.sleep(1.1)
                            after = pair.sample(); elapsed = time.monotonic() - began
                            feedback = []
                            for a, b in zip(before['peers'], after['peers']):
                                initial = a.get('telemetry', {}).get('carrier', {})
                                final = b.get('telemetry', {}).get('carrier', {})
                                delta = {key: final.get(key, 0)-initial.get(key, 0)
                                         for key in ('pull_probe_tx', 'pulled_data_rx', 'pull_replies_rx', 'payload_frame_rx', 'retransmits')}
                                delta.update(pull_probe_pps=round(delta['pull_probe_tx']/elapsed, 3),
                                             pull_budget_pps=final.get('pull_budget_pps'),
                                             fast_healthy=final.get('fast_healthy'),
                                             compat_active=final.get('compat_active'))
                                feedback.append(delta)
                            row.update(**result, feedback=feedback, processes_unchanged=
                                       [a['pid'] for a in before['peers']] == [b['pid'] for b in after['peers']])
                            row['internal_recoveries'] = [b.get('telemetry', {}).get('internal_recoveries', 0)-a.get('telemetry', {}).get('internal_recoveries', 0)
                                                          for a, b in zip(before['peers'], after['peers'])]
                            floor = (100 if rate == 200 else 200) if mode in ('clean', 'asymmetric', 'stateful') else 30
                            row['status'] = 'pass' if result['received_mbps'] >= floor and row['processes_unchanged'] and not any(row['internal_recoveries']) else 'fail'
                            if label == 'candidate' and mode == 'asymmetric' and feedback[0]['pull_probe_pps'] > 200:
                                row['status'] = 'fail'; row['reason'] = 'Unanswered PULL overhead exceeded 200pps average'
                            if label == 'candidate' and mode == 'stateful' and not any(x['pulled_data_rx'] > 0 for x in feedback):
                                row['status'] = 'fail'; row['reason'] = 'Stateful case did not exercise returned PULL DATA'
                    except Exception as exc:
                        row.update(status='fail', reason=str(exc))
                    rows.append(row); samples[label] = row
                    print(json.dumps(row), flush=True)
                    with (OUT / 'field-results.jsonl').open('a') as f: f.write(json.dumps(row)+'\n')
                    if label == 'candidate' and row['status'] != 'pass': failures.append(row)
                if mode in ('clean', 'stateful') and all('received_mbps' in samples[x] for x in ('rc1', 'candidate')):
                    if samples['candidate']['received_mbps'] < .65*samples['rc1']['received_mbps']:
                        failures.append(dict(case=mode, link_mbps=rate, reverse=reverse, reason='Clean A/B regression >35%'))
    (OUT / 'field-summary.json').write_text(json.dumps(dict(rows=rows, failures=failures), indent=2))
    if failures: raise RuntimeError(f'{len(failures)} candidate field checks failed; raw observations retained')


if __name__ == '__main__': main()
