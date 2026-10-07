"""Reproduce the captured directional ICMP loss on disposable native CI."""
import json
import os
import time

from cloud_extended import ARCH, OUT, Pair, run


def wait_fast(pair):
    deadline = time.monotonic() + 12
    while time.monotonic() < deadline:
        sample = pair.sample()
        if all(peer.get('telemetry', {}).get('carrier', {}).get('fast_healthy')
               for peer in sample['peers']):
            return sample
        if any(pair.pid(i) is None for i in range(2)):
            raise RuntimeError('Tunnel exited during directional discovery')
        time.sleep(.1)
    raise RuntimeError('Both directions did not establish authenticated FAST')


def cases():
    for wire in ('legacy', 'compact'):
        for blocked in (0, 1):
            for rate in (100, 200):
                for reverse in (False, True):
                    yield wire, blocked, rate, reverse, '0%', False
            for reverse in (False, True):
                yield wire, blocked, 100, reverse, '0%', True
        for loss in ('0.15%', '1%'):
            for reverse in (False, True):
                yield wire, 0, 200, reverse, loss, False


def main():
    if os.geteuid() != 0 or os.environ.get('GITHUB_ACTIONS') != 'true':
        raise RuntimeError('Disposable privileged GitHub Actions runner required')
    OUT.mkdir(exist_ok=True)
    for key in ('net.core.rmem_max', 'net.core.wmem_max'):
        current = int(run('sysctl', '-n', key).stdout.strip())
        run('sysctl', '-qw', f'{key}={max(current, 16 << 20)}')
    failures = []
    rows = []
    for index, (wire, blocked, rate, reverse, loss, udp) in enumerate(cases()):
        row = dict(case='captured-control-path', architecture=ARCH, wire=wire,
                   blocked_request_side=blocked, link_mbps=rate, reverse=reverse,
                   loss=loss, udp=udp, sample_sec=6, warmup_sec=2, trial=index)
        try:
            with Pair('bip', label=f'control-{index}-') as pair:
                for i in range(2):
                    path = pair.path / f'{i}.json'
                    cfg = json.loads(path.read_text())
                    cfg['transport']['bip_wire_mode'] = wire
                    path.write_text(json.dumps(cfg))
                router = ['ip', 'netns', 'exec', pair.router, 'iptables']
                run(*router, '-A', 'FORWARD', '-s', pair.outer[blocked],
                    '-p', 'icmp', '--icmp-type', 'echo-request', '-j', 'DROP')
                pair.shape(rate, 94, loss=loss)
                pair.restart()
                before = wait_fast(pair)
                result = pair.finish_iperf(
                    *pair.iperf('10.77.1.2', 6, 2, reverse, 1 if udp else 16, udp=udp), 35)
                time.sleep(1.1)
                after = pair.sample()
                recoveries = [b.get('telemetry', {}).get('internal_recoveries', 0)
                              - a.get('telemetry', {}).get('internal_recoveries', 0)
                              for a, b in zip(before['peers'], after['peers'])]
                same = [a['pid'] for a in before['peers']] == [b['pid'] for b in after['peers']]
                healthy = all(p.get('telemetry', {}).get('carrier', {}).get('fast_healthy')
                              for p in after['peers'])
                # Preserve the existing low-loss connectivity floor. Report
                # useful throughput separately; a 1Mbps pass is not capacity proof.
                floor = 15 if udp else (rate / 2 if loss == '0%' else 1)
                fallback = before['peers'][1-blocked]['telemetry']['carrier'].get('reply_control_rx', 0)
                row.update(result, end_snapshot=after, internal_recoveries=recoveries,
                           processes_unchanged=same, both_fast=healthy,
                           reply_control_rx=fallback, required_mbps=floor,
                           router_firewall=run(*router, '-L', 'FORWARD', '-nvx').stdout)
                row['status'] = 'pass' if (result['received_mbps'] >= floor and same
                                          and healthy and fallback > 0 and not any(recoveries)) else 'fail'
        except Exception as exc:
            row.update(status='fail', reason=str(exc))
        rows.append(row)
        print(json.dumps(row), flush=True)
        with (OUT / 'control-path-results.jsonl').open('a') as output:
            output.write(json.dumps(row) + '\n')
        if row['status'] != 'pass':
            failures.append(row)
    (OUT / 'control-path-summary.json').write_text(json.dumps(dict(rows=rows, failures=failures), indent=2))
    if failures:
        raise RuntimeError(f'{len(failures)} directional control checks failed')


if __name__ == '__main__':
    main()
