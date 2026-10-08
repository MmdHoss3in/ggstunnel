"""Native candidate gates and retained, explicit controller A/B observations."""
import hashlib
import json
import os
import time
from cloud_extended import ARCH, BIN, OUT, SOURCE, Pair, run, stop


def main():
    if os.geteuid() != 0 or os.environ.get('GITHUB_ACTIONS') != 'true':
        raise RuntimeError('Requires disposable privileged GitHub runner')
    OUT.mkdir(exist_ok=True)
    for key in ('net.core.rmem_max', 'net.core.wmem_max'):
        run('sysctl', '-qw', f'{key}={max(int(run("sysctl", "-n", key).stdout), 16<<20)}')
    identity = dict(source_commit=run('git', '-C', SOURCE, 'rev-parse', 'HEAD').stdout.strip(),
                    binary_sha256=hashlib.sha256(BIN.read_bytes()).hexdigest(), architecture=ARCH)
    rows = []

    def record(row):
        row.update(identity, trial=len(rows)); rows.append(row)
        print(json.dumps(row), flush=True)
        with (OUT/'candidate-results.jsonl').open('a') as f: f.write(json.dumps(row)+'\n')

    def configure(pair, delivery, algorithm, wire):
        for i in range(2):
            path = pair.path/f'{i}.json'; cfg = json.loads(path.read_text())
            if pair.profile == 'bip':
                cfg['transport']['bip_delivery'] = delivery
                cfg['tuner']['algorithm'] = algorithm
            else: cfg['transport']['wire_mode'] = wire
            path.write_text(json.dumps(cfg))

    def transfer(pair, reverse):
        echo = pair.probe_server(); probe = pair.probe(12)
        before = pair.sample()
        try:
            result = pair.finish_iperf(*pair.iperf('10.77.1.2', 8, 2, reverse, 16), 35)
            progress = pair.finish_probe(probe, 20); after = pair.sample()
            result.update(verified_frames=progress['verified_frames'], max_gap_sec=progress['max_gap_sec'], end_snapshot=after,
                          same_processes=[p.get('pid') for p in before['peers']] == [p.get('pid') for p in after['peers']],
                          recoveries=[b.get('telemetry', {}).get('internal_recoveries', 0)-a.get('telemetry', {}).get('internal_recoveries', 0) for a, b in zip(before['peers'], after['peers'])])
            if not result['same_processes'] or any(result['recoveries']) or result['verified_frames'] < 10 or result['max_gap_sec'] > 5:
                raise RuntimeError('Continuity or verified useful progress failed')
            return result
        finally: stop(echo); stop(probe)

    cases = [(p, 'opaque', '0%', d) for p in ('tcp', 'udp', 'icmp', 'gre', 'ipip', 'dcpi') for d in (False, True)]
    cases += [('bip', recipe, loss, d) for recipe in ('ordered-loss', 'independent-loss', 'independent-delivery') for loss in ('0%', '1%', '3%') for d in (False, True)]
    observations = {}
    for profile, recipe, loss, reverse in cases:
        row = dict(kind='opaque' if profile != 'bip' else 'controller', profile=profile, recipe=recipe, loss=loss, reverse=reverse, status='fail')
        try:
            with Pair(profile, label=f'{profile}-{recipe}-{loss}-{int(reverse)}-') as pair:
                configure(pair, 'ordered' if recipe == 'ordered-loss' else 'independent', 'delivery' if recipe == 'independent-delivery' else 'loss', 'opaque')
                pair.shape(200, 80, loss); pair.restart(); time.sleep(1.2)
                row.update(transfer(pair, reverse))
                observations[(recipe, loss, reverse)] = row['received_mbps']
                if profile != 'bip': floor = 30
                elif recipe == 'independent-delivery': floor = {'0%': 100, '1%': 3, '3%': 2}[loss]
                else:
                    row['status'] = 'observed'; record(row); continue
                baseline = observations.get(('ordered-loss', loss, reverse)) if profile == 'bip' else None
                row.update(target_mbps=floor, ordered_loss_baseline_mbps=baseline)
                if row['received_mbps'] < floor or (baseline is not None and row['received_mbps'] < .9*baseline):
                    raise RuntimeError('Candidate capacity or A/B nonregression floor failed')
                row['status'] = 'pass'
        except Exception as error: row['error'] = str(error)
        record(row)

    for profile in ('bip', 'dcpi'):
        row = dict(kind='local-mtu', profile=profile, status='fail')
        try:
            with Pair(profile, label=f'mtu-{profile}-') as pair:
                for i in range(2):
                    run('ip', '-n', pair.names[i], 'link', 'set', pair.devs[i], 'mtu', '1200')
                    run('ip', '-n', pair.router, 'link', 'set', pair.router_devs[i], 'mtu', '1200')
                pair.restart()
                run('ip', 'netns', 'exec', pair.names[0], 'ping', '-c', '3', '-W', '2', '-M', 'do', '-s', '1252', '10.77.1.2', timeout=15)
                time.sleep(1.2); snapshot = pair.sample(); row['end_snapshot'] = snapshot
                limit = 1048 if profile == 'bip' else 1143
                for peer in snapshot['peers']:
                    stats = peer.get('telemetry', {})
                    if stats.get('local_underlay_mtu') != 1200 or not 256 <= stats.get('effective_frame_payload', 0) <= limit:
                        raise RuntimeError('Local underlay clamp missing')
                row['status'] = 'pass'
        except Exception as error: row['error'] = str(error)
        record(row)
    (OUT/'candidate-summary.json').write_text(json.dumps(rows, indent=2))
    if len(rows) != 32 or any(r['status'] not in ('pass', 'observed') for r in rows):
        raise RuntimeError('Candidate gates failed; retain all observations')


if __name__ == '__main__': main()
