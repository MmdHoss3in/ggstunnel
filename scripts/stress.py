#!/usr/bin/env python3
"""Field stability/capacity tests. Does not change tunnel or network settings."""
import argparse
import datetime
import json
import os
from pathlib import Path
import subprocess
import threading
import time
import zipfile


def run(args, timeout):
    try:
        p = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
        return p.returncode, p.stdout + p.stderr
    except subprocess.TimeoutExpired as e:
        return 124, (e.stdout or b'').decode() if isinstance(e.stdout, bytes) else (e.stdout or '')


def evaluate(code, data, target):
    end = data.get('end', {})
    received = end.get('sum_received', {})
    speed = received.get('bits_per_second', 0)
    loss = received.get('lost_percent', 0)
    ok = code == 0 and not data.get('error') and speed >= target * .8 and loss <= 1
    return dict(passed=ok, received_mbps=speed/1e6, lost_percent=loss,
                jitter_ms=received.get('jitter_ms'), error=data.get('error'), exit_code=code)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('mode', choices=['client', 'monitor'])
    ap.add_argument('--source', default='/root/ggstunnel-develop/source')
    ap.add_argument('--port', type=int, default=5207)
    ap.add_argument('--diagnostic', action='store_true')
    args = ap.parse_args()
    os.umask(0o077)
    base = Path(args.source).resolve()
    state = base/'develop-state'
    cfg = json.loads((state/'config.json').read_text())
    stamp = datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%SZ')
    out = state/'reports'/('stage5-'+args.mode+'-'+stamp)
    out.mkdir(parents=True)
    stop = threading.Event()

    def monitor():
        with (out/'telemetry.jsonl').open('w') as f:
            while not stop.is_set():
                try:
                    value = json.loads((state/'stats.json').read_text())
                    f.write(json.dumps({'collected_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(), 'stats': value})+'\n')
                    f.flush()
                except (OSError, ValueError):
                    pass
                stop.wait(1)

    thread = threading.Thread(target=monitor)
    thread.start()
    results = []
    try:
        if args.mode == 'monitor':
            print('Monitoring. Run client tests on the peer; then press Ctrl+C here.', flush=True)
            while True:
                time.sleep(1)
        else:
            if cfg['role'] != 'client':
                raise RuntimeError('Run client mode only on the foreign/client host')
            code, route = run(['ip', '-j', 'route', 'get', cfg['tun']['remote_addr']], 5)
            if code or json.loads(route)[0].get('dev') != cfg['tun']['name']:
                raise RuntimeError('Peer route must use configured TUN')
            common = ['iperf3', '-c', cfg['tun']['remote_addr'], '-B', cfg['tun']['local_addr'], '-p', str(args.port), '--connect-timeout', '3000', '-J']
            plan = [(2, 'TCP', 120), (2, 'UDP', 30)]
            plan += [(rate, proto, 15) for rate in (5, 10, 20) for proto in ('TCP', 'UDP')]
            if args.diagnostic:
                plan = [(rate, proto, 20) for rate in (2, 5) for proto in ('TCP', 'UDP')]
            for rate, proto, duration in plan:
                healthy = True
                for reverse in (False, True):
                    label = f'{proto}-{rate}M-'+('Iran-to-foreign' if reverse else 'foreign-to-Iran')
                    extra = ['-b', f'{rate}M', '-t', str(duration)]
                    if proto == 'UDP':
                        extra += ['-u', '-l', '1000']
                    if reverse:
                        extra += ['-R']
                    print('Running '+label, flush=True)
                    for attempt in range(2):
                        code, raw = run(common+extra, duration+20)
                        (out/(label+f'-attempt{attempt+1}.json')).write_text(raw)
                        try:
                            data = json.loads(raw)
                        except ValueError:
                            data = {'error': 'invalid/incomplete iperf output'}
                        # One retry only for a refused control connection, before data starts.
                        if attempt == 0 and 'Connection refused' in data.get('error', '') and not data.get('start', {}).get('connected'):
                            time.sleep(2)
                            continue
                        break
                    result = dict(label=label, duration_sec=duration, target_mbps=rate, **evaluate(code, data, rate*1e6))
                    results.append(result)
                    print(json.dumps(result), flush=True)
                    healthy &= result['passed']
                    time.sleep(2)
                if not healthy and not args.diagnostic:
                    print('Stopping load escalation: a measurement failed. See raw results.', flush=True)
                    break
    except KeyboardInterrupt:
        print('Stopped by operator.', flush=True)
    finally:
        stop.set()
        thread.join()
        # Diagnostic run ends by stopping the owned test processes and draining
        # the trace writer before the archive is built.
        if args.diagnostic:
            run(['bash', str(base/'setup.sh'), 'develop', 'stop'], 15)
        (out/'summary.json').write_text(json.dumps(results, indent=2)+'\n')
        # No configuration or shared key is included.
        for name in ('tunnel.log', 'iperf.log', 'bip-trace.jsonl'):
            p = state/name
            if p.exists():
                with p.open('rb') as f:
                    f.seek(0 if name == 'bip-trace.jsonl' else max(0, p.stat().st_size-2_000_000))
                    (out/name).write_bytes(f.read())
        archive = out.with_suffix('.zip')
        with zipfile.ZipFile(archive, 'w', zipfile.ZIP_DEFLATED) as z:
            for p in sorted(out.iterdir()):
                z.write(p, p.name)
        print('REPORT='+str(archive), flush=True)


if __name__ == '__main__':
    main()
