"""Extended short validation of the exact rc4 binary on disposable Linux CI."""
import argparse
import json
import math
import os
from pathlib import Path
import platform
import random
import re
import select
import statistics
import subprocess
import tempfile
import threading
import time

ROOT = Path(__file__).resolve().parents[1]
SOURCE = Path(os.environ.get('GGS_SOURCE', ROOT / 'release-source' if (ROOT / 'release-source').exists() else ROOT))
ARCH = {'x86_64': 'amd64', 'aarch64': 'arm64'}[platform.machine()]
BIN = SOURCE / 'dist' / ('ggstunnel-linux-' + ARCH)
OUT = ROOT / 'extended-results'


def run(*args, check=True, timeout=30):
    p = subprocess.run(list(map(str, args)), capture_output=True, text=True, timeout=timeout)
    if check and p.returncode:
        raise RuntimeError(' '.join(map(str, args[:5])) + ': ' + p.stderr + p.stdout)
    return p


def stop(p):
    if p and p.poll() is None:
        p.terminate()
        try:
            p.wait(timeout=5)
        except subprocess.TimeoutExpired:
            p.kill(); p.wait()


def record(row):
    row.update(binary_version=run(BIN, '-version').stdout.strip(), architecture=ARCH)
    print(json.dumps(row), flush=True)
    with (OUT / 'results.jsonl').open('a') as f:
        f.write(json.dumps(row) + '\n')


def percentile(values, fraction):
    if not values:
        return None
    a = sorted(values); position = (len(a) - 1) * fraction
    low = int(position); high = min(low + 1, len(a) - 1)
    return round(a[low] + (a[high] - a[low]) * (position - low), 3)


class Pair:
    def __init__(self, profile='bip', supervised=False):
        self.profile = profile; self.supervised = supervised
        self.names = ['gx-a', 'gx-b']; self.devs = ['gx-va', 'gx-vb']
        self.router = 'gx-r'; self.router_devs = ['gx-ra', 'gx-rb']
        self.outer = ['192.0.2.1', '198.51.100.1']
        self.p = [None, None]; self.units = ['ggs-cloud-a', 'ggs-cloud-b']
        self.children = []; self.created = []; self.logs = []
        self.tmp = tempfile.TemporaryDirectory(); self.path = Path(self.tmp.name)
        self.rate = 200; self.rtt = 80; self.monitor_data = []

    def __enter__(self):
        try:
            for name in [*self.names, self.router]:
                run('ip', 'netns', 'add', name); self.created.append(name)
            run('ip', 'netns', 'exec', self.router, 'sysctl', '-qw', 'net.ipv4.ip_forward=1')
            key = os.urandom(32).hex()
            for i, name in enumerate(self.names):
                gateway = '192.0.2.254' if i == 0 else '198.51.100.254'
                run('ip', 'link', 'add', self.devs[i], 'type', 'veth', 'peer', 'name', self.router_devs[i])
                run('ip', 'link', 'set', self.devs[i], 'netns', name)
                run('ip', 'link', 'set', self.router_devs[i], 'netns', self.router)
                run('ip', '-n', name, 'addr', 'add', self.outer[i] + '/24', 'dev', self.devs[i])
                run('ip', '-n', self.router, 'addr', 'add', gateway + '/24', 'dev', self.router_devs[i])
                run('ip', '-n', name, 'link', 'set', self.devs[i], 'up')
                run('ip', '-n', self.router, 'link', 'set', self.router_devs[i], 'up')
                run('ip', '-n', name, 'route', 'add', 'default', 'via', gateway)
                run('ip', 'netns', 'exec', name, 'ethtool', '-K', self.devs[i], 'tso', 'off', 'gso', 'off', 'gro', 'off')
                run('ip', 'netns', 'exec', self.router, 'ethtool', '-K', self.router_devs[i], 'tso', 'off', 'gso', 'off', 'gro', 'off')
                run('ip', '-n', name, 'link', 'set', 'lo', 'up')
                cfg = json.loads((SOURCE / 'examples' / ('server.json' if i == 0 else 'client.json')).read_text())
                cfg['profile'] = profile = self.profile; cfg['psk'] = key
                cfg['tuner']['mode'] = 'adaptive' if profile == 'bip' else 'manual'
                cfg['real'].update(local_ip=self.outer[i], peer_ip=self.outer[1-i],
                                   listen_addr=self.outer[i] + ':24443', peer_addr=self.outer[1-i] + ':24443')
                cfg['tun'].update(name='gx0', local_addr=f'10.77.1.{i+1}', remote_addr=f'10.77.1.{2-i}')
                cfg['telemetry'].update(interval_sec=1, stats_file=str(self.path / f'stats-{i}.json'))
                (self.path / f'{i}.json').write_text(json.dumps(cfg)); (self.path / f'{i}.json').chmod(0o600)
                self.logs.append((OUT / f'tunnel-{i}.log').open('a'))
            self.shape()
            return self
        except BaseException:
            self.__exit__(None, None, None); raise

    def shape(self, rate=None, rtt=None, loss='0%', extra=(), asymmetric=False):
        if rate is not None: self.rate = rate
        if rtt is not None: self.rtt = rtt
        self.queue_limit = max(256, min(20000, math.ceil(self.rate * 1e6 * self.rtt / 1000 / 8 / 1400)))
        for i, name in enumerate(self.names):
            applied = '3%' if asymmetric and i == 1 else loss
            # Router egress is the receiver's incoming path, outside sender TSQ.
            run('ip', 'netns', 'exec', self.router, 'tc', 'qdisc', 'replace', 'dev', self.router_devs[1-i], 'root',
                'netem', 'limit', str(self.queue_limit), 'delay', f'{self.rtt / 2:g}ms', 'loss', applied,
                'rate', f'{self.rate}mbit', *extra)

    def pid(self, i):
        if self.supervised:
            value = run('systemctl', 'show', self.units[i], '-p', 'MainPID', '--value', check=False).stdout.strip()
            return int(value) if value.isdigit() and int(value) else None
        return self.p[i].pid if self.p[i] and self.p[i].poll() is None else None

    def start_peer(self, i):
        if self.supervised:
            run('systemd-run', '--quiet', '--unit=' + self.units[i], '--property=Restart=on-failure',
                '--property=RestartSec=3', '/usr/bin/ip', 'netns', 'exec', self.names[i], BIN,
                '-c', self.path / f'{i}.json')
        else:
            self.p[i] = subprocess.Popen(['ip', 'netns', 'exec', self.names[i], str(BIN),
                                          '-c', str(self.path / f'{i}.json')], stdout=self.logs[i], stderr=self.logs[i])

    def stop_peer(self, i):
        if self.supervised:
            run('systemctl', 'stop', self.units[i], check=False)
            run('systemctl', 'reset-failed', self.units[i], check=False)
        else: stop(self.p[i])

    def restart(self):
        for i in range(2): self.stop_peer(i)
        for i in range(2): self.start_peer(i)
        self.reachable(20)

    def reachable(self, limit=15):
        began = time.monotonic()
        while time.monotonic() - began < limit:
            if not self.supervised and any(self.pid(i) is None for i in range(2)):
                raise RuntimeError('Tunnel process exited')
            p = run('ip', 'netns', 'exec', self.names[0], 'ping', '-c', '1', '-W', '1', '10.77.1.2', check=False, timeout=3)
            if p.returncode == 0: return round(time.monotonic() - began, 3)
            time.sleep(.1)
        raise RuntimeError(f'TUN unreachable after {limit}s')

    def child(self, i, args, pipes=True):
        p = subprocess.Popen(['ip', 'netns', 'exec', self.names[i], *map(str, args)],
                             stdout=subprocess.PIPE if pipes else subprocess.DEVNULL,
                             stderr=subprocess.PIPE if pipes else subprocess.DEVNULL, text=True)
        self.children.append(p); return p

    def iperf(self, address, seconds=30, warmup=5, reverse=False, streams=4, udp=False):
        server = self.child(1, ['iperf3', '-s', '-1'], False); time.sleep(.2)
        args = ['iperf3', '-c', address, '-t', str(seconds), '-O', str(warmup), '-P', str(streams), '-J']
        if reverse: args += ['-R']
        if udp: args += ['-u', '-b', '20M', '-l', '256']
        return server, self.child(0, args)

    def finish_iperf(self, server, client, limit):
        stdout, stderr = client.communicate(timeout=limit)
        if client.returncode: raise RuntimeError('iperf failure: ' + stderr + stdout[:200])
        data = json.loads(stdout)
        if 'error' in data: raise RuntimeError(data['error'])
        result = data['end'].get('sum_received', data['end'].get('sum', {}))
        if 'bits_per_second' not in result: raise RuntimeError('Missing iperf receiver result')
        server.wait(timeout=5)
        return dict(received_mbps=round(result['bits_per_second'] / 1e6, 3),
                    lost_percent=result.get('lost_percent'), retransmits=data['end'].get('sum_sent', {}).get('retransmits'))

    def probe_server(self):
        # Bind wildcard so peer TUN restart does not destroy the echo listener.
        p = self.child(1, ['python3', ROOT / 'scripts/cloud_probe.py', 'server', '0.0.0.0', '0'])
        self.ready(p); return p

    def probe(self, seconds):
        p = self.child(0, ['python3', ROOT / 'scripts/cloud_probe.py', 'client', '10.77.1.2', str(seconds)])
        self.ready(p); return p

    @staticmethod
    def ready(p):
        if not select.select([p.stdout], [], [], 20)[0]: raise RuntimeError('Probe startup timed out')
        line = p.stdout.readline()
        if not line: raise RuntimeError('Probe startup failed: ' + p.stderr.read())
        json.loads(line)

    @staticmethod
    def finish_probe(p, limit=90):
        stdout, stderr = p.communicate(timeout=limit)
        if p.returncode: raise RuntimeError('Integrity probe failed: ' + stderr)
        return json.loads(stdout.strip().splitlines()[-1])

    def sample(self):
        peers = []
        for i in range(2):
            pid = self.pid(i); info = {'pid': pid}
            if pid:
                try:
                    proc = Path('/proc') / str(pid)
                    status = (proc / 'status').read_text()
                    info['rss_mib'] = int(re.search(r'VmRSS:\s+(\d+)', status)[1]) / 1024
                    info['fds'] = len(list((proc / 'fd').iterdir()))
                    info['threads'] = int(re.search(r'Threads:\s+(\d+)', status)[1])
                    stat = (proc / 'stat').read_text().rsplit(')', 1)[1].split()
                    info['cpu_sec'] = (int(stat[11]) + int(stat[12])) / os.sysconf('SC_CLK_TCK')
                    telemetry = self.path / f'stats-{i}.json'
                    if telemetry.exists(): info['telemetry'] = json.loads(telemetry.read_text())
                except (OSError, ValueError, TypeError, json.JSONDecodeError): info['sample_race'] = True
            peers.append(info)
        return {'monotonic': time.monotonic(), 'peers': peers}

    def watch(self):
        done = threading.Event(); samples = []
        def poll():
            while not done.is_set():
                samples.append(self.sample()); done.wait(1)
        thread = threading.Thread(target=poll); thread.start()
        return done, thread, samples

    def __exit__(self, *unused):
        for p in self.children: stop(p)
        for i in range(2): self.stop_peer(i)
        for f in self.logs: f.close()
        for name in reversed(self.created): run('ip', 'netns', 'del', name, check=False)
        self.tmp.cleanup()


def performance(profile):
    failures = 0
    with Pair(profile) as pair:
        for rate in (200, 300):
            for rtt in (20, 80, 200):
                pair.shape(rate, rtt)
                for reverse in (False, True):
                    base = pair.finish_iperf(*pair.iperf(pair.outer[1], 10, 2, reverse), 30)
                    record(dict(kind='baseline', profile=profile, rate_mbps=rate, rtt_ms=rtt, reverse=reverse, **base))
                    for repeat in range(3):
                        row = dict(kind='performance', profile=profile, rate_mbps=rate, rtt_ms=rtt,
                                   reverse=reverse, repeat=repeat, sample_sec=30, warmup_sec=5,
                                   baseline_mbps=base['received_mbps'])
                        done = thread = None; samples = []
                        try:
                            pair.restart(); done, thread, samples = pair.watch()
                            ping = pair.child(0, ['ping', '-n', '-i', '.2', '-W', '1', '-c', '180', '10.77.1.2'])
                            row.update(pair.finish_iperf(*pair.iperf('10.77.1.2', 30, 5, reverse), 65))
                            stop(ping); ping_stdout, _ = ping.communicate()
                            times = [float(x) for x in re.findall(r'time[=<]([0-9.]+)', ping_stdout)]
                            row.update(ping_p95_ms=percentile(times, .95), ping_p99_ms=percentile(times, .99),
                                       baseline_ratio=round(row['received_mbps'] / base['received_mbps'], 3))
                            target = 100 if profile == 'bip' and rate == 200 and rtt == 80 else 1
                            row['target_mbps'] = target; row['status'] = 'pass' if row['received_mbps'] >= target else 'target_miss'
                            if row['status'] != 'pass': failures += 1
                        except Exception as error:
                            failures += 1; row.update(status='fail', error=str(error))
                            for p in pair.children: stop(p)
                        finally:
                            if done: done.set(); thread.join()
                            with (OUT / f'performance-{rate}-{rtt}-{reverse}-{repeat}.json').open('w') as f:
                                json.dump(samples, f)
                            record(row)
    return failures


def recovery_trial(pair, trial, scenario='blackhole3', duration=60):
    row = dict(kind='recovery', trial=trial, scenario=scenario, profile='bip', duration_sec=duration,
               rate_mbps=200, rtt_ms=80, supervisor=pair.supervised)
    try:
        pair.shape(200, 80); pair.restart()
        echo = pair.probe_server(); probe = pair.probe(duration)
        server, bulk = pair.iperf('10.77.1.2', duration, 0)
        seed = 104729 + trial; rng = random.Random(seed)
        fault_at = rng.uniform(6, 12); row.update(seed=seed, inject_after_sec=round(fault_at, 3))
        time.sleep(fault_at)
        if scenario.startswith('blackhole'):
            seconds = int(scenario[len('blackhole'):])
            pair.shape(loss='100%'); time.sleep(seconds); pair.shape()
        elif scenario == 'peer_restart':
            pair.stop_peer(1); pair.start_peer(1)
        elif scenario == 'burst':
            for _ in range(4):
                pair.shape(loss='100%'); time.sleep(.25); pair.shape(); time.sleep(.75)
        elif scenario == 'reorder': pair.shape(extra=('reorder', '25%', '50%'))
        elif scenario == 'duplicate': pair.shape(extra=('duplicate', '1%'))
        elif scenario == 'asymmetric': pair.shape(loss='0.2%', asymmetric=True)
        elif scenario == 'policing': pair.shape(rate=5)
        else: pair.shape(loss=scenario)
        restored = time.monotonic(); row['ping_recovery_sec'] = pair.reachable(15)
        data = pair.finish_probe(probe, duration + 160)
        resumed = [t - restored for t in data['completions'] if t >= restored]
        if not resumed: raise RuntimeError('Established integrity flow did not resume after fault')
        row.update(flow_recovery_sec=round(min(resumed), 3), verified_frames=data['verified_frames'], max_gap_sec=round(data['max_gap_sec'], 3))
        post = [t for t in data['completions'] if t >= restored]
        row['post_fault_max_gap_sec'] = round(max((b-a for a,b in zip(post, post[1:])), default=0), 3)
        row.update(pair.finish_iperf(server, bulk, 30))
        if row['flow_recovery_sec'] > 15: raise RuntimeError('Existing TCP flow exceeded 15s recovery target')
        if len(post) < 3 or row['post_fault_max_gap_sec'] > 15: raise RuntimeError('Post-fault flow stalled or had insufficient verified progress')
        if row['received_mbps'] < 1: raise RuntimeError('Bulk transfer fell below connectivity floor')
        row['status'] = 'pass'
        stop(echo)
    except Exception as error:
        row.update(status='fail', error=str(error))
    finally:
        if pair.supervised:
            row['supervisor_restarts'] = [run('systemctl', 'show', unit, '-p', 'NRestarts', '--value', check=False).stdout.strip() for unit in pair.units]
        record(row)
        for p in pair.children: stop(p)
        pair.children = []
    return row['status'] != 'pass'


def recoveries(shard):
    with Pair() as pair:
        return sum(recovery_trial(pair, shard * 10 + i) for i in range(10))


def impairments():
    failures = 0
    with Pair(supervised=True) as pair:
        for i, scenario in enumerate(('0.2%', '1%', '3%', 'burst', 'reorder', 'duplicate', 'asymmetric',
                                      'policing', 'peer_restart', 'blackhole10', 'blackhole30', 'blackhole60')):
            duration = 120 if scenario == 'blackhole60' else 90 if scenario == 'blackhole30' else 45
            failures += recovery_trial(pair, 1000 + i, scenario, duration)
    return failures


def resources():
    failures = 0; samples = []
    with Pair() as pair:
        pair.restart(); echo = pair.probe_server(); probe = pair.probe(900)
        original = [pair.pid(i) for i in range(2)]
        done, thread, samples = pair.watch()
        try:
            for cycle in range(45):
                row = dict(kind='resource_cycle', cycle=cycle, profile='bip', architecture=ARCH)
                try:
                    row.update(pair.finish_iperf(*pair.iperf('10.77.1.2', 10, 0, bool(cycle % 2),
                                                           (1, 4, 16)[cycle % 3], cycle % 5 == 4), 30))
                    time.sleep(9)
                    if [pair.pid(i) for i in range(2)] != original: raise RuntimeError('Long-lived tunnel process changed/exited')
                    row.update(status='pass', idle_snapshot=pair.sample())
                except Exception as error:
                    failures += 1; row.update(status='fail', error=str(error))
                    for p in pair.children:
                        if p not in (echo, probe): stop(p)
                record(row)
            result = pair.finish_probe(probe, 180)
            record(dict(kind='resource_integrity', status='pass', verified_frames=result['verified_frames'],
                        duration_sec=900, same_processes=[pair.pid(i) for i in range(2)] == original))
            time.sleep(15)
        finally:
            done.set(); thread.join()
            (OUT / 'resource-samples.json').write_text(json.dumps(samples))
        for i in range(2):
            valid = [s['peers'][i] for s in samples if 'rss_mib' in s['peers'][i]]
            if valid:
                late = valid[-10:]; early = valid[60:70] if len(valid) > 70 else valid[:10]
                row = dict(kind='resource_summary', peer=i, samples=len(valid), max_rss_mib=max(s['rss_mib'] for s in valid),
                           early_rss_mib=statistics.median(s['rss_mib'] for s in early),
                           late_rss_mib=statistics.median(s['rss_mib'] for s in late),
                           early_fds=statistics.median(s['fds'] for s in early), late_fds=statistics.median(s['fds'] for s in late))
                row['status'] = 'pass' if row['max_rss_mib'] < 256 and row['late_fds'] <= row['early_fds'] + 8 else 'resource_limit'
                if row['status'] != 'pass': failures += 1
                record(row)
    return failures


def lifecycle():
    failures = 0
    with Pair() as pair:
        for cycle in range(30):
            row = dict(kind='lifecycle', cycle=cycle)
            try:
                pair.restart(); echo = pair.probe_server(); probe = pair.probe(1)
                data = pair.finish_probe(probe, 20); stop(echo)
                row.update(status='pass', verified_frames=data['verified_frames'], snapshot=pair.sample())
            except Exception as error: failures += 1; row.update(status='fail', error=str(error))
            finally:
                for p in pair.children: stop(p)
                pair.children = []; record(row)
    return failures


def main():
    if os.geteuid() != 0 or os.environ.get('GITHUB_ACTIONS') != 'true':
        raise RuntimeError('Only root on a disposable GitHub Actions runner')
    OUT.mkdir(exist_ok=True)
    parser = argparse.ArgumentParser(); parser.add_argument('mode', choices=('performance', 'recovery', 'impairments', 'resources', 'lifecycle'))
    parser.add_argument('--profile', default='bip'); parser.add_argument('--shard', type=int, default=0)
    args = parser.parse_args()
    (OUT / 'environment.json').write_text(json.dumps(dict(binary_sha256=run('sha256sum', BIN).stdout.split()[0],
        source_commit=run('git', '-C', SOURCE, 'rev-parse', 'HEAD').stdout.strip(), architecture=ARCH,
        cpus=len(os.sched_getaffinity(0)), kernel=platform.release(), mode=args.mode,
        topology='three namespaces, netem on routed receiver path, TSO/GSO/GRO disabled', queue_policy='one full RTT BDP, minimum 256 packets')))
    failures = {'performance': lambda: performance(args.profile), 'recovery': lambda: recoveries(args.shard),
                'impairments': impairments, 'resources': resources, 'lifecycle': lifecycle}[args.mode]()
    if failures: raise SystemExit(f'{failures} failed/target-missed cases; all recorded observations retained')


if __name__ == '__main__':
    main()
