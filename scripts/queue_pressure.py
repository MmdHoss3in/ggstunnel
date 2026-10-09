"""Fixed cloud-only A/B gates for four-stream bursts and overloaded UDP fairness."""
import hashlib
import json
import os
from pathlib import Path
import re
import tarfile
import tempfile
import time

from cloud_extended import ARCH, BIN, OUT, SOURCE, Pair, percentile, run, stop
from queue_pressure_report import summary

BASELINE_SOURCE = 'ac5f73d013b51a574335e5e4bd301e73505d01d6'
BASELINE_SHA = 'bfd796fc81abd294ba43b653fe0a5bbd8776cddaba926219b0678c79c78e73b8'
CASES = ((200, '0.15%'), (500, '0%'))
SOURCE_COMMIT = None


def record(row):
    row.update(architecture=ARCH, source_commit=SOURCE_COMMIT)
    row['runtime_source_commit'] = BASELINE_SOURCE if row.get('version') == 'v0.3.4' else SOURCE_COMMIT
    print(json.dumps(row), flush=True)
    with (OUT / 'queue-pressure-results.jsonl').open('a') as f:
        f.write(json.dumps(row) + '\n')


def measure(pair, seconds=30, overload=False, reverse=False):
    echo = pair.probe_server()
    probe = pair.probe(seconds + 8)
    ping = pair.child(0, ['ping', '-n', '-i', '.2', '-c', str((seconds+5)*5), '-W', '2', '10.77.1.2'])
    before = pair.sample()
    done, thread, samples = pair.watch()
    try:
        if overload:
            server = pair.child(1, ['iperf3', '-s', '-1'], False)
            time.sleep(.2)
            client = pair.child(0, ['iperf3', '-c', '10.77.1.2', '-u', '-b', '160M', '-l', '1000', '-t', str(seconds), '-J'])
            result = pair.finish_iperf(server, client, seconds+25)
        else:
            result = pair.finish_iperf(*pair.iperf('10.77.1.2', seconds, 5, reverse, 4, capture_receiver=True), seconds+40)
        progress = pair.finish_probe(probe, seconds+20)
        ping_out, ping_err = ping.communicate(timeout=10)
        (OUT / ('queue-ping-'+str(time.time_ns())+'.txt')).write_text(ping_out+ping_err)
        rtts = [float(x) for x in re.findall(r'time=([0-9.]+) ms', ping_out)]
        if len(rtts) < (seconds+5)*4: raise RuntimeError('Too few successful latency probes')
        # Wait for a telemetry tick to include the completed bulk transfer.
        time.sleep(1.1)
        after = pair.sample()
        observed = [*samples, after]
        stats = [p.get('telemetry', {}) for p in after['peers']]
        ingress, drops, repairs = [], [], []
        for a, b in zip(before['peers'], after['peers']):
            old, new = a.get('telemetry', {}), b.get('telemetry', {})
            d = new['tun_queue_drops'] - old['tun_queue_drops']
            n = new.get('tun_ingress_packets', new['tx_read_packets']+new['tun_queue_drops']) - old.get('tun_ingress_packets', old['tx_read_packets']+old['tun_queue_drops'])
            ingress.append(n); drops.append(d)
            repairs.append(new['carrier']['retransmits']-old['carrier']['retransmits'])
        elapsed = after['monotonic']-before['monotonic']
        result.update(progress=progress, before=before, after=after,
            same_processes=[p['pid'] for p in before['peers']]==[p['pid'] for p in after['peers']],
            recoveries=[b['telemetry']['internal_recoveries']-a['telemetry']['internal_recoveries'] for a,b in zip(before['peers'],after['peers'])],
            ping_p95_ms=percentile(rtts, .95), ingress_packets=ingress, queue_drops=drops,
            drop_fraction=sum(drops)/max(1, sum(ingress)), carrier_retransmits=repairs,
            max_rss_mib=max(p.get('rss_mib', 0) for s in observed for p in s['peers']),
            cpu_cores=sum(b['cpu_sec']-a['cpu_sec'] for a,b in zip(before['peers'],after['peers']))/elapsed,
            peak_queue_bytes=max(s.get('queue_peak_bytes', 0) for s in stats),
            peak_flow_packets=max(s.get('queue_peak_flow_packets', 0) for s in stats),
            burst_admissions=sum(s.get('queue_burst_admissions', 0) for s in stats),
            max_queue_sojourn_ms=max(s.get('queue_max_sojourn_ms', 0) for s in stats))
        return result
    finally:
        done.set(); thread.join()
        (OUT / ('queue-samples-'+str(time.time_ns())+'.json')).write_text(json.dumps(samples))
        stop(echo); stop(probe); stop(ping)


def measurement_gate(result):
    progress=result['progress']
    if not result['same_processes'] or any(result['recoveries']) or progress['verified_frames']<30 or progress['max_gap_sec']>3:
        raise RuntimeError('Process or established sparse-flow integrity/progress gate failed')
    if result['max_rss_mib']>96 or result['peak_queue_bytes']>8<<20 or result['peak_flow_packets']>512:
        raise RuntimeError('Frozen resource bounds exceeded')


def main():
    global SOURCE_COMMIT
    if os.geteuid()!=0 or os.environ.get('GITHUB_ACTIONS')!='true': raise RuntimeError('Disposable cloud runner required')
    SOURCE_COMMIT=run('git','-C',SOURCE,'rev-parse','HEAD').stdout.strip()
    OUT.mkdir(exist_ok=True)
    for k in ('net.core.rmem_max','net.core.wmem_max'): run('sysctl','-qw',f'{k}={max(int(run("sysctl","-n",k).stdout),16<<20)}')
    failures=0
    with tempfile.TemporaryDirectory() as temporary:
        root=Path(temporary); archive=root/'stable.tar.gz'
        run('curl','-fL','--retry','3','https://github.com/MmdHoss3in/ggstunnel/releases/download/v0.3.4/ggstunnel-linux.tar.gz','-o',archive)
        if hashlib.sha256(archive.read_bytes()).hexdigest()!=BASELINE_SHA: raise RuntimeError('Immutable stable baseline checksum mismatch')
        with tarfile.open(archive) as package: package.extractall(root,filter='data')
        baseline=root/'ggstunnel/dist'/('ggstunnel-linux-'+ARCH); baseline.chmod(0o755)
        for rate,loss in CASES:
            for reverse in (False,True):
                observations=[]
                for trial in range(3):
                    for version in (('v0.3.4','candidate') if trial%2==0 else ('candidate','v0.3.4')):
                        row=dict(kind='queue-pressure',rate=rate,loss=loss,reverse=reverse,trial=trial,version=version,status='fail')
                        try:
                            with Pair(label=f'queue-{rate}-{reverse}-{trial}-{version}-') as pair:
                                pair.executables=[baseline if version=='v0.3.4' else BIN]*2
                                pair.baseline_preserve_config=True; pair.shape(rate,80,loss); pair.restart()
                                row.update(measure(pair,reverse=reverse))
                            measurement_gate(row)
                            if row['received_mbps']<(100 if rate==200 else 300): raise RuntimeError('Capacity floor failed')
                            row['status']='pass'
                        except Exception as exc: row['error']=str(exc); failures+=1
                        observations.append(row); record(row)
                aggregate=dict(kind='queue-pressure-summary',rate=rate,loss=loss,reverse=reverse,status='fail')
                try: aggregate.update(summary(observations)); aggregate['status']='pass'
                except Exception as exc: aggregate['error']=str(exc); failures+=1
                record(aggregate)
        row=dict(kind='queue-overload',status='fail')
        try:
            with Pair(label='queue-overload-') as pair:
                pair.shape(50,80,'0%'); pair.restart(); row.update(measure(pair,overload=True))
            measurement_gate(row)
            if sum(row['queue_drops'])==0 or row['burst_admissions']==0: raise RuntimeError('Queue pressure/burst was not exercised')
            if row['ping_p95_ms']>250: raise RuntimeError('Overload starved latency-sensitive traffic')
            row['status']='pass'
        except Exception as exc: row['error']=str(exc); failures+=1
        record(row)
    if failures: raise RuntimeError(f'{failures} fixed queue-pressure gates failed; no automatic retries')


if __name__=='__main__': main()
