"""Focused RC5 gates; retain baseline measurements, never publish a release."""
import hashlib
import json
import os
from pathlib import Path
import sys
import tarfile
import tempfile
import time

from cloud_extended import ARCH, BIN, OUT, SOURCE, Pair, run, stop


def record(row):
    row.update(architecture=ARCH,source_commit=run('git','-C',SOURCE,'rev-parse','HEAD').stdout.strip())
    row['runtime_source_commit']='5fa738b343000c6744a87fdae0c82a5967402f83' if row.get('version')=='rc4' else row['source_commit']
    print(json.dumps(row),flush=True)
    with (OUT/'rc5-focus-results.jsonl').open('a') as f:f.write(json.dumps(row)+'\n')


def lifecycle():
    for profile in ('tcp','udp','icmp','gre','ipip','dcpi'):
        row=dict(kind='rc5-lifecycle',profile=profile,status='fail')
        try:
            with Pair(profile,label='rc5-'+profile+'-') as pair:
                for i in range(2):
                    path=pair.path/f'{i}.json';cfg=json.loads(path.read_text())
                    cfg['transport'].update(wire_mode='opaque',opaque_session='challenge')
                    path.write_text(json.dumps(cfg))
                pair.shape(200,80,'0.15%');pair.restart()
                recoveries=[]
                for trial in range(10):
                    side=trial%2; other=1-side; old_other=pair.pid(other)
                    pair.stop_peer(side);pair.start_peer(side)
                    recoveries.append(pair.reachable(20))
                    if pair.pid(other)!=old_other:raise RuntimeError('Untouched peer unexpectedly restarted')
                speeds=[]
                for reverse in (False,True):
                    result=pair.finish_iperf(*pair.iperf('10.77.1.2',8,2,reverse,4),35)
                    speeds.append(result)
                    if result['received_mbps']<30:raise RuntimeError('Challenge carrier capacity below original opaque floor')
                udp_speeds=[]
                for reverse in (False,True):
                    result=pair.finish_iperf(*pair.iperf('10.77.1.2',6,2,reverse,1,udp=True),30)
                    udp_speeds.append(result)
                    if result['received_mbps']<15 or (result.get('lost_percent') or 0)>1:raise RuntimeError('Inner UDP throughput/loss gate failed')
                time.sleep(1.2);snapshot=pair.sample()
                for peer in snapshot['peers']:
                    stats=peer.get('telemetry',{})
                    if not stats.get('peer_authenticated') or stats.get('internal_recoveries',0):raise RuntimeError('Authentication or untouched lifecycle failed')
                    if stats.get('carrier',{}).get('session_mode')!='challenge':raise RuntimeError('Wrong negotiated mode')
                row.update(status='pass',restart_recovery_sec=recoveries,speeds=speeds,udp_speeds=udp_speeds,end_snapshot=snapshot)
        except Exception as exc:row['error']=str(exc)
        record(row)
        if row['status']!='pass':raise RuntimeError('RC5 lifecycle failed; retain evidence')


def transfer(pair,seconds,reverse):
    echo=pair.probe_server();probe=pair.probe(seconds+4)
    before=pair.sample()
    try:
        result=pair.finish_iperf(*pair.iperf('10.77.1.2',seconds,2,reverse,16,capture_receiver=True),seconds+35)
        progress=pair.finish_probe(probe,seconds+20)
        after=pair.sample()
        result.update(progress=progress,end_snapshot=after,same_processes=[p['pid'] for p in before['peers']]==[p['pid'] for p in after['peers']],
                      recoveries=[b.get('telemetry',{}).get('internal_recoveries',0)-a.get('telemetry',{}).get('internal_recoveries',0) for a,b in zip(before['peers'],after['peers'])])
        intervals=result.get('receiver_intervals_mbps',[])[1:-1]
        if len(intervals)>=8:
            n=len(intervals)//4
            result['first_quarter_mbps']=sum(intervals[:n])/n
            result['last_quarter_mbps']=sum(intervals[-n:])/n
        return result
    finally:stop(echo);stop(probe)


def loss():
    with tempfile.TemporaryDirectory() as temporary:
        root=Path(temporary);archive=root/'rc4.tar.gz'
        run('curl','-fL','--retry','3','https://github.com/MmdHoss3in/ggstunnel/releases/download/v0.3.4-rc4/ggstunnel-linux.tar.gz','-o',archive)
        if hashlib.sha256(archive.read_bytes()).hexdigest()!='962ebfa526fd5a36719619e63ac39ccdf555cc2845edc151e3651c752d2a4dcb':raise RuntimeError('RC4 baseline checksum mismatch')
        with tarfile.open(archive) as package:package.extractall(root,filter='data')
        baseline=root/'ggstunnel'/'dist'/('ggstunnel-linux-'+ARCH)
        baseline.chmod(0o755)
        for impairment,seconds,reverse in [('1%',30,False),('1%',30,True),('3%',30,False),('3%',30,True),('3%',120,False)]:
            old=None
            for label,executable in [('rc4',baseline),('candidate',BIN)]:
                row=dict(kind='rc5-loss-ab',version=label,loss=impairment,seconds=seconds,reverse=reverse,status='observed' if label=='rc4' else 'fail')
                try:
                    with Pair(label='rc5-loss-'+label+'-') as pair:
                        pair.executables=[executable,executable];pair.baseline_preserve_config=True
                        pair.shape(200,80,impairment);pair.restart();time.sleep(1.2)
                        row.update(transfer(pair,seconds,reverse))
                    if label=='rc4':old=row['received_mbps']
                    else:
                        row['baseline_mbps']=old
                        target=max(3 if impairment=='1%' else 2,.9*old)
                        row['required_mbps']=target
                        progress=row['progress']
                        if row['received_mbps']<target or not row['same_processes'] or any(row['recoveries']) or progress['verified_frames']<10 or progress['max_gap_sec']>5:raise RuntimeError('Original progress/nonregression gate failed')
                        row['status']='pass'
                except Exception as exc:row.update(status='fail',error=str(exc))
                record(row)
                if row['status']=='fail':raise RuntimeError('RC5 loss A/B failed; preserve source and results')


if __name__=='__main__':
    if os.geteuid()!=0 or os.environ.get('GITHUB_ACTIONS')!='true':raise RuntimeError('Disposable privileged cloud runner required')
    OUT.mkdir(exist_ok=True)
    for key in ('net.core.rmem_max','net.core.wmem_max'):
        run('sysctl','-qw',f'{key}={max(int(run("sysctl","-n",key).stdout),16<<20)}')
    {'lifecycle':lifecycle,'loss':loss}[sys.argv[1]]()
