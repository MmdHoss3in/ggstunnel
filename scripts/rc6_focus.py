"""Frozen RC6 cloud gates; fixed repetitions/order, no retry-until-pass."""
import hashlib
import json
import math
import os
from pathlib import Path
import statistics
import sys
import tarfile
import tempfile
import time

from cloud_extended import ARCH, BIN, OUT, ROOT, SOURCE, Pair, run, stop
from rc5_focus import transfer

def record(row):
    row.update(architecture=ARCH,source_commit=run('git','-C',SOURCE,'rev-parse','HEAD').stdout.strip())
    print(json.dumps(row),flush=True)
    with (OUT/'rc6-results.jsonl').open('a') as f:f.write(json.dumps(row)+'\n')

def configure(pair,**transport):
    for side in range(2):
        path=pair.path/f'{side}.json';cfg=json.loads(path.read_text())
        if pair.profile!='bip':cfg['transport'].update(wire_mode='opaque',opaque_session='challenge')
        cfg['transport'].update(transport)
        path.write_text(json.dumps(cfg))

def device_identity(pair):
    result=[]
    for name in pair.names:
        link=json.loads(run('ip','-n',name,'-j','link','show','dev','gx0').stdout)[0]
        routes=json.loads(run('ip','-n',name,'-j','route','show').stdout)
        result.append(dict(ifindex=link['ifindex'],routes=routes))
    return result

def renewal():
    failures=0
    for profile in ('bip','tcp','udp','icmp','gre','ipip','dcpi'):
        row=dict(kind='renewal',profile=profile,status='fail')
        try:
            with Pair(profile,label='rc6-renew-'+profile+'-') as pair:
                configure(pair,session_max_age_sec=30)
                # One peer renews at 30/61s, the other at 45s. Preserve an
                # already-open TCP connection through a forwarding listener.
                path=pair.path/'1.json';cfg=json.loads(path.read_text());cfg['transport']['session_max_age_sec']=45;path.write_text(json.dumps(cfg))
                path=pair.path/'0.json';cfg=json.loads(path.read_text());cfg['forwards']=[dict(protocol='tcp',listen=pair.outer[0]+':25443',target='10.77.1.2:25443')];path.write_text(json.dumps(cfg))
                pair.shape(200,80,'0.15%');pair.restart()
                initial=device_identity(pair);pids=[pair.pid(i) for i in range(2)]
                echo=pair.probe_server()
                probe=pair.child(0,['python3',ROOT/'scripts/cloud_probe.py','client',pair.outer[0],'70'])
                pair.ready(probe)
                samples=[];began=time.monotonic()
                while time.monotonic()-began<70:
                    if device_identity(pair)!=initial:raise RuntimeError('Physical TUN or routes changed during renewal')
                    snapshot=pair.sample();samples.append(snapshot)
                    if [p['pid'] for p in snapshot['peers']]!=pids:raise RuntimeError('Process restarted')
                    time.sleep(.5)
                progress=pair.finish_probe(probe,40);stop(echo)
                end=pair.sample()
                renewals=[p.get('telemetry',{}).get('internal_recoveries',0) for p in end['peers']]
                if renewals[0]<2 or renewals[1]<1:raise RuntimeError('Accelerated renewal did not occur')
                if progress['verified_frames']<20 or progress['max_gap_sec']>15:raise RuntimeError('Established forwarded flow stalled or lost integrity')
                row.update(status='pass',renewals=renewals,progress=progress,end_snapshot=end)
                (OUT/('rc6-renew-'+profile+'-samples.json')).write_text(json.dumps(samples))
        except Exception as exc:row['error']=str(exc)
        record(row);failures+=row['status']!='pass'
    if failures:raise RuntimeError(f'{failures} renewal cases failed')

def wait_payload(pair,ceiling,exact=False,limit=60):
    began=time.monotonic()
    while time.monotonic()-began<limit:
        snapshot=pair.sample();stats=[p.get('telemetry',{}) for p in snapshot['peers']]
        if all(s.get('path_mtu_state')=='confirmed' and (s.get('effective_frame_payload')==ceiling if exact else 256<=s.get('effective_frame_payload',0)<=ceiling) for s in stats):return snapshot
        if any(pair.pid(i) is None for i in range(2)):raise RuntimeError('Path discovery exited process')
        time.sleep(.5)
    raise RuntimeError('Authenticated path ceiling not established: '+json.dumps(snapshot))

def size_filter(pair,maximum):
    run('ip','netns','exec',pair.router,'iptables','-F','FORWARD')
    if maximum:run('ip','netns','exec',pair.router,'iptables','-A','FORWARD','-m','length','--length',f'{maximum+1}:65535','-j','DROP')

def path_sizes():
    failures=0
    for profile,wire in [('bip','legacy'),('bip','compact'),('udp','opaque')]:
        row=dict(kind='path-mtu',profile=profile,wire=wire,status='fail')
        try:
            with Pair(profile,label='rc6-mtu-'+wire+'-') as pair:
                configure(pair,path_mtu=True)
                for side in range(2):
                    path=pair.path/f'{side}.json';cfg=json.loads(path.read_text());cfg['performance']['max_frame_payload']=1348
                    if wire=='compact':cfg['transport']['bip_wire_mode']='compact'
                    path.write_text(json.dumps(cfg))
                pair.shape(200,80,'0%')
                # Silent mid-path size drop: no ICMP PTB and local MTU 1500.
                size_filter(pair,1200);pair.restart();initial=device_identity(pair)
                ceiling=1048 if profile=='bip' else 1135
                row['initial_blackhole']=wait_payload(pair,ceiling)
                for reverse in (False,True):
                    result=pair.finish_iperf(*pair.iperf('10.77.1.2',8,2,reverse,4),35)
                    row.setdefault('blackhole_capacity',[]).append(result)
                    if result['received_mbps']<15:raise RuntimeError('MTU-reduced path capacity below 15Mbps')
                size_filter(pair,None)
                row['raised_path']=wait_payload(pair,1348,exact=True,limit=50)
                size_filter(pair,1000)
                row['reduced_path']=wait_payload(pair,848 if profile=='bip' else 935,limit=70)
                pair.reachable(15)
                if device_identity(pair)!=initial:raise RuntimeError('Path reduction recreated physical TUN/routes')
                row['status']='pass'
        except Exception as exc:row['error']=str(exc)
        record(row);failures+=row['status']!='pass'
    if failures:raise RuntimeError(f'{failures} path size cases failed')

def performance():
    failures=0
    with tempfile.TemporaryDirectory() as temporary:
        root=Path(temporary);archive=root/'rc5.tar.gz'
        run('curl','-fL','--retry','3','https://github.com/MmdHoss3in/ggstunnel/releases/download/v0.3.4-rc5/ggstunnel-linux.tar.gz','-o',archive)
        if hashlib.sha256(archive.read_bytes()).hexdigest()!='fd14bed5120c5d609bebd389d3999b5d132eeaa8430759bfc490ab898852da12':raise RuntimeError('Immutable RC5 baseline checksum mismatch')
        with tarfile.open(archive) as package:package.extractall(root,filter='data')
        baseline=root/'ggstunnel/dist'/('ggstunnel-linux-'+ARCH);baseline.chmod(0o755)
        for loss,rate in [('0%',200),('0%',500),('1%',200),('3%',200)]:
            for reverse in (False,True):
                values={'rc5':[],'candidate':[]};paired=[]
                for trial in range(3):
                    for version in (('rc5','candidate') if trial%2==0 else ('candidate','rc5')):
                        row=dict(kind='fixed-performance',loss=loss,rate=rate,reverse=reverse,trial=trial,version=version,status='fail')
                        try:
                            with Pair(label=f'rc6-perf-{loss}-{rate}-{reverse}-{trial}-{version}-') as pair:
                                exe=baseline if version=='rc5' else BIN
                                pair.executables=[exe,exe];pair.baseline_preserve_config=True
                                pair.shape(rate,80,loss);pair.restart();row['cold_start_sec']=pair.reachable(20)
                                row.update(transfer(pair,20,reverse))
                            floor=(150 if rate==200 else 300) if loss=='0%' else 30 if loss=='1%' else 15
                            if row['received_mbps']<floor or not row['same_processes'] or any(row['recoveries']) or row['progress']['verified_frames']<10 or row['progress']['max_gap_sec']>5:raise RuntimeError('Frozen capacity/integrity/process gate failed')
                            values[version].append(row['received_mbps']);row['status']='pass'
                        except Exception as exc:row['error']=str(exc);failures+=1
                        record(row)
                    if len(values['rc5'])==trial+1 and len(values['candidate'])==trial+1:paired.append(values['candidate'][-1]/values['rc5'][-1])
                aggregate=dict(kind='fixed-performance-summary',loss=loss,rate=rate,reverse=reverse,values=values,paired_ratios=paired,status='fail')
                if len(paired)==3:
                    aggregate['geometric_ratio']=math.exp(statistics.mean(math.log(x) for x in paired))
                    # Independent baseline replicates expose runner variance.
                    aggregate['baseline_cv']=statistics.stdev(values['rc5'])/statistics.mean(values['rc5'])
                    if aggregate['geometric_ratio']>=.90 and min(paired)>=.75 and aggregate['baseline_cv']<=.15:aggregate['status']='pass'
                if aggregate['status']!='pass':failures+=1
                record(aggregate)
    if failures:raise RuntimeError(f'{failures} fixed performance/variance gates failed; no automatic reruns')

if __name__=='__main__':
    if os.geteuid()!=0 or os.environ.get('GITHUB_ACTIONS')!='true':raise RuntimeError('Disposable cloud runner required')
    OUT.mkdir(exist_ok=True)
    for key in ('net.core.rmem_max','net.core.wmem_max'):run('sysctl','-qw',f'{key}={max(int(run("sysctl","-n",key).stdout),16<<20)}')
    {'renewal':renewal,'path':path_sizes,'performance':performance}[sys.argv[1]]()
