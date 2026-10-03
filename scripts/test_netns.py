#!/usr/bin/env python3
"""Privileged integration test, only on a disposable Linux CI runner.

Two network namespaces exercise the built binary, real TUN, raw ICMP, AES-GCM,
and the kernel TCP stack. Results are synthetic, never a claim about WAN speed.
"""
import json
import os
from pathlib import Path
import secrets
import subprocess
import tempfile
import time

ROOT=Path(__file__).resolve().parents[1]

def run(*args, **kw):
    return subprocess.run(list(map(str,args)),check=True,text=True,capture_output=True,**kw)

def main():
    if os.geteuid()!=0: raise RuntimeError('Requires root on a disposable Linux runner')
    profile=os.environ.get('GGS_TEST_PROFILE','bip')
    if profile not in ('bip','tcp','udp','icmp','gre'):raise ValueError('Unknown test profile')
    names=['ggs-ci-a','ggs-ci-b']
    processes=[]
    created=[]
    with tempfile.TemporaryDirectory() as tmp:
        tmp=Path(tmp); logs=[]
        try:
            for n in names: run('ip','netns','add',n); created.append(n)
            run('ip','link','add','ggs-ci-va','type','veth','peer','name','ggs-ci-vb')
            for i,n in enumerate(names):
                dev=('ggs-ci-va','ggs-ci-vb')[i]
                run('ip','link','set',dev,'netns',n)
                run('ip','-n',n,'addr','add',f'192.0.2.{i+1}/24','dev',dev)
                run('ip','-n',n,'link','set',dev,'up')
                run('ip','-n',n,'link','set','lo','up')
                run('ip','netns','exec',n,'tc','qdisc','add','dev',dev,'root','netem','delay','40ms','rate','100mbit')
            key=secrets.token_hex(32)
            for i,n in enumerate(names):
                cfg=json.loads((ROOT/'examples'/('server.json' if i==0 else 'client.json')).read_text())
                cfg['psk']=key
                cfg['profile']=profile
                cfg['tuner']['mode']='adaptive' if profile=='bip' else 'manual'
                cfg['real']['local_ip']=f'192.0.2.{i+1}'
                cfg['real']['peer_ip']=f'192.0.2.{2-i}'
                cfg['real']['listen_addr']=f'192.0.2.{i+1}:24443'
                cfg['real']['peer_addr']=f'192.0.2.{2-i}:24443'
                cfg['tun']['name']='ggsci0'
                cfg['tun']['local_addr']=f'10.77.1.{i+1}'
                cfg['tun']['remote_addr']=f'10.77.1.{2-i}'
                path=tmp/f'{i}.json';path.write_text(json.dumps(cfg));path.chmod(0o600)
                log=(tmp/f'{i}.log').open('w+');logs.append(log)
                processes.append(subprocess.Popen(['ip','netns','exec',n,str(ROOT/'dist/ggstunnel-linux-amd64'),'-c',str(path)],stdout=log,stderr=log))
            for attempt in range(20):
                try:
                    run('ip','netns','exec',names[0],'ping','-c','1','-W','1','10.77.1.2',timeout=3)
                    break
                except subprocess.SubprocessError:
                    time.sleep(.2)
            else: raise RuntimeError('Encrypted TUN never became reachable')
            results=[]
            for loss in (('0%','0.2%') if profile=='bip' else ('0%',)):
                for i,n in enumerate(names):
                    dev=('ggs-ci-va','ggs-ci-vb')[i]
                    run('ip','netns','exec',n,'tc','qdisc','change','dev',dev,'root','netem','delay','40ms','loss',loss,'rate','100mbit')
                for reverse in (False,True):
                    server=subprocess.Popen(['ip','netns','exec',names[1],'iperf3','-s','-1'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
                    processes.append(server);time.sleep(.25)
                    args=['ip','netns','exec',names[0],'iperf3','-c','10.77.1.2','-t','8','-P','4','-J']
                    if reverse:args.append('-R')
                    data=json.loads(run(*args,timeout=40).stdout)
                    if 'error' in data:raise RuntimeError(data['error'])
                    rate=data['end']['sum_received']['bits_per_second']/1e6
                    row={'profile':profile,'loss':loss,'reverse':reverse,'received_mbps':round(rate,3)}
                    print(json.dumps(row),flush=True);results.append(row)
                    if os.environ.get('GGS_RESULTS'):
                        with Path(os.environ['GGS_RESULTS']).open('a') as report:
                            report.write(json.dumps(row)+'\n')
                    floor=10 if loss=='0%' else 1
                    if rate<floor:raise RuntimeError(f'Real TUN throughput collapsed below {floor} Mbps')
                    server.wait(timeout=5)
            print(f'PASS: {profile}, real encrypted TUN, both directions, 80ms base RTT, 100Mbps netem link')
        finally:
            for p in processes:
                if p.poll() is None:p.terminate()
            for p in processes:
                try:p.wait(timeout=5)
                except subprocess.TimeoutExpired:p.kill();p.wait()
            for log in logs:
                log.seek(0);print(log.read()[-16000:]);log.close()
            for n in reversed(created):run('ip','netns','del',n)

if __name__=='__main__':main()
