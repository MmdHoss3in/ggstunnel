#!/usr/bin/env python3
"""Short real TUN regressions, shaped on a router outside sender TCP TSQ."""
import json
import os
from pathlib import Path
import time
from cloud_extended import Pair, OUT, run, stop

def record(destination, row):
    print(json.dumps(row),flush=True)
    if destination:
        with Path(destination).open('a') as f:f.write(json.dumps(row)+'\n')

def main():
    if os.geteuid()!=0 or os.environ.get('GITHUB_ACTIONS')!='true':
        raise RuntimeError('Requires root on a disposable GitHub Actions runner')
    profile=os.environ.get('GGS_TEST_PROFILE','bip')
    if profile not in ('bip','tcp','udp','icmp','gre'):raise ValueError('Unknown profile')
    OUT.mkdir(exist_ok=True)
    with Pair(profile) as pair:
        for loss in (('0%','0.2%','1%') if profile=='bip' else ('0%',)):
            pair.shape(100,80,loss)
            for reverse in (False,True):
                pair.restart()
                result=pair.finish_iperf(*pair.iperf('10.77.1.2',8,2,reverse),40)
                row=dict(profile=profile,loss=loss,reverse=reverse,sample_sec=8,warmup_sec=2,
                         base_rtt_ms=80,link_mbps=100,fresh_session=True,**result)
                floor=30 if loss=='0%' else 1
                row['status']='pass' if result['received_mbps']>=floor else 'fail'
                record(os.environ.get('GGS_RESULTS'),row)
                if row['status']!='pass':raise RuntimeError('Real TUN throughput collapsed: '+json.dumps(row))
        if profile=='bip':
            def recovery(case,**values):record(os.environ.get('GGS_RECOVERY_RESULTS'),dict(profile=profile,case=case,status='pass',**values))
            pair.shape();pair.restart();echo=pair.probe_server();probe=pair.probe(14)
            server,bulk=pair.iperf('10.77.1.2',14,0)
            time.sleep(2);pair.shape(loss='100%');time.sleep(3);pair.shape()
            restored=time.monotonic();ping=pair.reachable(15)
            data=pair.finish_probe(probe,40);result=pair.finish_iperf(server,bulk,30)
            resumed=[t-restored for t in data['completions'] if t>=restored]
            if not resumed or min(resumed)>15 or result['received_mbps']<1:raise RuntimeError('Existing TCP flow failed to recover')
            recovery('three_second_blackhole',recovery_sec=ping,flow_recovery_sec=round(min(resumed),3),verified_frames=data['verified_frames'],**result)
            stop(echo);pair.stop_peer(1);pair.start_peer(1);recovery('peer_restart',recovery_sec=pair.reachable(20))
            for i in range(2):
                pair.stop_peer(i)
                run('ip','-n',pair.names[i],'link','set',pair.devs[i],'mtu','1200')
                run('ip','-n',pair.router,'link','set',pair.router_devs[i],'mtu','1200')
                path=pair.path/f'{i}.json';cfg=json.loads(path.read_text())
                cfg['tun']['mtu']=1040;cfg['performance']['max_frame_payload']=1040;path.write_text(json.dumps(cfg))
            pair.restart()
            run('ip','netns','exec',pair.names[0],'ping','-c','3','-W','2','-M','do','-s','1012','10.77.1.2',timeout=10)
            recovery('outer_mtu_1200',tun_mtu=1040,payload_bytes=1012)
    print('PASS: real encrypted TUN, both directions, routed 80ms RTT / 100Mbps')

if __name__=='__main__':main()
