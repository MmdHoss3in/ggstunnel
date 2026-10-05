"""Short native TUN observations; no multiday statistical guarantee."""
import json, os, time
from cloud_extended import ARCH, OUT, Pair, run

def nic(pair,i):
    return int(run('ip','netns','exec',pair.names[i],'cat',f'/sys/class/net/{pair.devs[i]}/statistics/rx_bytes').stdout)

def main():
    if os.geteuid()!=0 or os.environ.get('GITHUB_ACTIONS')!='true': raise RuntimeError('Disposable privileged runner required')
    OUT.mkdir(exist_ok=True)
    for key in ('net.core.rmem_max','net.core.wmem_max'):
        run('sysctl','-qw',f'{key}={max(int(run("sysctl","-n",key).stdout),16<<20)}')
    cases=[('bip',p,r,d,'0%') for p in (1280,1348) for r in (200,500) for d in (False,True)]
    cases += [(p,1280,200,d,'0%') for p in ('tcp','udp','icmp','gre','ipip') for d in (False,True)]
    cases += [('bip',p,200,True,'0.2%') for p in (1280,1348)]
    cases=[(*case,'legacy') for case in cases]
    cases += [('bip',p,r,d,'0%','compact') for p in (1280,1348) for r in (200,500) for d in (False,True)]
    cases += [('bip',p,200,True,'0.2%','compact') for p in (1280,1348)]
    rows=[];failures=[]
    for profile,payload,rate,reverse,loss,wire in cases:
        row=dict(profile=profile,payload=payload,link_mbps=rate,reverse=reverse,loss=loss,wire=wire,architecture=ARCH,base_rtt_ms=80,sample_sec=8,warmup_sec=2)
        try:
            with Pair(profile) as pair:
                for i in range(2):
                    path=pair.path/f'{i}.json';cfg=json.loads(path.read_text())
                    cfg['performance']['max_frame_payload']=payload;cfg['tun']['mtu']=payload
                    if wire=='compact':cfg['transport']['bip_wire_mode']='compact'
                    path.write_text(json.dumps(cfg))
                pair.shape(rate,80,loss=loss);pair.restart();time.sleep(1.2)
                side=0 if reverse else 1
                before=pair.sample();n0=nic(pair,side);began=time.monotonic()
                result=pair.finish_iperf(*pair.iperf('10.77.1.2',8,2,reverse,16),35)
                time.sleep(1.2);after=pair.sample();n1=nic(pair,side);elapsed=time.monotonic()-began
                a=before['peers'][side].get('telemetry',{});b=after['peers'][side].get('telemetry',{})
                useful=b.get('rx_delivered_bytes',0)-a.get('rx_delivered_bytes',0)
                row.update(result,nic_rx_bytes=n1-n0,tun_rx_delivered_bytes=useful,nic_to_inner_ratio=round((n1-n0)/useful,4) if useful>0 else None,
                    cpu_cores_used=[round((v.get('cpu_sec',0)-u.get('cpu_sec',0))/elapsed,3) for u,v in zip(before['peers'],after['peers'])],end_snapshot=after)
                recoveries=[v.get('telemetry',{}).get('internal_recoveries',0)-u.get('telemetry',{}).get('internal_recoveries',0) for u,v in zip(before['peers'],after['peers'])]
                same=[u.get('pid') for u in before['peers']]==[v.get('pid') for v in after['peers']]
                floor=(100 if rate==200 else 200) if profile=='bip' and loss=='0%' else (1 if loss!='0%' else 30)
                row.update(internal_recoveries=recoveries,processes_unchanged=same,status='pass' if result['received_mbps']>=floor and same and not any(recoveries) else 'fail')
        except Exception as exc: row.update(status='fail',reason=str(exc))
        print(json.dumps(row),flush=True);rows.append(row)
        with (OUT/'transport-results.jsonl').open('a') as f:f.write(json.dumps(row)+'\n')
        if row['status']!='pass':failures.append(row)
    (OUT/'transport-summary.json').write_text(json.dumps(dict(rows=rows,failures=failures),indent=2))
    if failures:raise RuntimeError(f'{len(failures)} checks failed; raw observations retained')

if __name__=='__main__':main()
