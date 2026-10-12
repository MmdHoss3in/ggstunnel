"""Exact 0.3.6 upgrade/rollback and mixed-version checks on disposable Linux CI."""
import hashlib
import json
import os
from pathlib import Path
import tarfile
import tempfile
from unittest.mock import patch

import manage as m
from cloud_extended import ARCH, BIN, OUT, SOURCE, Pair, run

BASELINE_SHA='7533905bf96deb8ec998569861831ee9a93add9be4bc2c6565c0825ae0c48701'

def record(row):
    row.update(architecture=ARCH,source_commit=run('git','-C',SOURCE,'rev-parse','HEAD').stdout.strip())
    print(json.dumps(row),flush=True)
    with (OUT/'field-stall-results.jsonl').open('a') as f:f.write(json.dumps(row)+'\n')

def installed_state(names):
    result={}
    for n in names:
        pid=int(run('systemctl','show',m.unit(n),'-p','MainPID','--value').stdout.strip())
        result[n]=dict(active=m.active(n),enabled=run('systemctl','is-enabled',m.unit(n),check=False).stdout.strip(),pid=pid,
                       executable_sha=hashlib.sha256(Path(f'/proc/{pid}/exe').read_bytes()).hexdigest() if pid else None)
    return result

def seven_instance_upgrade(baseline):
    names=[f'ggs{i:02d}' for i in range(1,8)]
    if any(m.confpath(n).exists() for n in names):raise RuntimeError('Refusing to overwrite an existing tunnel')
    m.install(baseline)
    run('ip','link','add','ggs-ci-outer','type','dummy')
    saved={}
    try:
        run('ip','addr','add','198.18.0.1/24','dev','ggs-ci-outer')
        run('ip','link','set','ggs-ci-outer','up')
        for i,n in enumerate(names,1):
            c=m.make_config(i,'bip','198.18.0.1',f'198.18.0.{10+i}',24000+i,f'{i:064x}','server')
            c['tun']['routes']=[f'10.200.{i}.0/24']
            c['forwards']=[dict(protocol='tcp',listen=f'127.0.0.1:{25200+i}',target=f"{c['tun']['remote_addr']}:443")]
            m.atomic(m.confpath(n),json.dumps(c));saved[n]=m.confpath(n).read_bytes()
        for n in names[:5]:m.action('on',n)
        run('systemctl','enable',m.unit(names[5]))
        run('systemctl','disable',m.unit(names[6]),check=False)
        before=installed_state(names)
        new_sha=hashlib.sha256(BIN.read_bytes()).hexdigest()
        old_sha=hashlib.sha256((baseline/'dist'/BIN.name).read_bytes()).hexdigest()
        def verify(expected):
            after=installed_state(names)
            for n in names:
                if m.confpath(n).read_bytes()!=saved[n]:raise RuntimeError('Upgrade changed config: '+n)
                if (after[n]['active'],after[n]['enabled'])!=(before[n]['active'],before[n]['enabled']):raise RuntimeError('Upgrade changed service state: '+n)
                if after[n]['active'] and after[n]['executable_sha']!=expected:raise RuntimeError('Wrong running binary: '+n)
            return after
        m.install(SOURCE);upgraded=verify(new_sha)
        m.rollback();verify(old_sha)
        real_action=m.action;fault={'armed':True}
        def fail_third(verb,target):
            if verb=='restart' and target==names[2] and fault['armed']:
                fault['armed']=False;raise RuntimeError('injected third live service restart failure')
            return real_action(verb,target)
        try:
            with patch.object(m,'action',fail_third):m.install(SOURCE)
        except RuntimeError as exc:
            if 'injected third' not in str(exc):raise
        else:raise RuntimeError('Fault injection was not exercised')
        verify(old_sha)
        if (m.OPT/'install-transaction.json').exists():raise RuntimeError('Rollback transaction was not committed')
        m.install(SOURCE);verify(new_sha)
        record(dict(case='seven-instance-real-upgrade',status='pass',active_count=5,stopped_enabled_count=1,disabled_count=1,
                    configurations_preserved=7,partial_failure_rollback=True,
                    restarted_pids=sum(upgraded[n]['pid']!=before[n]['pid'] for n in names[:5])))
    finally:
        for n in names:
            m.run(['systemctl','disable','--now',m.unit(n)],check=False)
            m.confpath(n).unlink(missing_ok=True)
        run('ip','link','del','ggs-ci-outer',check=False)

def mixed_version(baseline):
    old=baseline/'dist'/BIN.name
    for first in (0,1):
        with Pair(label=f'field-upgrade-{first}-') as pair:
            pair.executables=[old,old];pair.baseline_preserve_config=True
            pair.shape(200,80,'0%');pair.restart()
            for phase in ('old','mixed','new'):
                if phase!='old':
                    i=first if phase=='mixed' else 1-first
                    pair.stop_peer(i);pair.executables[i]=BIN;pair.start_peer(i);pair.reachable(20)
                for reverse in (False,True):
                    server,client=pair.iperf('10.77.1.2',seconds=8,warmup=2,reverse=reverse)
                    result=pair.finish_iperf(server,client,20)
                    row=dict(case='mixed-version',first_upgraded=first,phase=phase,reverse=reverse,**result)
                    if result['received_mbps']<100:raise RuntimeError('Mixed-version useful throughput floor failed: '+json.dumps(row))
                    row['status']='pass';record(row)

def main():
    if os.geteuid()!=0 or os.environ.get('GITHUB_ACTIONS')!='true':raise RuntimeError('Disposable GitHub runner required')
    OUT.mkdir(exist_ok=True)
    for key in ('net.core.rmem_max','net.core.wmem_max'):
        current=int(run('sysctl','-n',key).stdout.strip())
        run('sysctl','-w',f'{key}={max(current,16*1024*1024)}')
    with tempfile.TemporaryDirectory() as temporary:
        root=Path(temporary);archive=root/'baseline.tar.gz'
        run('curl','-fL','--retry','3','https://github.com/MmdHoss3in/ggstunnel/releases/download/v0.3.6/ggstunnel-linux.tar.gz','-o',archive,timeout=120)
        if hashlib.sha256(archive.read_bytes()).hexdigest()!=BASELINE_SHA:raise RuntimeError('Published 0.3.6 checksum mismatch')
        with tarfile.open(archive) as package:package.extractall(root,filter='data')
        baseline=root/'ggstunnel';m.verify_package(baseline,ARCH)
        seven_instance_upgrade(baseline)
        mixed_version(baseline)

if __name__=='__main__':main()
