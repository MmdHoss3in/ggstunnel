#!/usr/bin/env python3
"""ggstunnel host manager. All subprocesses use argv, never shell interpolation."""
import argparse
import base64
import contextlib
import datetime
import fcntl
import getpass
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import platform
import re
import secrets
import shutil
import subprocess
import sys
import tempfile
import time
import threading
import zipfile

ROOT = Path('/etc/ggstunnel')
OPT = Path('/opt/ggstunnel')
UNITS = Path('/etc/systemd/system')
RUN = Path('/run/ggstunnel')
VERSION = (Path(__file__).resolve().parents[1]/'internal/version/VERSION').read_text().strip()
PROFILES = ('bip', 'tcp', 'udp', 'icmp', 'gre')

def run(args, check=True, timeout=90):
    p = subprocess.run([str(x) for x in args], text=True, capture_output=True, timeout=timeout)
    if check and p.returncode:
        raise RuntimeError(' '.join(map(str, args[:3])) + ': ' + p.stderr.strip() + p.stdout.strip())
    return p

def atomic(path, data, mode=0o600):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd, name = tempfile.mkstemp(dir=path.parent, prefix='.ggs-')
    try:
        os.fchmod(fd, mode)
        with os.fdopen(fd, 'w') as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.replace(name, path)
    finally:
        if os.path.exists(name): os.unlink(name)

def name_ok(name):
    if not re.fullmatch(r'ggs[0-9]{2,3}', name): raise ValueError('Invalid tunnel name')
    return name

def confpath(name): return ROOT / 'tunnels' / (name_ok(name) + '.json')
def unit(name): return 'ggstunnel@' + name_ok(name) + '.service'
def binary(): return OPT / 'current' / 'dist' / ('ggstunnel-linux-' + arch())
def arch():
    a = {'x86_64': 'amd64', 'aarch64': 'arm64'}.get(platform.machine())
    if not a: raise ValueError('Only Linux amd64/arm64 supported')
    return a

def configs():
    return {p.stem: json.loads(p.read_text()) for p in sorted((ROOT / 'tunnels').glob('ggs*.json'))}

def ipv4(s):
    a = ipaddress.IPv4Address(s)
    if a.is_unspecified or a.is_multicast or a.is_loopback: raise ValueError('Use a unicast server IPv4 address')
    return str(a)

def integer(s, low, high):
    n = int(s)
    if not low <= n <= high: raise ValueError(f'Value must be {low}..{high}')
    return n

def addresses(index):
    integer(index, 1, 168)
    return f'10.{87+index}.1.1', f'10.{87+index}.1.2'

def make_config(index, profile, server, peer, port, psk, role, local=None):
    integer(index, 1, 168)
    if profile not in PROFILES: raise ValueError('Unsupported transport')
    server, peer = ipv4(server), ipv4(peer)
    if server == peer: raise ValueError('Server and peer must differ')
    integer(port, 1024, 65535)
    if not re.fullmatch('[0-9a-f]{64}', psk): raise ValueError('Invalid PSK')
    a, b = addresses(index)
    client = role == 'client'
    if role not in ('client', 'server'): raise ValueError('Invalid role')
    local = ipv4(local or (peer if client else server))
    remote = server if client else peer
    return dict(config_version=1, mode='tun', role=role, profile=profile, psk=psk,
        real=dict(local_ip=local, peer_ip=remote, listen_addr=f'{local}:{port}', peer_addr=f'{remote}:{port}'),
        tun=dict(name=f'ggs{index:02d}', local_addr=b if client else a, remote_addr=a if client else b,
                 prefix=30, mtu=1280, tx_queue_len=256, routes=[]),
        transport=dict(l4_port=port, heartbeat_sec=2, idle_timeout_sec=30, sock_buf=4 << 20, bip_pull_burst=128, bip_max_retries=8),
        performance=dict(profile='stable', queue_size=4096, max_frame_payload=1280),
        tuner=dict(mode='adaptive' if profile == 'bip' else 'manual', max_pps=10000, max_burst=128, unlimited_rate=True),
        telemetry=dict(interval_sec=2), forwards=[])

def encode_join(c):
    if c['role'] != 'server': raise ValueError('Generate join code on Iran')
    data = dict(v=2, index=int(c['tun']['name'][3:]), profile=c['profile'], server=c['real']['local_ip'],
                peer=c['real']['peer_ip'], port=c['transport']['l4_port'], psk=c['psk'],
                mtu=c['tun']['mtu'], payload=c['performance']['max_frame_payload'])
    raw = json.dumps(data, sort_keys=True, separators=(',', ':')).encode()
    return 'GGS2.' + base64.urlsafe_b64encode(raw).decode().rstrip('=') + '.' + hashlib.sha256(raw).hexdigest()[:16]

def decode_join(token, local=None):
    if len(token) > 4096: raise ValueError('Join code too long')
    prefix, encoded, digest = token.strip().split('.')
    if prefix != 'GGS2': raise ValueError('Unknown join code format')
    raw = base64.b64decode(encoded + '=' * (-len(encoded) % 4), altchars=b'-_', validate=True)
    if not secrets.compare_digest(hashlib.sha256(raw).hexdigest()[:16], digest): raise ValueError('Join code checksum mismatch')
    d = json.loads(raw)
    if set(d) != {'v','index','profile','server','peer','port','psk','mtu','payload'} or d['v'] != 2:
        raise ValueError('Unsupported join data')
    c = make_config(d['index'], d['profile'], d['server'], d['peer'], d['port'], d['psk'], 'client', local)
    c['tun']['mtu'] = integer(d['mtu'], 576, 1500)
    c['performance']['max_frame_payload'] = integer(d['payload'], 256, 1348)
    return c

def active(name): return run(['systemctl', 'is-active', '--quiet', unit(name)], check=False).returncode == 0

def validate(c, exe=None):
    ROOT.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd, path = tempfile.mkstemp(dir=ROOT, suffix='.json')
    try:
        with os.fdopen(fd, 'w') as f: json.dump(c, f)
        run([exe or binary(), '-c', path, '-check'])
    finally: os.unlink(path)

def conflict(c, old_name=None):
    for name, other in configs().items():
        if name == old_name: continue
        if c['tun']['name'] == name or c['tun']['local_addr'] == other['tun']['local_addr']:
            raise ValueError('Tunnel ID/address already allocated')
        if c['profile'] == other['profile']:
            if c['profile'] in ('tcp', 'udp') and c['real']['listen_addr'] == other['real']['listen_addr']:
                raise ValueError('Transport port already allocated')
            if c['profile'] in ('bip','icmp','gre') and c['real']['peer_ip'] == other['real']['peer_ip']:
                raise ValueError('One raw tunnel per transport and public peer IP')
    binds = set()
    for name, other in configs().items():
        if name != old_name:
            binds.update((r['protocol'], r['listen']) for r in other.get('forwards', []))
    for r in c.get('forwards', []):
        key = (r['protocol'], r['listen'])
        if key in binds: raise ValueError('Duplicate forward listener')
        binds.add(key)

def wait_service(name):
    time.sleep(1)
    if not active(name):
        raise RuntimeError('Service did not stay active; inspect: journalctl -u ' + unit(name))

def save_config(c, replace=False):
    name = name_ok(c['tun']['name']); path = confpath(name)
    if path.exists() and not replace: raise ValueError('Tunnel exists; edit or delete it first')
    conflict(c, name if replace else None); validate(c)
    old = path.read_text() if path.exists() else None
    was_active = active(name) if old else False
    if old: atomic(ROOT / 'backups' / (name + '-' + str(time.time_ns()) + '.json'), old)
    atomic(path, json.dumps(c, indent=2) + '\n')
    try:
        if old is None: run(['systemctl', 'enable', '--now', unit(name)]); wait_service(name)
        elif was_active: run(['systemctl', 'restart', unit(name)]); wait_service(name)
    except Exception:
        if old is not None:
            atomic(path, old)
            if was_active: run(['systemctl', 'restart', unit(name)], check=False)
        else:
            run(['systemctl', 'disable', '--now', unit(name)], check=False)
            path.unlink(missing_ok=True)
        raise
    print('Saved:', name, c['profile'], c['tun']['local_addr'], '<->', c['tun']['remote_addr'])

def local_route(peer):
    p = run(['ip', '-j', 'route', 'get', peer])
    row = json.loads(p.stdout)[0]
    return ipv4(row.get('prefsrc') or row.get('src'))

def create_server():
    used = configs(); index = next((i for i in range(1,169) if f'ggs{i:02d}' not in used), None)
    if not index: raise ValueError('No free IDs')
    print('Transports: tcp / udp / bip / icmp / gre. BIP5 performance candidate: both peers require this release.')
    profile = ask('Transport', 'bip').lower()
    server = ipv4(ask('Iran public IPv4'))
    peer = ipv4(ask('Foreign public IPv4'))
    port = integer(ask('Port (TCP/UDP only)', str(24000+index)), 1024,65535)
    c = make_config(index, profile, server, peer, port, secrets.token_hex(32), 'server')
    save_config(c)
    print('Copy this SECRET join code to the foreign server (contains PSK):\n' + encode_join(c))
    print('Allow inbound', f'{profile.upper()} {port}' if profile in ('tcp','udp') else ('IPv4 protocol 47' if profile=='gre' else 'ICMP'), 'from', peer, 'in your firewall.')

def join_client():
    token = getpass.getpass('Paste SECRET GGS2 join code (hidden): ').strip()
    c = decode_join(token)
    c['real']['local_ip'] = local_route(c['real']['peer_ip'])
    c['real']['listen_addr'] = f"{c['real']['local_ip']}:{c['transport']['l4_port']}"
    if c['tun']['name'] in configs():
        if ask('Tunnel exists. Type REPLACE to update it') != 'REPLACE': return
        c['forwards'] = configs()[c['tun']['name']].get('forwards', [])
        save_config(c, True)
    else: save_config(c)
    print('Allow the selected transport from Iran in the host/provider firewall.')

def select_name():
    status(); return name_ok(ask('Tunnel name, e.g. ggs01'))

def status():
    for name,c in configs().items():
        p = run(['systemctl','is-enabled',unit(name)],check=False)
        print(name, c['role'], c['profile'], c['tun']['local_addr'], '<->', c['tun']['remote_addr'],
              'RUNNING' if active(name) else 'STOPPED', p.stdout.strip())
    if not configs(): print('No configured tunnels')

def action(verb, name):
    names = list(configs()) if name == 'all' else [name_ok(name)]
    failures = []
    for n in names:
        if n not in configs(): raise ValueError('Unknown tunnel '+n)
        try:
            if verb == 'on': args = ['enable','--now']
            elif verb == 'off': args = ['disable','--now']
            elif verb in ('start','stop','restart'): args = [verb]
            else: raise ValueError('Invalid action')
            run(['systemctl',*args,unit(n)])
            if verb in ('on','start','restart'): wait_service(n)
            print(n, verb, 'OK')
        except Exception as e: failures.append(str(e))
    if failures: raise RuntimeError('\n'.join(failures))

def delete(name):
    path = confpath(name)
    if not path.exists(): raise ValueError('Unknown tunnel')
    run(['systemctl','disable','--now',unit(name)])
    atomic(ROOT/'backups'/(name+'-deleted-'+str(time.time_ns())+'.json'),path.read_text())
    path.unlink(); (RUN/(name+'.json')).unlink(missing_ok=True)
    run(['systemctl','reset-failed',unit(name)],check=False)
    print('Deleted tunnel; private config backup retained.')

def edit(name):
    c = configs()[name]
    print('1) Edit full JSON  2) Add TCP/UDP forward  3) Remove forward  4) Restore previous config')
    choice = ask('Choice')
    if choice == '1':
        fd,p = tempfile.mkstemp(dir=ROOT,suffix='.json')
        try:
            with os.fdopen(fd,'w') as f: json.dump(c,f,indent=2)
            subprocess.run(['nano',p],check=True)
            c = json.loads(Path(p).read_text())
            if c['tun']['name'] != name: raise ValueError('Tunnel name cannot be changed')
            save_config(c,True)
        finally: os.unlink(p)
    elif choice == '2':
        proto=ask('Forward protocol','tcp').lower()
        if proto not in ('tcp','udp'): raise ValueError('tcp or udp required')
        host=str(ipaddress.IPv4Address(ask('Local listen IP','0.0.0.0')))
        port=integer(ask('Listen port'),1,65535); target=integer(ask('Destination port on foreign/peer TUN IP'),1,65535)
        c.setdefault('forwards',[]).append(dict(protocol=proto,listen=f'{host}:{port}',target=f"{c['tun']['remote_addr']}:{target}"))
        save_config(c,True)
    elif choice == '3':
        for i,r in enumerate(c.get('forwards',[]),1): print(i,r)
        i=integer(ask('Rule number'),1,len(c.get('forwards',[])))
        c['forwards'].pop(i-1);save_config(c,True)
    elif choice == '4':
        files=sorted((ROOT/'backups').glob(name+'-*.json'),key=lambda p:p.stat().st_mtime,reverse=True)
        for i,p in enumerate(files[:10],1): print(i,p.name)
        p=files[integer(ask('Backup number'),1,min(10,len(files)))-1]
        save_config(json.loads(p.read_text()),True)
    if c['role']=='server': print('If shared settings changed, replace the client config too using this code:\n'+encode_join(c))

def diagnose(name):
    c=configs()[name];stamp=datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%SZ')
    dest=ROOT/'reports';dest.mkdir(mode=0o700,exist_ok=True)
    path=dest/(name+'-'+stamp+'.txt')
    chunks=[f'ggstunnel {VERSION}; transport={c["profile"]}; role={c["role"]}\n']
    for cmd in [[binary(),'-version'],['uname','-a'],['cat','/etc/os-release'],['free','-m'],['systemctl','status','--no-pager',unit(name)],
                ['ip','-s','link','show',c['tun']['name']],['ip','route','get',c['tun']['remote_addr']],
                ['ping','-I',c['tun']['name'],'-c','10','-W','2',c['tun']['remote_addr']],
                ['journalctl','-u',unit(name),'-n','120','--no-pager']]:
        p=run(cmd,check=False,timeout=40);chunks.append('$ '+' '.join(map(str,cmd))+'\n'+p.stdout+p.stderr)
    stats=RUN/(name+'.json')
    if stats.exists():chunks.append(stats.read_text())
    atomic(path,'\n'.join(chunks));print('REPORT='+str(path))

def capacity(name, mode, rates=(5,20,50,80,100), duration=30):
    c=configs()[name];local=c['tun']['local_addr'];peer=c['tun']['remote_addr'];dev=c['tun']['name']
    if mode=='listen':
        stamp=datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%SZ')
        dest=ROOT/'reports';dest.mkdir(mode=0o700,exist_ok=True)
        trace=dest/(name+'-listener-'+stamp+'.jsonl');stop=threading.Event()
        def monitor():
            with trace.open('w') as f:
                os.chmod(trace,0o600)
                while not stop.is_set():
                    stats=RUN/(name+'.json');row={'at':time.time()}
                    try:row.update(stats=json.loads(stats.read_text()),age_sec=time.time()-stats.stat().st_mtime)
                    except (OSError,ValueError) as e:row['error']=str(e)
                    f.write(json.dumps(row)+'\n');f.flush();stop.wait(1)
        worker=threading.Thread(target=monitor);worker.start()
        print('Private TUN iperf3 listener with telemetry. Ctrl+C to finish report.')
        try:subprocess.run(['iperf3','-s','-B',local,'-p','5207'],check=True)
        finally:
            stop.set();worker.join();path=trace.with_suffix('.zip')
            with zipfile.ZipFile(path,'w',zipfile.ZIP_DEFLATED) as z:
                os.chmod(path,0o600);z.write(trace,trace.name)
                z.writestr('version.txt',run([binary(),'-version']).stdout)
                z.writestr('journal.txt',run(['journalctl','-u',unit(name),'-n','200','--no-pager'],check=False).stdout)
            trace.unlink();print('REPORT='+str(path))
        return
    route=json.loads(run(['ip','-j','route','get',peer]).stdout)[0]
    if route.get('dev')!=dev:raise ValueError('Test route does not use this TUN')
    stamp=datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%SZ')
    dest=ROOT/'reports';dest.mkdir(mode=0o700,exist_ok=True)
    path=dest/(name+'-capacity-'+stamp+'.zip');results=[]
    with zipfile.ZipFile(path,'w',zipfile.ZIP_DEFLATED) as z:
        os.chmod(path,0o600)
        for rate in rates:
            healthy=True
            for proto in ('tcp','udp'):
                for reverse in (False,True):
                    label=f'{proto}-{rate}M-'+('reverse' if reverse else 'forward')
                    cmd=['iperf3','-c',peer,'-B',local,'-p','5207','-t',str(duration),'-b',f'{rate}M','-J','--connect-timeout','5000']
                    if proto=='udp':cmd+=['-u','-l','1000']
                    if reverse:cmd+=['-R']
                    try:p=run(cmd,check=False,timeout=duration+25)
                    except subprocess.TimeoutExpired:p=subprocess.CompletedProcess(cmd,124,'','iperf3 timeout')
                    z.writestr(label+'.json',p.stdout or p.stderr)
                    try:
                        d=json.loads(p.stdout);end=d.get('end',{});r=end.get('sum_received',end.get('sum',{}))
                        if r.get('sender') is True: raise ValueError('Receiver summary missing')
                        mbps=r.get('bits_per_second',0)/1e6;loss=r.get('lost_percent',0)
                        ok=p.returncode==0 and not d.get('error') and mbps>=rate*.8 and loss<=1
                    except (ValueError,TypeError):mbps=0;loss=None;ok=False
                    results.append(dict(test=label,received_mbps=mbps,lost_percent=loss,passed=ok));print(results[-1],flush=True)
                    healthy &= ok
                    stats=RUN/(name+'.json')
                    if stats.exists():z.writestr(label+'-telemetry.json',stats.read_text())
            if not healthy:print('Stopping higher rate steps after failed threshold');break
        z.writestr('summary.json',json.dumps(results,indent=2))
        z.writestr('version.txt',run([binary(),'-version']).stdout)
    print('REPORT='+str(path))

def tune(restore=False):
    file=Path('/etc/sysctl.d/90-ggstunnel.conf');backup=ROOT/'network-before.json'
    values={'net.core.rmem_max':16777216,'net.core.wmem_max':16777216,'net.ipv4.tcp_mtu_probing':1}
    if restore:
        if not backup.exists():raise ValueError('No saved tuning state')
        saved=json.loads(backup.read_text())
        for k,v in saved['before'].items():
            if run(['sysctl','-n',k]).stdout.strip()==str(saved['applied'][k]):run(['sysctl','-w',f'{k}={v}'])
        file.unlink(missing_ok=True);backup.unlink();print('Restored unchanged settings; externally changed values preserved');return
    if backup.exists():
        saved=json.loads(backup.read_text());values=saved['applied']
    else:
        before={k:run(['sysctl','-n',k]).stdout.strip() for k in values}
        values={k:max(v,int(before[k])) for k,v in values.items()}
        atomic(backup,json.dumps(dict(before=before,applied=values)))
    atomic(file,'# ggstunnel socket ceilings and TCP MTU probing\n'+'\n'.join(f'{k} = {v}' for k,v in values.items())+'\n',0o644)
    run(['sysctl','-p',file]);print('Tuning applied; existing larger values preserved')

UNIT = '''[Unit]
Description=ggstunnel %i
After=network-online.target
Wants=network-online.target
StartLimitIntervalSec=0
[Service]
Type=simple
ExecStart=/opt/ggstunnel/current/dist/BINARY -c /etc/ggstunnel/tunnels/%i.json -stats-file /run/ggstunnel/%i.json
Restart=on-failure
RestartSec=3
TimeoutStopSec=15
UMask=0077
RuntimeDirectory=ggstunnel
RuntimeDirectoryMode=0700
RuntimeDirectoryPreserve=yes
LimitNOFILE=65536
NoNewPrivileges=true
ProtectHome=true
ProtectSystem=strict
ReadWritePaths=/run/ggstunnel
PrivateTmp=true
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW CAP_NET_BIND_SERVICE
[Install]
WantedBy=multi-user.target
'''

def symlink(target,path):
    tmp=path.with_name(path.name+'.new');tmp.unlink(missing_ok=True);tmp.symlink_to(target);os.replace(tmp,path)

def restore_unit(path, content):
    if content is None:path.unlink(missing_ok=True)
    else:atomic(path,content,0o644)

def install(source):
    source=Path(source).resolve();a=arch()
    # Verify the complete package before executing its binary or changing files.
    manifest=source/'SHA256SUMS'
    listed=set()
    for line in manifest.read_text().splitlines():
        digest,rel=line.split();rel=rel.lstrip('*');p=source/rel
        if not re.fullmatch('[0-9a-f]{64}',digest) or not p.resolve().is_relative_to(source) or p.is_symlink():raise ValueError('Unsafe release manifest')
        if rel in listed:raise ValueError('Duplicate release path')
        listed.add(rel)
        if hashlib.sha256(p.read_bytes()).hexdigest()!=digest:raise ValueError('Release checksum mismatch: '+rel)
    required={'scripts/manage.py','dist/SHA256SUMS','dist/ggstunnel-linux-'+a}
    if not required.issubset(listed):raise ValueError('Incomplete release manifest')
    expected={}
    for line in (source/'dist/SHA256SUMS').read_text().splitlines():
        digest,n=line.split();expected[n.lstrip('*')]=digest
    exe=source/'dist'/('ggstunnel-linux-'+a)
    if hashlib.sha256(exe.read_bytes()).hexdigest()!=expected.get(exe.name):raise ValueError('Binary checksum mismatch')
    os.chmod(exe,0o755)
    for c in configs().values():validate(c,exe)
    release_version=run([exe,'-version']).stdout.strip().split()[-1]
    if not re.fullmatch(r'[A-Za-z0-9.-]+',release_version):raise ValueError('Invalid release version')
    release=OPT/'releases'/(release_version+'-'+hashlib.sha256(manifest.read_bytes()).hexdigest()[:12])
    release.parent.mkdir(parents=True,exist_ok=True)
    if not release.exists():shutil.copytree(source,release,ignore=shutil.ignore_patterns('develop-state','__pycache__','.git'))
    previous=(OPT/'current').resolve() if (OPT/'current').exists() else None
    running=[n for n in configs() if active(n)]
    unit_path=UNITS/'ggstunnel@.service'
    old_unit=unit_path.read_text() if unit_path.exists() else None
    new_unit=UNIT.replace('BINARY',exe.name)
    # Keep the previous installed unit for an upgrade from older packages
    # which did not save this generated release metadata.
    if previous and old_unit is not None and not (previous/'ggstunnel@.service').exists():
        atomic(previous/'ggstunnel@.service',old_unit,0o644)
    atomic(release/'ggstunnel@.service',new_unit,0o644)
    try:
        atomic(unit_path,new_unit,0o644)
        symlink(release,OPT/'current')
        atomic('/usr/local/bin/ggstunnel', '#!/bin/sh\nexec python3 /opt/ggstunnel/current/scripts/manage.py "$@"\n',0o755)
        run(['systemctl','daemon-reload'])
        for n in running:action('restart',n)
    except Exception:
        if previous:symlink(previous,OPT/'current')
        else:(OPT/'current').unlink(missing_ok=True)
        restore_unit(unit_path,old_unit)
        run(['systemctl','daemon-reload'],check=False)
        if previous:
            for n in running:run(['systemctl','restart',unit(n)],check=False)
        raise
    if previous and previous!=release:symlink(previous,OPT/'previous')
    print('Installed',release_version,'Run: sudo ggstunnel')

def rollback():
    target=OPT/'previous'
    if not target.exists():raise ValueError('No previous installed release')
    previous=target.resolve();current=(OPT/'current').resolve()
    for c in configs().values():validate(c,previous/'dist'/('ggstunnel-linux-'+arch()))
    running=[n for n in configs() if active(n)]
    unit_path=UNITS/'ggstunnel@.service'
    old_unit=unit_path.read_text() if unit_path.exists() else None
    saved_unit=previous/'ggstunnel@.service'
    try:
        if saved_unit.exists():restore_unit(unit_path,saved_unit.read_text())
        symlink(previous,OPT/'current')
        run(['systemctl','daemon-reload'])
        for n in running:action('restart',n)
    except Exception:
        symlink(current,OPT/'current')
        restore_unit(unit_path,old_unit)
        run(['systemctl','daemon-reload'],check=False)
        for n in running:run(['systemctl','restart',unit(n)],check=False)
        raise
    symlink(current,OPT/'previous');print('Rolled back executable/manager; configuration retained')

@contextlib.contextmanager
def locked():
    ROOT.mkdir(mode=0o700,parents=True,exist_ok=True)
    with (ROOT/'manager.lock').open('a') as f:
        fcntl.flock(f,fcntl.LOCK_EX)
        yield

def ask(label,default=''):
    value=input(label+(f' [{default}]' if default else '')+': ').strip()
    return value or default

def menu():
    while True:
        print('\nGGSTUNNEL '+VERSION+'\n1 Create Iran tunnel  2 Join from foreign  3 Status\n4 Start temporarily  5 Stop temporarily  6 Restart\n7 ON + boot enable  8 OFF + boot disable  9 Edit / forwards / restore config\n10 Delete tunnel  11 Show join code  12 Logs  13 Diagnostic report\n14 Capacity listener  15 Capacity test  16 Apply network tuning\n17 Restore tuning  18 Update from extracted package  19 Rollback release\n20 Sustained capacity test (10 minutes each direction/protocol)\n21 Apply BIP performance defaults to existing tunnels\n0 Exit\nActions 4-8 accept tunnel name or all. Temporary stop lasts until manual start or reboot.')
        choice=ask('Choice')
        if choice=='0':return
        try:
            with (locked() if choice not in ('3','12','13','14','15','20') else contextlib.nullcontext()):
                if choice=='1':create_server()
                elif choice=='2':join_client()
                elif choice=='3':status()
                elif choice in ('4','5','6','7','8'):
                    status();action({'4':'start','5':'stop','6':'restart','7':'on','8':'off'}[choice],ask('Tunnel name or all'))
                elif choice=='9':edit(select_name())
                elif choice=='10':
                    n=select_name()
                    if ask('Type DELETE to remove '+n)=='DELETE':delete(n)
                elif choice=='11':print(encode_join(configs()[select_name()]))
                elif choice=='12':run_logs(select_name())
                elif choice=='13':diagnose(select_name())
                elif choice in ('14','15'):capacity(select_name(),'listen' if choice=='14' else 'client')
                elif choice=='16':tune()
                elif choice=='17':tune(True)
                elif choice=='18':install(ask('Extracted package source directory'))
                elif choice=='19':rollback();return
                elif choice=='21':optimize_existing()
                elif choice=='20':capacity(select_name(),'client',(integer(ask('Rate Mbps','100'),1,1000),),600)
        except (Exception,KeyboardInterrupt) as e:print('ERROR:',str(e) or 'Interrupted')

def optimize_existing():
    for c in configs().values():
        if c['profile']!='bip':continue
        c.setdefault('tuner',{}).update(mode='adaptive',unlimited_rate=True,max_burst=128)
        c.setdefault('transport',{}).update(bip_pull_burst=128,bip_max_retries=8)
        c['performance']['queue_size']=max(4096,c['performance'].get('queue_size',4096))
        c['tun']['tx_queue_len']=min(256,c['tun'].get('tx_queue_len',256))
        save_config(c,True)
    print('BIP performance defaults applied; both peers must run BIP5.')

def run_logs(name):subprocess.run(['journalctl','-u',unit(name),'-n','100','--no-pager'])

def main():
    os.umask(0o077)
    ap=argparse.ArgumentParser();ap.add_argument('command',nargs='?',default='menu',choices=['menu','install','status','start','stop','restart','on','off','diagnose','capacity','listen','rollback'])
    ap.add_argument('target',nargs='?');args=ap.parse_args()
    if os.geteuid()!=0:raise ValueError('Run with sudo/root')
    if args.command=='menu':menu();return
    with (locked() if args.command not in ('status','diagnose','capacity','listen') else contextlib.nullcontext()):
        if args.command=='install':install(args.target or Path(__file__).resolve().parents[1])
        elif args.command=='status':status()
        elif args.command=='rollback':rollback()
        elif args.command=='diagnose':
            for n in (list(configs()) if args.target=='all' else [name_ok(args.target or '')]):diagnose(n)
        elif args.command in ('listen','capacity'):capacity(name_ok(args.target or ''),'listen' if args.command=='listen' else 'client')
        else:action(args.command,args.target or 'all')
if __name__=='__main__':
    try:main()
    except (Exception,KeyboardInterrupt) as e:print('ERROR:',str(e) or 'Interrupted',file=sys.stderr);sys.exit(1)
