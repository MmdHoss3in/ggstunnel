"""Reject incomplete, duplicated, failed or wrong-source stability evidence."""
import json
import math
from pathlib import Path
import statistics

ARCHES=('amd64','arm64')
PROFILES=('bip','tcp','udp','icmp','gre','ipip','dcpi')
BASELINE_SOURCE='aab18976517393dc87a1437eceaca63169ccee66'
CASES=(('0%',200),('0%',500),('1%',200),('3%',200))

def key(row):
    kind=row['kind'];arch=row['architecture']
    if kind not in ('renewal','path-mtu','fixed-performance','fixed-performance-summary'):raise ValueError('Unknown RC6 observation')
    if kind=='renewal':return kind,arch,row['profile']
    if kind=='path-mtu':return kind,arch,row['profile'],row['wire']
    base=(kind,arch,row['loss'],row['rate'],row['reverse'])
    return base+(row['version'],row['trial']) if kind=='fixed-performance' else base

def expected_keys():
    expected={('renewal',a,p) for a in ARCHES for p in PROFILES}
    expected.update(('path-mtu',a,p,w) for a in ARCHES for p,w in (('bip','legacy'),('bip','compact'),('udp','opaque')))
    for a in ARCHES:
        for loss,rate in CASES:
            for reverse in (False,True):
                expected.add(('fixed-performance-summary',a,loss,rate,reverse))
                expected.update(('fixed-performance',a,loss,rate,reverse,v,t)
                                for v in ('rc5','candidate') for t in range(3 if loss=='0%' else 5))
    return expected

def progress_ok(row,gap):
    progress=row.get('progress',{})
    return progress.get('verified_frames',0)>=10 and 0<=progress.get('max_gap_sec',math.inf)<=gap

def safe_payload(snapshot,ceiling,exact=False):
    peers=snapshot.get('peers',[])
    return len(peers)==2 and all(p.get('telemetry',{}).get('path_mtu_state')=='confirmed' and
           (p['telemetry'].get('effective_frame_payload')==ceiling if exact else
            256<=p['telemetry'].get('effective_frame_payload',0)<=ceiling) for p in peers)

def validate_rows(rows,source):
    expected=expected_keys();indexed={}
    for row in rows:
        k=key(row)
        if k not in expected or k in indexed:raise ValueError('Duplicate or unexpected RC6 observation')
        if row.get('source_commit')!=source or row.get('status')!='pass':raise ValueError('Failed or wrong-source RC6 observation')
        indexed[k]=row
    if indexed.keys()!=expected:raise ValueError('Incomplete RC6 observations')
    for row in rows:
        kind=row['kind']
        if kind in ('renewal','path-mtu'):
            before=row.get('device_before',[])
            if len(before)!=2 or before!=row.get('device_after'):raise ValueError('Physical TUN/routes continuity missing')
        if kind=='renewal':
            renewals=row.get('renewals',[]);peers=row.get('end_snapshot',{}).get('peers',[])
            if len(renewals)!=2 or renewals[0]<2 or renewals[1]<1 or len(peers)!=2 or row.get('pids_before')!=[p['pid'] for p in peers] or not progress_ok(row,15) or row['progress']['verified_frames']<20:
                raise ValueError('Renewal continuity/integrity failed')
        elif kind=='path-mtu':
            bip=row['profile']=='bip'
            speeds=row.get('blackhole_capacity',[])
            if not safe_payload(row.get('initial_blackhole',{}),1048 if bip else 1135) or not safe_payload(row.get('raised_path',{}),1348,True) or not safe_payload(row.get('reduced_path',{}),848 if bip else 935) or len(speeds)!=2 or any(not math.isfinite(s.get('received_mbps',0)) or s.get('received_mbps',0)<15 for s in speeds):
                raise ValueError('Authenticated path-size evidence failed')
        elif kind=='fixed-performance':
            loss=row['loss'];seconds,warmup=(20,2) if loss=='0%' else (45,15)
            floor=(150 if row['rate']==200 else 300) if loss=='0%' else 30 if loss=='1%' else 15
            runtime=BASELINE_SOURCE if row['version']=='rc5' else source
            speed=row.get('received_mbps',0)
            if row.get('recipe')!='steady-v2' or row.get('seconds')!=seconds or row.get('warmup_sec')!=warmup or row.get('runtime_source_commit')!=runtime or not math.isfinite(speed) or speed<floor or row.get('same_processes') is not True or row.get('recoveries')!=[0,0] or not progress_ok(row,5):
                raise ValueError('Capacity/integrity/runtime recipe failed')
        elif kind=='fixed-performance-summary':
            a,loss,rate,reverse=row['architecture'],row['loss'],row['rate'],row['reverse']
            repeats=3 if loss=='0%' else 5
            values={v:[indexed[('fixed-performance',a,loss,rate,reverse,v,t)]['received_mbps'] for t in range(repeats)] for v in ('rc5','candidate')}
            ratios=[new/old for new,old in zip(values['candidate'],values['rc5'])]
            geometric=math.exp(statistics.mean(math.log(x) for x in ratios))
            cv=statistics.stdev(values['rc5'])/statistics.mean(values['rc5'])
            if row.get('recipe')!='steady-v2' or row.get('values')!=values or row.get('paired_ratios')!=ratios or not math.isclose(row.get('geometric_ratio',0),geometric,rel_tol=1e-12) or not math.isclose(row.get('baseline_cv',0),cv,rel_tol=1e-12) or geometric<.90 or min(ratios)<.75 or cv>.15:
                raise ValueError('Paired performance/variance gate failed')
    return indexed

def report(directory,source):
    rows=[]
    for path in sorted(Path(directory).rglob('rc6-results.jsonl')):
        rows.extend(json.loads(line) for line in path.read_text().splitlines() if line.strip())
    validate_rows(rows,source)
    notes='\n## Persistent TUN, renewal, authenticated size and RC5 comparisons\n\n'
    notes+='164 exact-source observations on native amd64/arm64: 14 forwarded established-TCP renewal cases, 6 silent size-drop discovery cases, 128 fixed capacity/integrity samples and 16 paired summaries. Clean cases use 20 measured seconds/2-second warmup and three balanced pairs. Loss cases use 45 measured seconds/15-second warmup and five balanced pairs. The immutable RC5 archive, 90% geometric/75% individual-pair thresholds and 15% baseline-CV maximum are unchanged. The former short comparison failure remains documented in docs/stable-validation-history.md; it is not erased by this revised measurement recipe. These are short synthetic observations, not a 95% multiday or firewall-passage guarantee. All raw logs are in rc6-validation-results.tar.gz.\n\n'
    notes+='| Arch | Link Mbps | Loss | Direction | RC6/RC5 geometric ratio | Baseline CV | Candidate Mbps range |\n|---|---:|---|---|---:|---:|---:|\n'
    for row in rows:
        if row['kind']!='fixed-performance-summary':continue
        values=row['values']['candidate']
        notes+=f"| {row['architecture']} | {row['rate']} | {row['loss']} | {'reverse' if row['reverse'] else 'forward'} | {row['geometric_ratio']:.4f} | {row['baseline_cv']:.4f} | {min(values):.3f}–{max(values):.3f} |\n"
    notes+='\nRenewal maximum measured progress gap: '+f"{max(r['progress']['max_gap_sec'] for r in rows if r['kind']=='renewal'):.3f}"+' seconds. The physical TUN/routes and existing forwarded TCP connection remained; renewal still pauses delivery and can discard in-flight UDP. PMTU remains opt-in and DCPI experimental.\n'
    return notes
