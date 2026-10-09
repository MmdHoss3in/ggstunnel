"""Recompute queue-pressure gates from complete, exact-source native observations."""
import json
import math
from pathlib import Path
import statistics

BASELINE_SOURCE = 'ac5f73d013b51a574335e5e4bd301e73505d01d6'
CASES = ((200, '0%'), (500, '0%'))


def summary(rows):
    old = sorted((r for r in rows if r['version']=='v0.3.4'), key=lambda r:r['trial'])
    new = sorted((r for r in rows if r['version']=='candidate'), key=lambda r:r['trial'])
    if len(old)!=3 or len(new)!=3 or any(r['status']!='pass' for r in rows): raise ValueError('Incomplete or failed paired observations')
    ratios=[b['received_mbps']/a['received_mbps'] for a,b in zip(old,new)]
    result=dict(geometric_ratio=math.exp(statistics.mean(math.log(x) for x in ratios)),
        minimum_pair_ratio=min(ratios), baseline_cv=statistics.stdev(r['received_mbps'] for r in old)/statistics.mean(r['received_mbps'] for r in old),
        baseline_ping_p95_ms=statistics.median(r['ping_p95_ms'] for r in old), candidate_ping_p95_ms=statistics.median(r['ping_p95_ms'] for r in new),
        baseline_drop_fraction=statistics.median(r['drop_fraction'] for r in old), candidate_drop_fraction=statistics.median(r['drop_fraction'] for r in new),
        baseline_cpu_cores=statistics.median(r['cpu_cores'] for r in old), candidate_cpu_cores=statistics.median(r['cpu_cores'] for r in new))
    if result['geometric_ratio']<.90 or result['minimum_pair_ratio']<.75 or result['baseline_cv']>.15: raise ValueError('Paired speed or baseline variance gate failed')
    if result['candidate_ping_p95_ms']>max(result['baseline_ping_p95_ms']*1.2,result['baseline_ping_p95_ms']+25): raise ValueError('Latency regression')
    if result['candidate_drop_fraction']>result['baseline_drop_fraction']+.005: raise ValueError('Local drop fraction regression')
    if result['candidate_cpu_cores']>result['baseline_cpu_cores']*1.25+.1: raise ValueError('CPU regression')
    return result


def key(r):
    prefix=(r['architecture'], r['kind'])
    if r['kind']=='queue-overload': return prefix
    prefix+=(r['rate'],r['loss'],r['reverse'])
    return prefix+(r['version'],r['trial']) if r['kind']=='queue-pressure' else prefix


def validate(rows, source):
    expected=set()
    for arch in ('amd64','arm64'):
        expected.add((arch,'queue-overload'))
        for rate,loss in CASES:
            for reverse in (False,True):
                expected.add((arch,'queue-pressure-summary',rate,loss,reverse))
                expected.update((arch,'queue-pressure',rate,loss,reverse,v,t) for v in ('v0.3.4','candidate') for t in range(3))
    indexed={}
    for row in rows:
        k=key(row)
        if k not in expected or k in indexed: raise ValueError('Duplicate or unexpected pressure observation')
        if row.get('status')!='pass' or row.get('source_commit')!=source: raise ValueError('Failed or wrong-source pressure observation')
        runtime=BASELINE_SOURCE if row.get('version')=='v0.3.4' else source
        if row.get('runtime_source_commit')!=runtime: raise ValueError('Wrong baseline or candidate runtime')
        indexed[k]=row
    if indexed.keys()!=expected: raise ValueError('Incomplete queue-pressure evidence')
    for r in rows:
        if r['kind']=='queue-pressure-summary':
            measured=summary([indexed[(r['architecture'],'queue-pressure',r['rate'],r['loss'],r['reverse'],v,t)] for v in ('v0.3.4','candidate') for t in range(3)])
            if any(not math.isclose(r.get(k,math.inf),v,rel_tol=1e-9,abs_tol=1e-9) for k,v in measured.items()): raise ValueError('Forged pressure summary')
            continue
        if not r.get('same_processes') or any(r['recoveries']) or len(r['recoveries'])!=2 or r['progress']['verified_frames']<30 or not 0<=r['progress']['max_gap_sec']<=3: raise ValueError('Sparse progress/process gate failed')
        if not 0<r['max_rss_mib']<=96 or not 0<=r['peak_queue_bytes']<=8<<20 or not 0<=r['peak_flow_packets']<=512: raise ValueError('Resource bound exceeded')
        for name in ('received_mbps','drop_fraction','ping_p95_ms','cpu_cores'):
            if not math.isfinite(r[name]) or r[name]<0: raise ValueError('Invalid pressure metric')
        if r['kind']=='queue-overload':
            if sum(r['queue_drops'])<=0 or r['burst_admissions']<=0 or r['ping_p95_ms']>250: raise ValueError('Overload gate failed or unexercised')
        elif r['received_mbps']<(100 if r['rate']==200 else 300): raise ValueError('Pressure speed floor failed')
    return indexed


def report(directory, source):
    rows=[]
    for path in sorted(Path(directory).rglob('queue-pressure-results.jsonl')):
        rows.extend(json.loads(line) for line in path.read_text().splitlines() if line.strip())
    validate(rows,source)
    text='\n## Queue pressure and latency qualification\n\n58 exact-source observations on native amd64/arm64. Four TCP streams, 80ms RTT, 30 measured seconds after 5s warmup, three balanced pairs against immutable v0.3.4 in each direction on 200Mbps/0% and 500Mbps/0% paths. Concurrent hashed TCP and ping probes measure progress and latency. Separate 160Mbps UDP offered to a 50Mbps link must exercise burst admission and bounded drops while preserving sparse progress. Raw observations and samples are in queue-pressure-results.tar.gz. These are short synthetic tests, not WAN or multiday guarantees.\n\n'
    text+='| Arch | Link Mbps | Loss | Direction | Speed ratio | Baseline/candidate drop % | Baseline/candidate p95 ms |\n|---|---:|---|---|---:|---:|---:|\n'
    for r in rows:
        if r['kind']=='queue-pressure-summary': text+=f"| {r['architecture']} | {r['rate']} | {r['loss']} | {'reverse' if r['reverse'] else 'forward'} | {r['geometric_ratio']:.3f} | {100*r['baseline_drop_fraction']:.3f}/{100*r['candidate_drop_fraction']:.3f} | {r['baseline_ping_p95_ms']:.2f}/{r['candidate_ping_p95_ms']:.2f} |\n"
    return text
