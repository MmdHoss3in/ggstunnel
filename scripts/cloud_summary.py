"""Preserve every observation and report conditional exact binomial bounds."""
import json
import math
from pathlib import Path
import re
import statistics

ROOT = Path(__file__).resolve().parents[1]


def lower_bound(successes, total, alpha=.05):
    if not successes or not total: return 0.0
    if successes == total: return alpha ** (1 / total)
    def tail(p):
        return sum(math.comb(total, k) * p ** k * (1 - p) ** (total - k) for k in range(successes, total + 1))
    low, high = 0., 1.
    for _ in range(80):
        middle = (low + high) / 2
        if tail(middle) < alpha: low = middle
        else: high = middle
    return low


def main():
    rows = []
    for path in sorted((ROOT / 'collected').rglob('results.jsonl')):
        for line in path.read_text().splitlines():
            if line.strip(): rows.append(json.loads(line))
    trials = [r for r in rows if r.get('kind') == 'recovery' and r.get('scenario') == 'blackhole3']
    passed = sum(r['status'] == 'pass' for r in trials)
    unique = len({r['trial'] for r in trials}) == len(trials)
    summary = dict(recovery_trials=len(trials), recovery_successes=passed,
                   exact_one_sided_95_lower_bound=lower_bound(passed, len(trials)),
                   planned_60_trials_complete=len(trials) == 60 and unique and {r['trial'] for r in trials} == set(range(60)),
                   scope='A 60-second synthetic BIP transfer with a three-second outage, 200Mbps link and 80ms RTT.',
                   independence_assumed_not_proven=True, multi_day_uptime_claim=False,
                   architecture_counts={arch: sum(r.get('architecture') == arch for r in rows) for arch in ('amd64', 'arm64')})
    failures = [r for r in rows if r.get('status') in ('fail', 'target_miss', 'resource_limit')]
    summary['failed_or_target_missed_cases'] = len(failures)
    counts = {kind: sum(r.get('kind') == kind for r in rows) for kind in
              ('baseline', 'performance', 'resource_cycle', 'resource_integrity', 'resource_summary', 'lifecycle', 'steady_loss', 'compatibility','capacity_baseline','capacity','capacity_hold')}
    counts['impairments'] = sum(r.get('kind') == 'recovery' and r.get('scenario') != 'blackhole3' for r in rows)
    summary['observation_counts'] = counts
    expected = dict(baseline=60, performance=180, resource_cycle=90, resource_integrity=2,
                    resource_summary=4, lifecycle=30, impairments=12, steady_loss=18, compatibility=6,
                    capacity_baseline=16,capacity=32,capacity_hold=2)
    summary['planned_observations_complete'] = all(counts[k] == n for k, n in expected.items()) and summary['planned_60_trials_complete']
    compatible=[r for r in rows if r.get('kind')=='compatibility']
    required_compatibility={(tag,peer) for tag in ('v0.3.0-rc4','v0.3.0','v0.3.1-rc1') for peer in (0,1)}
    summary['compatibility_scenarios_complete']=len(compatible)==6 and {(r.get('legacy_tag'),r.get('legacy_peer')) for r in compatible}==required_compatibility
    summary['planned_observations_complete'] = summary['planned_observations_complete'] and summary['compatibility_scenarios_complete']
    capacities=[r for r in rows if r.get('kind')=='capacity']
    capacity_keys={(r.get('rate_mbps'),r.get('rtt_ms'),r.get('reverse'),r.get('repeat')) for r in capacities}
    required_capacity={(rate,rtt,reverse,repeat) for rate in (100,200,500,1000) for rtt in (20,80) for reverse in (False,True) for repeat in range(2)}
    holds=[r for r in rows if r.get('kind')=='capacity_hold']
    summary['capacity_scenarios_complete']=len(capacities)==32 and capacity_keys==required_capacity and len(holds)==2 and {r.get('architecture') for r in holds}=={'amd64','arm64'}
    summary['planned_observations_complete'] = summary['planned_observations_complete'] and summary['capacity_scenarios_complete']
    boundary_files = list((ROOT / 'collected').rglob('boundaries.log'))
    diagnostic_files = list((ROOT / 'collected').rglob('resources.log'))
    boundary_logs = '\n'.join(p.read_text() for p in boundary_files)
    diagnostic_logs = '\n'.join(p.read_text() for p in diagnostic_files)
    expected_packages = ('carrier', 'frame', 'session', 'engine')
    summary['boundary_packages_passed'] = all(re.search(r'^ok\s+ggstunnel/internal/' + package + r'\s', boundary_logs, re.M) for package in expected_packages)
    summary['diagnostic_resource_test_passed'] = bool(re.search(r'^ok\s+ggstunnel/internal/carrier\s', diagnostic_logs, re.M))
    summary['go_log_failure_detected'] = bool(re.search(r'(^FAIL\b|--- FAIL:|WARNING: DATA RACE|panic:)', boundary_logs + diagnostic_logs, re.M))
    version = (ROOT / 'internal/version/VERSION').read_text().strip()
    text = '# '+version+' extended short cloud validation\n\n'
    text += 'This report describes short synthetic tests of the exact candidate runtime with routed receiver-path shaping and offloads disabled. It does not establish multi-day uptime or Iran/foreign WAN reliability. All failures and target misses are retained.\n\n'
    text += f"Planned observation counts complete: {summary['planned_observations_complete']}; counts: {json.dumps(counts)}. Missing observations do not count as passes.\n\n"
    text += f"Go boundary packages passed: {summary['boundary_packages_passed']}; diagnostic resource test passed: {summary['diagnostic_resource_test_passed']}; Go log failure detected: {summary['go_log_failure_detected']}. Logs must be inspected alongside Actions job conclusions.\n\n"
    text += f"Recovery trials: {passed}/{len(trials)} passed; 60 planned runs complete: {summary['planned_60_trials_complete']}.\n\n"
    if summary['planned_60_trials_complete']:
        text += f"Conditional exact one-sided 95% lower confidence bound: {100*summary['exact_one_sided_95_lower_bound']:.3f}% success for the specified short experiment, assuming independent trials and a fixed distribution. Seed changes and separate runners do not prove those assumptions. This is not a multi-day survival probability.\n\n"
    else: text += 'Incomplete planned sample: no 60-trial reliability demonstration is claimed.\n\n'
    text += '## Throughput\n\n| Carrier | Link Mbps | RTT ms | Direction | Samples | Min / median / max Mbps | Median direct baseline Mbps | Target misses/errors |\n|---|---:|---:|---|---:|---|---:|---:|\n'
    performances = [r for r in rows if r.get('kind') == 'performance']
    for key in sorted({(r['profile'], r['rate_mbps'], r['rtt_ms'], r['reverse']) for r in performances}):
        group = [r for r in performances if (r['profile'], r['rate_mbps'], r['rtt_ms'], r['reverse']) == key]
        rates = [r['received_mbps'] for r in group if 'received_mbps' in r]
        baseline = [r['baseline_mbps'] for r in group]
        values = '/'.join(f'{v:.2f}' for v in (min(rates), statistics.median(rates), max(rates))) if rates else 'none'
        text += f"| {key[0]} | {key[1]} | {key[2]} | {'reverse' if key[3] else 'forward'} | {len(group)} | {values} | {statistics.median(baseline):.2f} | {sum(r['status']!='pass' for r in group)} |\n"
    text += '\n## Impairments and failures\n\n'
    for row in rows:
        if row.get('kind') == 'recovery' and row.get('scenario') != 'blackhole3':
            text += f"- {row['scenario']}: {row['status']}; first existing-flow response after injection/restoration={row.get('flow_recovery_sec', 'unavailable')}s; longest response gap={row.get('max_gap_sec', 'unavailable')}s; supervisor restarts={row.get('supervisor_restarts', 'not supervised')}; {row.get('error', '')}\n"
    text += '\nAn impairment pass means the specified connectivity/integrity criteria passed, not that throughput remained stable. Loss/reorder/asymmetry/rate-limit case averages include the clean period before injection and cannot be interpreted as steady impaired throughput. First response after injection does not bound subsequent stalls; inspect longest response gaps. The rate-limit case uses netem shaping on all outer traffic, not a protocol-specific ICMP policer.\n'
    for row in failures:
        text += '- ' + json.dumps(row, ensure_ascii=False) + '\n'
    text += '\n## Resource observations\n\n'
    for row in rows:
        if row.get('kind') in ('resource_summary', 'resource_integrity'):
            text += '- ' + json.dumps(row) + '\n'
    text += '\nRSS/FD measurements are short screening observations, not a proof of absence of leaks. In-process Go heap/goroutine tests, if present, are separate from measurements of the exact release executable.\n'
    text += '\n## Steady impaired transfers and compatibility\n\n'
    for row in rows:
        if row.get('kind') in ('steady_loss','compatibility'): text += '- ' + json.dumps(row) + '\n'
    text += '\n## Capacity scaling and sustained load\n\n'
    text += '100/200/500/1000Mbps links, 20/80ms RTT, both directions, eight TCP streams, two fresh runs per scenario. Receiver throughput is measured; a link rate is not a promised tunnel rate. The separate ten-minute holds use eight streams on a 500Mbps/80ms path, the same installed processes, receiver-side interval JSON, one-minute medians >=200Mbps, late median >=75% of early median, concurrent hashed-flow progress, and RSS <256MiB. These are short load tests, not validated acceleration models for days of uptime.\n\n'
    for row in rows:
        if row.get('kind') in ('capacity','capacity_hold'):
            concise={k:v for k,v in row.items() if k!='end_snapshot'}
            text += '- ' + json.dumps(concise) + '\n'
    (ROOT / 'extended-report.md').write_text(text)
    (ROOT / 'extended-summary.json').write_text(json.dumps(summary, indent=2))
    print(json.dumps(summary, indent=2))
    if failures or not summary['planned_observations_complete'] or not summary['boundary_packages_passed'] or not summary['diagnostic_resource_test_passed'] or summary['go_log_failure_detected']:
        raise SystemExit('Extended release gate failed; inspect retained observations')


if __name__ == '__main__': main()
