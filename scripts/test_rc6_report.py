import copy
import math
import statistics
import unittest

import rc6_report as report

SOURCE='a'*40

def fixture():
    rows=[]
    identity=[{'ifindex':1,'routes':[]},{'ifindex':2,'routes':[]}]
    for arch in report.ARCHES:
        for profile in report.PROFILES:
            rows.append(dict(kind='renewal',architecture=arch,profile=profile,source_commit=SOURCE,status='pass',
                device_before=copy.deepcopy(identity),device_after=copy.deepcopy(identity),pids_before=[100,101],
                renewals=[2,1],end_snapshot={'peers':[{'pid':100},{'pid':101}]},progress={'verified_frames':50,'max_gap_sec':1}))
        for profile,wire in [('bip','legacy'),('bip','compact'),('udp','opaque')]:
            def snapshot(payload):return {'peers':[{'telemetry':{'path_mtu_state':'confirmed','effective_frame_payload':payload}} for _ in range(2)]}
            rows.append(dict(kind='path-mtu',architecture=arch,profile=profile,wire=wire,source_commit=SOURCE,status='pass',
                device_before=copy.deepcopy(identity),device_after=copy.deepcopy(identity),initial_blackhole=snapshot(1048 if profile=='bip' else 1134),
                raised_path=snapshot(1348),reduced_path=snapshot(844 if profile=='bip' else 929),blackhole_capacity=[{'received_mbps':100},{'received_mbps':100}]))
        for loss,rate in report.CASES:
            for reverse in (False,True):
                count=3 if loss=='0%' else 5
                speed=(180 if rate==200 else 380) if loss=='0%' else 100 if loss=='1%' else 50
                values={'rc5':[speed]*count,'candidate':[speed]*count}
                for version in values:
                    for trial in range(count):
                        rows.append(dict(kind='fixed-performance',architecture=arch,loss=loss,rate=rate,reverse=reverse,version=version,trial=trial,
                            source_commit=SOURCE,runtime_source_commit=report.BASELINE_SOURCE if version=='rc5' else SOURCE,status='pass',recipe='steady-v2',
                            seconds=20 if loss=='0%' else 45,warmup_sec=2 if loss=='0%' else 15,received_mbps=speed,same_processes=True,
                            recoveries=[0,0],progress={'verified_frames':50,'max_gap_sec':1}))
                rows.append(dict(kind='fixed-performance-summary',architecture=arch,loss=loss,rate=rate,reverse=reverse,
                    source_commit=SOURCE,status='pass',recipe='steady-v2',values=values,paired_ratios=[1]*count,geometric_ratio=1,baseline_cv=0))
    return rows

class ReportTests(unittest.TestCase):
    def test_complete_exact_source(self):
        rows=fixture()
        self.assertEqual(len(rows),164)
        self.assertEqual(len(report.validate_rows(rows,SOURCE)),164)

    def test_missing_duplicate_failed_or_wrong_source(self):
        for mutation in ('missing','duplicate','failed','source'):
            with self.subTest(mutation=mutation):
                rows=fixture()
                if mutation=='missing':rows.pop()
                elif mutation=='duplicate':rows.append(rows[0])
                elif mutation=='failed':rows[0]['status']='fail'
                else:rows[0]['source_commit']='b'*40
                with self.assertRaises(ValueError):report.validate_rows(rows,SOURCE)

    def test_cancellation_identity_and_path_evidence(self):
        for mutation in ('device','pid','oversize','unauthenticated'):
            with self.subTest(mutation=mutation):
                rows=fixture()
                if mutation=='device':rows[0]['device_after'][0]['ifindex']=7
                elif mutation=='pid':rows[0]['end_snapshot']['peers'][0]['pid']=999
                else:
                    row=next(r for r in rows if r['kind']=='path-mtu')
                    stats=row['initial_blackhole']['peers'][0]['telemetry']
                    if mutation=='oversize':stats['effective_frame_payload']=1348
                    else:stats['path_mtu_state']='unconfirmed'
                with self.assertRaises(ValueError):report.validate_rows(rows,SOURCE)

    def test_changed_recipe_runtime_or_corrupt_progress(self):
        for field,value in [('warmup_sec',2),('seconds',20),('runtime_source_commit','b'*40),('recoveries',[1,0]),('received_mbps',math.nan),('same_processes',False)]:
            with self.subTest(field=field):
                rows=fixture();row=next(r for r in rows if r['kind']=='fixed-performance' and r['loss']=='1%' and r['version']=='candidate')
                row[field]=value
                with self.assertRaises(ValueError):report.validate_rows(rows,SOURCE)

    def test_recompute_summary_instead_of_trusting_pass(self):
        rows=fixture();row=next(r for r in rows if r['kind']=='fixed-performance-summary')
        row['geometric_ratio']=1.01
        with self.assertRaises(ValueError):report.validate_rows(rows,SOURCE)

    def test_high_variance_fails_even_with_equal_candidate_speed(self):
        rows=fixture();speeds=[80,150,90,170,100]
        for row in rows:
            if row.get('loss')!='1%' or row.get('architecture')!='amd64' or row.get('reverse') is not True:continue
            if row['kind']=='fixed-performance':row['received_mbps']=speeds[row['trial']]
            else:
                row['values']={v:speeds[:] for v in ('rc5','candidate')}
                row['baseline_cv']=statistics.stdev(speeds)/statistics.mean(speeds)
        with self.assertRaisesRegex(ValueError,'variance'):report.validate_rows(rows,SOURCE)

if __name__=='__main__':unittest.main()
