import copy
import unittest

from queue_pressure_report import BASELINE_SOURCE, CASES, summary, validate

SOURCE='a'*40


def fixture():
    rows=[]
    common=dict(status='pass',source_commit=SOURCE,runtime_source_commit=SOURCE,same_processes=True,recoveries=[0,0],
        progress={'verified_frames':300,'max_gap_sec':.1},max_rss_mib=32,peak_queue_bytes=100000,peak_flow_packets=300,
        ping_p95_ms=90,cpu_cores=.5,drop_fraction=.01,queue_drops=[100,0],ingress_packets=[10000,0],burst_admissions=200)
    for arch in ('amd64','arm64'):
        for rate,loss in CASES:
            for reverse in (False,True):
                group=[]
                for version in ('v0.3.4','candidate'):
                    for trial in range(3):
                        row=copy.deepcopy(common)
                        row.update(architecture=arch,kind='queue-pressure',rate=rate,loss=loss,reverse=reverse,version=version,trial=trial,received_mbps=rate*.8,
                            runtime_source_commit=BASELINE_SOURCE if version=='v0.3.4' else SOURCE)
                        group.append(row); rows.append(row)
                aggregate=dict(architecture=arch,kind='queue-pressure-summary',rate=rate,loss=loss,reverse=reverse,status='pass',source_commit=SOURCE,runtime_source_commit=SOURCE)
                aggregate.update(summary(group)); rows.append(aggregate)
        row=copy.deepcopy(common)
        row.update(architecture=arch,kind='queue-overload',received_mbps=40)
        rows.append(row)
    return rows


class QueuePressureReportTests(unittest.TestCase):
    def test_complete_native_source(self):
        self.assertEqual(len(validate(fixture(),SOURCE)),58)

    def test_incomplete_duplicate_wrong_runtime_and_failed(self):
        for mode in ('missing','duplicate','runtime','failed'):
            with self.subTest(mode=mode):
                rows=fixture()
                if mode=='missing': rows.pop()
                elif mode=='duplicate': rows.append(rows[0])
                elif mode=='runtime': rows[0]['runtime_source_commit']=SOURCE
                else: rows[0]['status']='fail'
                with self.assertRaises(ValueError): validate(rows,SOURCE)

    def test_latency_drop_cpu_and_speed_regressions(self):
        for name,value in (('ping_p95_ms',200),('drop_fraction',.1),('cpu_cores',2),('received_mbps',50)):
            with self.subTest(name=name):
                rows=fixture()
                for row in rows:
                    if row.get('version')=='candidate' and row.get('rate')==200 and row.get('reverse') is False and row['architecture']=='amd64': row[name]=value
                with self.assertRaises(ValueError): validate(rows,SOURCE)

    def test_forged_summary_unexercised_overload_and_memory(self):
        for mode in ('summary','overload','memory','nan'):
            with self.subTest(mode=mode):
                rows=fixture()
                if mode=='summary': next(r for r in rows if r['kind']=='queue-pressure-summary')['geometric_ratio']=2
                elif mode=='overload': rows[-1]['burst_admissions']=0
                elif mode=='memory': rows[-1]['peak_queue_bytes']=9<<20
                else: rows[0]['cpu_cores']=float('nan')
                with self.assertRaises(ValueError): validate(rows,SOURCE)
