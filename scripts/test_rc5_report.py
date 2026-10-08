"""Publication rejects missing, duplicated, mismatched or regressed evidence."""
import copy
import unittest
from rc5_report import ARCHES, PROFILES, CASES, BASELINE, validate_rows


class RC5ReportTests(unittest.TestCase):
    def observations(self):
        rows = []
        for arch in ARCHES:
            for profile in PROFILES:
                rows.append(dict(kind='rc5-lifecycle', architecture=arch, profile=profile,
                                 source_commit='candidate', runtime_source_commit='candidate', status='pass',
                                 restart_recovery_sec=[1] * 10, speeds=[dict(received_mbps=100)] * 2,
                                 udp_speeds=[dict(received_mbps=20, lost_percent=.2)] * 2,
                                 end_snapshot=dict(peers=[dict(telemetry=dict(peer_authenticated=True,
                                     internal_recoveries=0, carrier=dict(session_mode='challenge')))] * 2)))
            for loss, seconds, reverse in CASES:
                for version in ('rc4', 'candidate'):
                    rows.append(dict(kind='rc5-loss-ab', architecture=arch, version=version,
                                     loss=loss, seconds=seconds, reverse=reverse, source_commit='candidate',
                                     runtime_source_commit=BASELINE if version == 'rc4' else 'candidate',
                                     status='observed' if version == 'rc4' else 'pass', received_mbps=30,
                                     same_processes=True, recoveries=[0, 0],
                                     progress=dict(verified_frames=100, max_gap_sec=.5)))
        return rows

    def test_complete_evidence_passes(self):
        validate_rows(self.observations(), 'candidate')

    def test_missing_duplicate_failed_wrong_source_or_runtime_rejected(self):
        rows = self.observations()
        for invalid in (rows[:-1], rows + [copy.deepcopy(rows[0])]):
            with self.assertRaises(ValueError): validate_rows(invalid, 'candidate')
        for field, value in (('source_commit', 'other'), ('runtime_source_commit', BASELINE), ('status', 'fail')):
            invalid = copy.deepcopy(rows); invalid[0][field] = value
            with self.assertRaises(ValueError): validate_rows(invalid, 'candidate')

    def test_false_pass_labels_do_not_bypass_measured_loss_gate(self):
        rows = self.observations()
        position = next(i for i, row in enumerate(rows) if row.get('version') == 'candidate')
        for field, value in (('received_mbps', 26), ('same_processes', False), ('recoveries', [1, 0]),
                             ('progress', dict(verified_frames=9, max_gap_sec=.1)),
                             ('progress', dict(verified_frames=100, max_gap_sec=6))):
            invalid = copy.deepcopy(rows); invalid[position][field] = value
            with self.assertRaises(ValueError): validate_rows(invalid, 'candidate')

    def test_lifecycle_health_and_restart_evidence_required(self):
        rows = self.observations()
        for field, value in (('restart_recovery_sec', [1] * 9), ('speeds', [dict(received_mbps=29)] * 2),
                             ('udp_speeds', [dict(received_mbps=20, lost_percent=2)] * 2),
                             ('end_snapshot', dict(peers=[]))):
            invalid = copy.deepcopy(rows); invalid[0][field] = value
            with self.assertRaises(ValueError): validate_rows(invalid, 'candidate')
