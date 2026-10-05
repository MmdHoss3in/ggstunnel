import unittest
from cloud_extended import whole_transfer_receiver_bytes

class ApplicationAccountingTests(unittest.TestCase):
    def test_warmup_reset_cannot_be_used_as_whole_transfer(self):
        report={'start':{'test_start':{'omit':2}},
                'intervals':[{'sum':{'bytes':2097152,'omitted':True}},
                             {'sum':{'bytes':20316160,'omitted':False}}],
                'end':{'sum_received':{'bytes':20316160}}}
        self.assertIsNone(whole_transfer_receiver_bytes(report))

    def test_zero_omit_requires_consistent_receiver_accounting(self):
        report={'start':{'test_start':{'omit':0}},
                'intervals':[{'sum':{'bytes':100}}, {'sum':{'bytes':300}}],
                'end':{'sum_received':{'bytes':400}}}
        self.assertEqual(whole_transfer_receiver_bytes(report),400)
        report['end']['sum_received']['bytes']=399
        with self.assertRaisesRegex(RuntimeError,'whole-transfer accounting'):
            whole_transfer_receiver_bytes(report)
