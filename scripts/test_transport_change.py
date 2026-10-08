"""State-preserving carrier migration and explicit challenge-version joins."""
import copy
import json
import unittest
from unittest.mock import patch
from test_manage import ManagerTests, m, EXE


class TransportChangeTests(unittest.TestCase):
    setUp = ManagerTests.setUp
    config = ManagerTests.config
    fake_run = ManagerTests.fake_run

    def test_challenge_join_and_old_dcpi_are_explicit(self):
        for profile in ('tcp','udp','icmp','gre','ipip','dcpi'):
            c=self.config(profile=profile)
            c['transport'].update(wire_mode='opaque',opaque_session='challenge')
            token=m.encode_join(c)
            self.assertTrue(token.startswith('GGS5.'))
            other=m.decode_join(token)
            self.assertEqual(other['transport']['opaque_session'],'challenge')
            for cfg in (c,other):m.validate(cfg,EXE)
            c['transport'].pop('opaque_session')
            old=m.decode_join(m.encode_join(c))
            self.assertNotIn('opaque_session',old['transport'])
            m.validate(old,EXE)

    def test_switch_preserves_routes_identity_forwards_and_stopped_state(self):
        c=self.config(profile='bip')
        c['transport']['bip_wire_mode']='compact'
        c['tun']['routes']=['10.120.0.0/16']
        c['forwards']=[dict(protocol='tcp',listen='0.0.0.0:24444',target='10.88.1.2:443')]
        m.atomic(m.confpath('ggs01'),json.dumps(c))
        with patch.object(m,'ask',return_value='dcpi'),patch.object(m,'run',self.fake_run),patch.object(m,'wait_service',lambda n:None):
            m.configure_transport('ggs01')
        saved=json.loads(m.confpath('ggs01').read_text())
        self.assertEqual(saved['tun'],c['tun'])
        self.assertEqual(saved['forwards'],c['forwards'])
        self.assertEqual(saved['psk'],c['psk'])
        self.assertEqual(saved['real'],c['real'])
        self.assertEqual(saved['tuner']['mode'],'manual')
        self.assertNotIn('bip_delivery',saved['transport'])
        self.assertNotIn('bip_wire_mode',saved['transport'])
        self.assertEqual(saved['transport']['opaque_session'],'challenge')
        self.assertFalse(self.running)
        self.assertTrue(list((self.root/'backups').glob('ggs01-*.json')))

    def test_running_restart_failure_restores_entire_config(self):
        c=self.config(profile='dcpi');m.atomic(m.confpath('ggs01'),json.dumps(c))
        self.running.add('ggs01');self.fail_restart=True
        with patch.object(m,'ask',return_value='bip'),patch.object(m,'run',self.fake_run),patch.object(m,'wait_service',lambda n:None),self.assertRaises(RuntimeError):
            m.configure_transport('ggs01')
        self.assertEqual(json.loads(m.confpath('ggs01').read_text()),c)
        self.assertIn('ggs01',self.running)

    def test_port_collision_and_invalid_choice_do_not_change_config(self):
        original=self.config(profile='bip');m.atomic(m.confpath('ggs01'),json.dumps(original))
        other=self.config(2,'udp');other['real']['listen_addr']='0.0.0.0:25001'
        m.atomic(m.confpath('ggs02'),json.dumps(other))
        with patch.object(m,'ask',side_effect=['udp','opaque','25001']),self.assertRaises(ValueError):m.configure_transport('ggs01')
        self.assertEqual(json.loads(m.confpath('ggs01').read_text()),original)
        with patch.object(m,'ask',return_value='invalid'),self.assertRaises(ValueError):m.configure_transport('ggs01')
        self.assertEqual(json.loads(m.confpath('ggs01').read_text()),original)

    def test_generic_health_and_null_stats(self):
        with patch.object(m,'RUN',self.root):
            for carrier in (None,{}):
                m.atomic(self.root/'ggs01.json',json.dumps(dict(profile='dcpi',carrier=carrier,peer_authenticated=False)))
                self.assertEqual(m.peer_health('ggs01'),'WAITING FOR AUTHENTICATED PEER')
            m.atomic(self.root/'ggs01.json',json.dumps(dict(profile='dcpi',peer_authenticated=True,peer_silence_ms=91000)))
            self.assertEqual(m.peer_health('ggs01'),'NO PEER RESPONSE')
