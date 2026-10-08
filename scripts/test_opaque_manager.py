"""New wire settings must be explicit, reversible and preserve service state."""
import copy
import json
import subprocess
import unittest
from unittest.mock import patch
from test_manage import ManagerTests, m, EXE


class OpaqueManagerTests(unittest.TestCase):
    setUp = ManagerTests.setUp
    config = ManagerTests.config
    fake_run = ManagerTests.fake_run

    def test_opaque_join_all_carriers_and_dcpi_legacy_rejection(self):
        for profile in ('tcp', 'udp', 'icmp', 'gre', 'ipip', 'dcpi'):
            c = self.config(profile=profile)
            c['transport']['wire_mode'] = 'opaque'
            c['transport'].pop('opaque_session', None)  # Explicit RC4/GGS4 compatibility.
            token = m.encode_join(c)
            self.assertTrue(token.startswith('GGS4.'))
            peer = m.decode_join(token)
            self.assertEqual(peer['transport']['wire_mode'], 'opaque')
            for cfg in (c, peer): m.validate(cfg, EXE)
        c = self.config(profile='dcpi')
        c['transport'].pop('wire_mode')
        with self.assertRaisesRegex(ValueError, 'DCPI requires'):
            m.decode_join(m.encode_join(c))

    def test_opaque_menu_preserves_stop_and_restores_failed_change(self):
        c = self.config(profile='udp')
        m.atomic(m.confpath('ggs01'), json.dumps(c))
        with patch.object(m, 'ask', return_value='opaque'), patch.object(m, 'run', self.fake_run), patch.object(m, 'wait_service', lambda n: None):
            m.configure_opaque('ggs01')
        saved = json.loads(m.confpath('ggs01').read_text())
        self.assertEqual(saved['transport']['wire_mode'], 'opaque')
        self.assertEqual(saved['transport']['opaque_session'], 'challenge')
        self.assertFalse(self.running)
        self.running.add('ggs01'); self.fail_restart = True
        with patch.object(m, 'ask', return_value='legacy'), patch.object(m, 'run', self.fake_run), patch.object(m, 'wait_service', lambda n: None), self.assertRaises(RuntimeError):
            m.configure_opaque('ggs01')
        self.assertEqual(json.loads(m.confpath('ggs01').read_text()), saved)

    def test_dcpi_does_not_ask_for_port_or_allow_duplicate_peer(self):
        values = ['dcpi', '198.51.100.10', '203.0.113.20']
        with patch.object(m, 'configs', return_value={}), patch.object(m, 'ask', side_effect=values) as ask, patch.object(m, 'save_config') as save:
            m.create_server()
        self.assertEqual(ask.call_count, 3)
        c = save.call_args.args[0]
        self.assertEqual(c['transport']['wire_mode'], 'opaque')
        m.atomic(m.confpath('ggs01'), json.dumps(c))
        other = copy.deepcopy(c); other['tun']['name'] = 'ggs02'; other['tun']['local_addr'] = '10.89.1.1'
        with self.assertRaisesRegex(ValueError, 'One raw tunnel'): m.conflict(other)

    def test_path_test_never_changes_configuration(self):
        c = self.config(profile='bip'); m.atomic(m.confpath('ggs01'), json.dumps(c))
        before = m.confpath('ggs01').read_bytes()
        with patch.object(m, 'active', return_value=True), patch.object(m, 'RUN', self.root), patch.object(m, 'run', return_value=subprocess.CompletedProcess([], 0, '', '')) as command, patch.object(m, 'save_config') as save:
            m.path_test('ggs01')
        self.assertEqual(command.call_count, 3); save.assert_not_called()
        self.assertEqual(m.confpath('ggs01').read_bytes(), before)

    def test_generic_health_detects_authenticated_silence(self):
        with patch.object(m, 'RUN', self.root):
            m.atomic(self.root/'ggs01.json', json.dumps(dict(peer_authenticated=True, peer_silence_ms=91000)))
            self.assertEqual(m.peer_health('ggs01'), 'NO PEER RESPONSE')
