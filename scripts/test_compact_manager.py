import unittest
import json
from unittest.mock import patch
from test_manage import ManagerTests, m, EXE

class CompactManagerTests(unittest.TestCase):
 setUp=ManagerTests.setUp
 config=ManagerTests.config
 fake_run=ManagerTests.fake_run
 def test_ipip_join_and_same_peer_conflict(self):
  c=self.config(profile='ipip');peer=m.decode_join(m.encode_join(c))
  self.assertEqual(peer['profile'],'ipip');m.validate(c,EXE);m.validate(peer,EXE)
  m.atomic(m.confpath('ggs01'),json.dumps(c))
  other=self.config(2,'ipip');other['real']['peer_ip']=c['real']['peer_ip']
  with self.assertRaisesRegex(ValueError,'One raw tunnel'):m.conflict(other)
 def test_compact_join_preserves_mode_and_payload(self):
  c=self.config(profile='bip');c['transport']['bip_wire_mode']='compact'
  c['tun']['mtu']=1348;c['performance']['max_frame_payload']=1348
  token=m.encode_join(c);self.assertTrue(token.startswith('GGS3.'))
  peer=m.decode_join(token)
  self.assertEqual(peer['transport']['bip_wire_mode'],'compact')
  self.assertEqual(peer['performance']['max_frame_payload'],1348)
  self.assertEqual(peer['tun']['mtu'],1348)
  m.validate(c,EXE);m.validate(peer,EXE)
 def test_wire_menu_preserves_stop_and_legacy_rollback(self):
  c=self.config(profile='bip');m.atomic(m.confpath('ggs01'),json.dumps(c))
  with patch.object(m,'ask',side_effect=['compact','1348']),patch.object(m,'run',self.fake_run),patch.object(m,'wait_service',lambda n:None):m.configure_wire('ggs01')
  compact=json.loads(m.confpath('ggs01').read_text());self.assertEqual(compact['transport']['bip_wire_mode'],'compact');self.assertFalse(self.running)
  with patch.object(m,'ask',side_effect=['legacy','1280']),patch.object(m,'run',self.fake_run),patch.object(m,'wait_service',lambda n:None):m.configure_wire('ggs01')
  legacy=json.loads(m.confpath('ggs01').read_text());self.assertNotIn('bip_wire_mode',legacy['transport']);self.assertTrue(m.encode_join(legacy).startswith('GGS2.'))
 def test_wire_menu_rejects_tcp_and_bad_mode(self):
  m.atomic(m.confpath('ggs01'),json.dumps(self.config()))
  with self.assertRaises(ValueError):m.configure_wire('ggs01')
  m.atomic(m.confpath('ggs01'),json.dumps(self.config(profile='bip')))
  with patch.object(m,'ask',return_value='invalid'),self.assertRaises(ValueError):m.configure_wire('ggs01')
