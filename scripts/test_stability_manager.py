"""Cloud-only installer interruption/fault and extended config regressions."""
import contextlib
import importlib.util
import io
import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

spec=importlib.util.spec_from_file_location('stability_manager',Path(__file__).with_name('manage.py'))
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)

class StabilityManagerTests(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
  self.root=Path(self.tmp.name);self.stack=contextlib.ExitStack();self.addCleanup(self.stack.close)
  for key,value in dict(OPT=self.root/'opt',ROOT=self.root/'config',UNITS=self.root/'units',WRAPPER=self.root/'bin/ggstunnel').items():self.stack.enter_context(patch.object(m,key,value))
  self.stack.enter_context(contextlib.redirect_stdout(io.StringIO()))
 def config(self,profile='bip'):
  return m.make_config(1,profile,'198.51.100.10','203.0.113.20',24001,'a'*64,'server')
 def test_extended_join_roundtrip_and_wrong_types(self):
  for profile,wire,session in [('bip','legacy',''),('bip','compact',''),('udp','opaque','challenge')]:
   c=self.config(profile)
   c['transport'].update(path_mtu=True,session_max_age_sec=600)
   if wire=='compact':c['transport']['bip_wire_mode']='compact'
   if wire=='opaque':c['transport'].update(wire_mode=wire,opaque_session=session)
   c['performance']['queue_max_age_ms']=2000
   code=m.encode_join(c);self.assertTrue(code.startswith('GGS6.'))
   other=m.decode_join(code)
   self.assertEqual(other['transport']['path_mtu'],True)
   self.assertEqual(other['transport']['session_max_age_sec'],600)
   self.assertEqual(other['performance']['queue_max_age_ms'],2000)
  c['transport']['path_mtu']='true'
  # Encoder normalizes UI boolean, decoder strictly rejects wire type abuses.
  c['performance']['queue_max_age_ms']=True
  with self.assertRaisesRegex(ValueError,'setting types'):m.decode_join(m.encode_join(c))
 def fixture(self):
  first=m.OPT/'releases/first';second=m.OPT/'releases/second'
  first.mkdir(parents=True);second.mkdir()
  m.symlink(first,m.OPT/'current');m.symlink(second,m.OPT/'previous')
  m.atomic(m.UNITS/'ggstunnel@.service','old unit',0o640)
  m.atomic(m.WRAPPER,'old wrapper',0o750)
  return first,second
 def test_interrupted_upgrade_recovers_complete_previous_state(self):
  first,second=self.fixture();m.begin_install_transaction(['ggs01'])
  m.symlink(second,m.OPT/'current');m.symlink(first,m.OPT/'previous')
  m.atomic(m.UNITS/'ggstunnel@.service','partial unit');m.atomic(m.WRAPPER,'partial wrapper')
  calls=[]
  def run(args,check=True,timeout=90):
   calls.append(args);return subprocess.CompletedProcess(args,0,'','')
  with patch.object(m,'run',run),patch.object(m,'wait_service',lambda name:None):m.recover_install_transaction()
  self.assertEqual((m.OPT/'current').resolve(),first)
  self.assertEqual((m.OPT/'previous').resolve(),second)
  self.assertEqual((m.UNITS/'ggstunnel@.service').read_text(),'old unit')
  self.assertEqual(m.WRAPPER.read_text(),'old wrapper');self.assertEqual(m.WRAPPER.stat().st_mode&0o777,0o750)
  self.assertFalse((m.OPT/'install-transaction.json').exists())
  self.assertIn(['systemctl','restart','ggstunnel@ggs01.service'],calls)
 def test_disk_full_before_journal_has_no_live_mutations(self):
  first,second=self.fixture()
  with patch.object(m,'atomic',side_effect=OSError(28,'disk full')):
   with self.assertRaises(OSError):m.begin_install_transaction(['ggs01'])
  self.assertEqual((m.OPT/'current').resolve(),first)
  self.assertEqual(m.WRAPPER.read_text(),'old wrapper')
 def test_failed_recovery_retains_journal_for_next_attempt(self):
  first,second=self.fixture();m.begin_install_transaction(['ggs01']);m.symlink(second,m.OPT/'current')
  with patch.object(m,'run',return_value=subprocess.CompletedProcess([],1,'','failure')):
   with self.assertRaisesRegex(RuntimeError,'journal retained'):m.recover_install_transaction()
  self.assertEqual((m.OPT/'current').resolve(),first)
  self.assertTrue((m.OPT/'install-transaction.json').exists())
 def test_unsafe_recovery_target_rejected_before_mutation(self):
  first,_=self.fixture();m.begin_install_transaction([])
  path=m.OPT/'install-transaction.json';data=json.loads(path.read_text());data['current']=str(self.root);path.write_text(json.dumps(data))
  with self.assertRaisesRegex(ValueError,'Unsafe'):m.recover_install_transaction()
  self.assertEqual((m.OPT/'current').resolve(),first)
 def test_stability_menu_saves_and_emits_extended_join(self):
  c=self.config()
  with patch.object(m,'configs',return_value={'ggs01':c}),patch.object(m,'ask',side_effect=['600','2000','on']),patch.object(m,'save_config') as save:
   m.configure_stability('ggs01')
  self.assertEqual(c['transport']['session_max_age_sec'],600);self.assertTrue(c['transport']['path_mtu'])
  save.assert_called_once_with(c,True)

if __name__=='__main__':unittest.main()
