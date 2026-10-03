"""Regression coverage for manager transactions and every interactive dispatch."""
import contextlib
import copy
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

spec=importlib.util.spec_from_file_location('rc5_manager',Path(__file__).with_name('manage.py'))
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)

class RC5ManagerTests(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
  self.root=Path(self.tmp.name)
  p=patch.object(m,'ROOT',self.root);p.start();self.addCleanup(p.stop)
 def cfg(self,i=1):
  return m.make_config(i,'tcp','198.51.100.10','203.0.113.20',24000+i,'a'*64,'server')
 def save(self,c):m.atomic(m.confpath(c['tun']['name']),json.dumps(c))
 def test_corrupt_config_is_visible_and_repairable(self):
  self.save(self.cfg());m.atomic(m.confpath('ggs02'),'{broken')
  with self.assertRaises(ValueError):m.configs()
  with contextlib.redirect_stdout(io.StringIO()) as out:
   self.assertEqual(list(m.configs(strict=False)),['ggs01'])
  self.assertIn('ggs02 INVALID',out.getvalue())
  self.assertEqual(list(m.configs(ignore='ggs02')),['ggs01'])
  broken=self.cfg(3);broken['tun'].pop('remote_addr');self.save(broken)
  with contextlib.redirect_stdout(io.StringIO()):self.assertNotIn('ggs03',m.configs(strict=False))
 def test_wildcard_and_transport_forward_collision(self):
  c=self.cfg();self.save(c);other=self.cfg(2)
  other['forwards']=[dict(protocol='tcp',listen='0.0.0.0:24001',target='10.89.1.2:443')]
  with self.assertRaises(ValueError):m.conflict(other)
  other['forwards'][0]['protocol']='udp';m.conflict(other)
  self.assertTrue(m.listeners_overlap('[::]:443','198.51.100.10:443'))
  self.assertFalse(m.listeners_overlap('198.51.100.10:443','198.51.100.11:443'))
 def test_restore_prints_current_join(self):
  c=self.cfg();self.save(c);old=copy.deepcopy(c);old['psk']='b'*64
  m.atomic(self.root/'backups/ggs01-1.json',json.dumps(old))
  def save(c,replace):self.save(c)
  with patch.object(m,'ask',side_effect=['4','1']),patch.object(m,'save_config',save),contextlib.redirect_stdout(io.StringIO()) as out:m.edit('ggs01')
  token=next(x for x in out.getvalue().splitlines() if x.startswith('GGS2.'))
  self.assertEqual(m.decode_join(token)['psk'],old['psk'])
 def test_forward_editor_add_remove_and_empty_errors(self):
  self.save(self.cfg())
  def save(c,replace):self.save(c)
  with patch.object(m,'save_config',save),contextlib.redirect_stdout(io.StringIO()):
   with patch.object(m,'ask',side_effect=['2','udp','0.0.0.0','5353','53']):m.edit('ggs01')
   rule=m.configs()['ggs01']['forwards'][0]
   self.assertEqual(rule,dict(protocol='udp',listen='0.0.0.0:5353',target='10.88.1.2:53'))
   with patch.object(m,'ask',side_effect=['3','1']):m.edit('ggs01')
   self.assertEqual(m.configs()['ggs01']['forwards'],[])
   with patch.object(m,'ask',return_value='3'),self.assertRaisesRegex(ValueError,'No forwarding'):m.edit('ggs01')
   with patch.object(m,'ask',return_value='4'),self.assertRaisesRegex(ValueError,'No configuration backups'):m.edit('ggs01')
 def test_tuning_transaction_and_external_changes(self):
  file=self.root/'sysctl.conf';file.write_text('# existing owner settings\n');file.chmod(0o640)
  values={'net.core.rmem_max':'212992','net.core.wmem_max':'212992','net.ipv4.tcp_mtu_probing':'0'}
  original=dict(values);fail=[False]
  def execute(args,check=True,timeout=90):
   if args[1]=='-n':out=values[args[2]]+'\n'
   elif args[1]=='-p':
    for key in values:values[key]=str(16777216 if key.endswith('_max') else 1)
    if fail[0]:fail[0]=False;raise RuntimeError('partial sysctl apply')
    out=''
   else:key,value=args[2].split('=');values[key]=value;out=''
   return subprocess.CompletedProcess(args,0,out,'')
  with patch.object(m,'SYSCTL_FILE',file),patch.object(m,'run',execute):
   m.tune();m.tune();m.tune(True)
   self.assertEqual(file.read_text(),'# existing owner settings\n');self.assertEqual(file.stat().st_mode&0o777,0o640)
   self.assertEqual(values,original)
   fail[0]=True
   with self.assertRaises(RuntimeError):m.tune()
   self.assertEqual(values,original);self.assertFalse((self.root/'network-before.json').exists())
   m.tune();file.write_text('# externally changed\n');values['net.core.rmem_max']='33554432';m.tune(True)
   self.assertEqual(file.read_text(),'# externally changed\n');self.assertEqual(values['net.core.rmem_max'],'33554432')
 def test_raw_transports_do_not_request_unused_port(self):
  for profile in ('bip','icmp','gre','tcp','udp'):
   values=[profile,'198.51.100.10','203.0.113.20']+(['25001'] if profile in ('tcp','udp') else [])
   with patch.object(m,'configs',return_value={}),patch.object(m,'ask',side_effect=values) as ask,patch.object(m,'save_config') as save,contextlib.redirect_stdout(io.StringIO()):
    m.create_server()
   self.assertEqual(ask.call_count,4 if profile in ('tcp','udp') else 3)
   self.assertEqual(save.call_args.args[0]['transport']['l4_port'],25001 if profile in ('tcp','udp') else 24001)
 def test_peer_health_separates_process_and_peer(self):
  with patch.object(m,'RUN',self.root):
   self.assertEqual(m.peer_health('ggs01'),'HEALTH UNKNOWN')
   for carrier,expected in [({'peer_authenticated':False},'HANDSHAKING'),({'peer_authenticated':True},'PEER RESPONDING'),({'peer_authenticated':True,'path_suspended':True},'NO PEER RESPONSE'),({},'HEALTH UNKNOWN'),([], 'HEALTH UNKNOWN')]:
    m.atomic(self.root/'ggs01.json',json.dumps({'carrier':carrier}))
    self.assertEqual(m.peer_health('ggs01'),expected)
   with patch.object(m.time,'time',return_value=(self.root/'ggs01.json').stat().st_mtime+20):
    self.assertEqual(m.peer_health('ggs01'),'STALE TELEMETRY')
   m.atomic(self.root/'ggs01.json','{broken')
   self.assertEqual(m.peer_health('ggs01'),'HEALTH UNKNOWN')
 def test_every_menu_option_dispatches(self):
  route={'1':'create_server','2':'join_client','3':'status','9':'edit','10':'delete','11':'encode_join',
         '12':'run_logs','13':'diagnose','14':'capacity','15':'capacity','16':'tune','17':'tune',
         '18':'install','19':'rollback','20':'capacity','21':'optimize_existing'}
  for choice in map(str,range(1,22)):
   with self.subTest(choice=choice),contextlib.ExitStack() as stack:
    stack.enter_context(contextlib.redirect_stdout(io.StringIO()))
    stack.enter_context(patch.object(m,'locked',contextlib.nullcontext))
    stack.enter_context(patch.object(m,'select_name',return_value='ggs01'))
    stack.enter_context(patch.object(m,'configs',return_value={'ggs01':self.cfg()}))
    stack.enter_context(patch.object(m,'status'))
    stack.enter_context(patch.object(m.os,'execv'))
    values=[choice]
    if choice in ('4','5','6','7','8'):values+=['all']
    if choice=='10':values+=['DELETE']
    if choice=='18':values+=['/tmp/package']
    if choice=='20':values+=['100']
    values+=['0'];stack.enter_context(patch.object(m,'ask',side_effect=values))
    target='action' if choice in ('4','5','6','7','8') else route[choice]
    mock=stack.enter_context(patch.object(m,target,return_value='test'))
    m.menu();mock.assert_called_once()
    if target=='action':self.assertEqual(mock.call_args.args,({'4':'start','5':'stop','6':'restart','7':'on','8':'off'}[choice],'all'))
    if choice=='17':self.assertEqual(mock.call_args.args,(True,))
    if choice=='20':self.assertEqual(mock.call_args.args,('ggs01','client',(100,),600))
  with patch.object(m,'ask',side_effect=EOFError),patch.object(m,'locked') as lock,contextlib.redirect_stdout(io.StringIO()):
   m.menu();lock.assert_not_called()

if __name__=='__main__':unittest.main()
