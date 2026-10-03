import copy
import importlib.util
import hashlib
import shutil
import json
import subprocess
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch

spec=importlib.util.spec_from_file_location('manage',Path(__file__).with_name('manage.py'))
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
EXE=Path(__file__).resolve().parents[1]/'dist'/'ggstunnel-linux-amd64'

class ManagerTests(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
  self.root=Path(self.tmp.name);self.patch=patch.object(m,'ROOT',self.root);self.patch.start();self.addCleanup(self.patch.stop)
  self.running=set();self.enabled=set();self.fail_restart=False
 def config(self,index=1,profile='tcp'):
  return m.make_config(index,profile,'198.51.100.10',f'203.0.113.{index+10}',24000+index,'a'*64,'server')
 def fake_run(self,args,check=True,timeout=90):
  args=list(map(str,args));code=0
  if args[0]=='systemctl':
   action=args[1];name=args[-1].split('@')[-1].split('.')[0]
   if action=='is-active':code=0 if name in self.running else 3
   elif action=='is-enabled':code=0 if name in self.enabled else 1
   elif action=='enable':self.enabled.add(name);self.running.add(name)
   elif action=='disable':self.enabled.discard(name);self.running.discard(name)
   elif action=='stop':self.running.discard(name)
   elif action in ('start','restart'):
    if self.fail_restart:self.fail_restart=False;raise RuntimeError('injected startup failure')
    self.running.add(name)
  if code and check:raise RuntimeError('fake failed')
  return subprocess.CompletedProcess(args,code,'','')
 def test_90_configs_valid_and_join_roundtrip(self):
  for profile in m.PROFILES:
   for i in range(1,10):
    c=self.config(i,profile);peer=m.decode_join(m.encode_join(c))
    self.assertEqual(c['psk'],peer['psk']);self.assertEqual(c['tun']['local_addr'],peer['tun']['remote_addr'])
    for cfg in (c,peer):m.validate(cfg,EXE)
  self.assertEqual(m.addresses(1),('10.88.1.1','10.88.1.2'))
  self.assertEqual(m.addresses(9),('10.96.1.1','10.96.1.2'))
 def test_reject_code_corruption_and_arbitrary_config(self):
  code=m.encode_join(self.config());bad=code[:-1]+('0' if code[-1]!='0' else '1')
  with self.assertRaises(ValueError):m.decode_join(bad)
  with self.assertRaises(ValueError):m.name_ok('../../bad')
  with self.assertRaises(ValueError):m.make_config(169,'tcp','198.51.100.10','203.0.113.20',24444,'a'*64,'server')
 def test_stop_vs_off_and_group(self):
  for i in range(1,10):c=self.config(i);m.atomic(m.confpath(c['tun']['name']),json.dumps(c))
  with patch.object(m,'run',self.fake_run),patch.object(m,'wait_service',lambda n:None):
   m.action('on','all');self.assertEqual(len(self.enabled),9);self.assertEqual(len(self.running),9)
   m.action('stop','all');self.assertEqual(len(self.enabled),9);self.assertFalse(self.running)
   m.action('start','all');self.assertEqual(len(self.running),9)
   m.action('off','ggs01');self.assertNotIn('ggs01',self.enabled);self.assertNotIn('ggs01',self.running)
 def test_edit_preserves_stop_and_rolls_back_failure(self):
  c=self.config();m.atomic(m.confpath('ggs01'),json.dumps(c))
  with patch.object(m,'run',self.fake_run),patch.object(m,'validate',lambda c:None),patch.object(m,'wait_service',lambda n:None):
   edited=copy.deepcopy(c);edited['tun']['mtu']=1200;m.save_config(edited,True);self.assertFalse(self.running)
   self.running.add('ggs01');self.fail_restart=True
   with self.assertRaises(RuntimeError):m.save_config(c,True)
   self.assertEqual(json.loads(m.confpath('ggs01').read_text())['tun']['mtu'],1200)
 def test_duplicate_id_and_raw_peer(self):
  c=self.config(profile='bip');m.atomic(m.confpath('ggs01'),json.dumps(c))
  with self.assertRaises(ValueError):m.conflict(c)
  other=self.config(2,'bip');other['real']['peer_ip']=c['real']['peer_ip']
  with self.assertRaises(ValueError):m.conflict(other)
 def test_delete_keeps_backup_and_others(self):
  for i in (1,2):c=self.config(i);m.atomic(m.confpath(c['tun']['name']),json.dumps(c))
  with patch.object(m,'run',self.fake_run),patch.object(m,'RUN',self.root/'run'):
   m.delete('ggs01')
  self.assertFalse(m.confpath('ggs01').exists());self.assertTrue(m.confpath('ggs02').exists())
  self.assertTrue(list((self.root/'backups').glob('ggs01-deleted-*.json')))

 def test_install_update_rollback_and_checksum(self):
  source=self.root/'package';(source/'dist').mkdir(parents=True)
  shutil.copy2(EXE,source/'dist'/EXE.name)
  (source/'scripts').mkdir();(source/'scripts/manage.py').write_text('# manager test fixture')
  (source/'internal/version').mkdir(parents=True);(source/'internal/version/VERSION').write_text(m.VERSION)
  def manifest():
   exe=source/'dist'/EXE.name
   (source/'dist/SHA256SUMS').write_text(hashlib.sha256(exe.read_bytes()).hexdigest()+'  '+exe.name+'\n')
   lines=[]
   for p in sorted(source.rglob('*')):
    if p.is_file() and p!=source/'SHA256SUMS':lines.append(hashlib.sha256(p.read_bytes()).hexdigest()+'  '+str(p.relative_to(source)))
   (source/'SHA256SUMS').write_text('\n'.join(lines)+'\n')
  manifest()
  for i in (1,2):c=self.config(i);m.atomic(m.confpath(c['tun']['name']),json.dumps(c))
  self.running={'ggs01'};self.enabled={'ggs01','ggs02'}
  opt=self.root/'opt';units=self.root/'units';real_atomic=m.atomic
  def fake_atomic(path,data,mode=0o600):
   if str(path)=='/usr/local/bin/ggstunnel':path=self.root/'wrapper'
   real_atomic(path,data,mode)
  def execute(args,check=True,timeout=90):
   if str(args[0])=='systemctl':return self.fake_run(args,check,timeout)
   p=subprocess.run(list(map(str,args)),text=True,capture_output=True,timeout=timeout)
   if p.returncode and check:raise RuntimeError(p.stderr)
   return p
  with patch.object(m,'OPT',opt),patch.object(m,'UNITS',units),patch.object(m,'atomic',fake_atomic),patch.object(m,'run',execute),patch.object(m,'wait_service',lambda n:None):
   m.install(source);first=(opt/'current').resolve()
   first_unit=(units/'ggstunnel@.service').read_text()
   (source/'scripts/manage.py').write_text('# manager updated fixture');manifest()
   with patch.object(m,'UNIT',m.UNIT.replace('RestartSec=3','RestartSec=4')):m.install(source)
   second=(opt/'current').resolve();self.assertNotEqual(first,second)
   self.assertIn('RestartSec=4',(units/'ggstunnel@.service').read_text())
   self.assertEqual(self.running,{'ggs01'});self.assertEqual(self.enabled,{'ggs01','ggs02'})
   m.rollback();self.assertEqual((opt/'current').resolve(),first)
   self.assertEqual((units/'ggstunnel@.service').read_text(),first_unit)
   (source/'scripts/manage.py').write_text('# next fixture');manifest();self.fail_restart=True
   with patch.object(m,'UNIT',m.UNIT.replace('RestartSec=3','RestartSec=5')):
    with self.assertRaises(RuntimeError):m.install(source)
   self.assertEqual((opt/'current').resolve(),first)
   self.assertEqual((units/'ggstunnel@.service').read_text(),first_unit)
   (source/'scripts/manage.py').write_text('# tampered')
   with self.assertRaises(ValueError):m.install(source)

 def test_capacity_stops_above_failed_rate_and_excludes_psk(self):
  c=self.config();m.atomic(m.confpath('ggs01'),json.dumps(c));calls=[]
  def execute(args,check=True,timeout=90):
   if args[0]=='ip':out=json.dumps([{'dev':'ggs01'}])
   elif args[0]=='iperf3':
    rate=int(args[args.index('-b')+1][:-1]);calls.append(rate)
    out=json.dumps({'end':{'sum_received':{'bits_per_second':5e6,'lost_percent':0,'sender':False}}})
   else:out='ggstunnel 0.3.0-rc1'
   return subprocess.CompletedProcess(args,0,out,'')
  with patch.object(m,'run',execute),patch.object(m,'RUN',self.root/'run'):
   m.capacity('ggs01','client')
  self.assertEqual(calls,[5]*4+[20]*4)
  archive=next((self.root/'reports').glob('*.zip'))
  with zipfile.ZipFile(archive) as z:
   self.assertEqual(len(json.loads(z.read('summary.json'))),8)
   self.assertNotIn(c['psk'],''.join(z.read(n).decode() for n in z.namelist()))

if __name__=='__main__':unittest.main()
