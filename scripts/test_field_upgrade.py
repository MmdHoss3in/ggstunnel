"""Seven-instance transactional upgrade coverage; executed in Linux CI."""
import contextlib
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch

spec=importlib.util.spec_from_file_location('field_upgrade_manager',Path(__file__).with_name('manage.py'))
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)

class FieldUpgradeTests(unittest.TestCase):
    def test_seven_configs_upgrade_partial_failure_and_rollback(self):
        with tempfile.TemporaryDirectory() as temporary, contextlib.ExitStack() as stack:
            root=Path(temporary)
            for key,value in dict(ROOT=root/'config',OPT=root/'opt',UNITS=root/'units',WRAPPER=root/'bin/ggstunnel').items():
                stack.enter_context(patch.object(m,key,value))
            stack.enter_context(contextlib.redirect_stdout(io.StringIO()))
            exe=Path(__file__).resolve().parents[1]/'dist'/('ggstunnel-linux-'+m.arch())
            source=root/'package';(source/'dist').mkdir(parents=True)
            shutil.copy2(exe,source/'dist'/exe.name)
            (source/'scripts').mkdir();(source/'scripts/manage.py').write_text('# package one')
            (source/'internal/version').mkdir(parents=True)
            (source/'internal/version/VERSION').write_text(m.VERSION)
            def manifest():
                (source/'dist/SHA256SUMS').write_text(hashlib.sha256((source/'dist'/exe.name).read_bytes()).hexdigest()+'  '+exe.name+'\n')
                lines=[hashlib.sha256(p.read_bytes()).hexdigest()+'  '+p.relative_to(source).as_posix() for p in sorted(source.rglob('*')) if p.is_file() and p!=source/'SHA256SUMS']
                (source/'SHA256SUMS').write_text('\n'.join(lines)+'\n')
            saved={}
            for i in range(1,8):
                c=m.make_config(i,'bip','198.51.100.1',f'203.0.113.{i}',24000+i,hex(i)[2:]*64,'server')
                c['tun']['routes']=[f'10.200.{i}.0/24']
                c['forwards']=[dict(protocol='tcp',listen=f'127.0.0.1:{25000+i}',target=f"{c['tun']['remote_addr']}:443")]
                m.atomic(m.confpath(c['tun']['name']),json.dumps(c))
                saved[c['tun']['name']]=m.confpath(c['tun']['name']).read_bytes()
            running={'ggs01','ggs02','ggs03','ggs04','ggs05'}
            enabled=running|{'ggs06'}
            calls=[];fail={'armed':False}
            def execute(args,check=True,timeout=90):
                args=list(map(str,args))
                if args[0]!='systemctl':
                    p=subprocess.run(args,capture_output=True,text=True,timeout=timeout)
                    if p.returncode and check:raise RuntimeError(p.stderr+p.stdout)
                    return p
                calls.append(args)
                name=args[-1].removeprefix('ggstunnel@').removesuffix('.service')
                code=0
                if args[1]=='is-active':code=0 if name in running else 3
                elif args[1]=='is-enabled':code=0 if name in enabled else 1
                elif args[1]=='restart' and name=='ggs03' and fail['armed']:
                    fail['armed']=False;raise RuntimeError('injected third-instance failure')
                return subprocess.CompletedProcess(args,code,'','')
            stack.enter_context(patch.object(m,'run',execute))
            stack.enter_context(patch.object(m,'wait_service',lambda _:None))
            manifest();m.install(source);first=(m.OPT/'current').resolve()
            (source/'scripts/manage.py').write_text('# package two');manifest()
            fail['armed']=True
            with self.assertRaisesRegex(RuntimeError,'third-instance'):m.install(source)
            self.assertEqual((m.OPT/'current').resolve(),first)
            self.assertFalse((m.OPT/'install-transaction.json').exists())
            for name,data in saved.items():self.assertEqual(m.confpath(name).read_bytes(),data)
            m.install(source);second=(m.OPT/'current').resolve()
            self.assertNotEqual(second,first)
            m.rollback();self.assertEqual((m.OPT/'current').resolve(),first)
            restarted={a[-1] for a in calls if a[1]=='restart'}
            self.assertEqual(restarted,{m.unit(n) for n in running})
            self.assertFalse(any(a[1] in ('enable','disable','stop','start') for a in calls))
            for name,data in saved.items():self.assertEqual(m.confpath(name).read_bytes(),data)

    def test_menu_distinguishes_delivery_stall_from_peer_liveness(self):
        with tempfile.TemporaryDirectory() as temporary, patch.object(m,'RUN',Path(temporary)):
            p=m.RUN/'ggs01.json'
            p.write_text(json.dumps({'carrier':{'peer_authenticated':True,'delivery_stalled':True}}))
            self.assertEqual(m.peer_health('ggs01'),'DATA DELIVERY STALLED')

if __name__=='__main__':unittest.main()
