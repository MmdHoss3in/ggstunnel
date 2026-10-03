import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

spec=importlib.util.spec_from_file_location("develop",Path(__file__).with_name("develop.py"))
d=importlib.util.module_from_spec(spec)
spec.loader.exec_module(d)


class DeveloperTests(unittest.TestCase):
    def test_real_owned_process_start_stop(self):
        import os
        import sys
        with tempfile.TemporaryDirectory() as tmp, patch.object(d,"STATE",Path(tmp)):
            try:
                d.launch("probe",[sys.executable,"-c","import time; time.sleep(30)"])
            except ValueError as e:
                if str(e)=="Process exited before registration":
                    self.skipTest("Workspace does not expose spawned process identity through /proc")
                raise
            rec=d.owned("probe")
            self.assertIsNotNone(rec)
            d.stop("probe")
            self.assertIsNone(d.owned("probe"))
            try:
                os.waitpid(rec["pid"],0)
            except ChildProcessError:
                pass

    def test_linux_proc_identity_and_owned_stop(self):
        import sys
        import signal
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);proc=root/"123";proc.mkdir()
            fields=["S"]+["0"]*18+["98765"]
            (proc/"stat").write_text("123 (name with spaces) "+" ".join(fields))
            (proc/"cmdline").write_bytes(b"ggstunnel\x00-c\x00config.json\x00")
            (proc/"exe").symlink_to(sys.executable)
            ident=d.identity(123,root)
            self.assertEqual(ident["start"],"98765")
            with patch.object(d,"STATE",root):
                (root/"tunnel.pid.json").write_text(json.dumps({"pid":123,"identity":ident}))
                with patch.object(d,"identity",side_effect=[ident,None,None]),patch.object(d.os,"kill") as kill:
                    d.stop("tunnel")
                    kill.assert_called_once_with(123,signal.SIGTERM)

    def test_restart_failure_still_saves_report(self):
        with tempfile.TemporaryDirectory() as tmp, patch.object(d,"STATE",Path(tmp)):
            c=json.loads((d.BASE/"examples/client.json").read_text())
            (Path(tmp)/"config.json").write_text(json.dumps(c))
            active={"tunnel":True}
            def owned(name):
                return {"pid":123} if active.get(name) else None
            def stop(name):
                active[name]=False
            with patch.object(d,"root_required"),patch.object(d,"owned",side_effect=owned),patch.object(d,"stop",side_effect=stop),patch.object(d,"start",side_effect=ValueError("mock start failure")),patch.object(d.Report,"command",return_value="PASS"):
                d.restart_test()
            p=list((Path(tmp)/"reports").glob("*.txt"))[0]
            self.assertIn("Restart failure: FAIL",p.read_text())
            self.assertNotIn("Authenticated reconnect after local restart: PASS",p.read_text())

    def test_report_redacts_and_is_private(self):
        with tempfile.TemporaryDirectory() as tmp, patch.object(d,"STATE",Path(tmp)):
            r=d.Report("secret-shared-key")
            r.add("log","INFO","secret-shared-key appears in test log")
            p=r.save("server")
            self.assertNotIn("secret-shared-key",p.read_text())
            self.assertIn("REDACTED",p.read_text())
            self.assertEqual(p.stat().st_mode & 0o777,0o600)

    def test_stale_pid_cannot_stop_another_process(self):
        with tempfile.TemporaryDirectory() as tmp, patch.object(d,"STATE",Path(tmp)):
            (Path(tmp)/"tunnel.pid.json").write_text(json.dumps({"pid":123,"identity":{"start":"old"}}))
            with patch.object(d,"identity",return_value={"start":"new"}), patch.object(d.os,"kill") as kill:
                d.stop("tunnel")
                kill.assert_not_called()

    def test_timeout_and_missing_command_are_distinct(self):
        with patch.object(d.shutil,"which",return_value=None):
            self.assertEqual(d.run(["missing"])[0],"SKIP")
        with patch.object(d.shutil,"which",return_value="test"), patch.object(d.subprocess,"run",side_effect=subprocess.TimeoutExpired("test",1,output=b"partial")):
            status,output=d.run(["test"])
            self.assertEqual(status,"TIMEOUT")
            self.assertIn("partial",output)

    def test_wrong_route_skips_throughput_and_saves_report(self):
        with tempfile.TemporaryDirectory() as tmp, patch.object(d,"STATE",Path(tmp)):
            c=json.loads((d.BASE/"examples/server.json").read_text())
            (Path(tmp)/"config.json").write_text(json.dumps(c))
            def fake_run(argv,timeout=8):
                if argv[:4]==["ip","-j","route","get"]:
                    return "PASS",'[{"dev":"eth0"}]'
                return "PASS","mock output"
            with patch.object(d,"run",side_effect=fake_run) as runner, patch.object(d,"binary",return_value=Path("/test/ggstunnel")):
                d.collect(True,5207)
                self.assertFalse(any(call.args[0][0]=="iperf3" for call in runner.call_args_list))
            reports=list((Path(tmp)/"reports").glob("*.txt"))
            self.assertEqual(len(reports),1)
            self.assertIn("Throughput route isolation: FAIL",reports[0].read_text())


if __name__=="__main__":
    unittest.main()
