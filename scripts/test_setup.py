import os
from pathlib import Path
import subprocess
import tempfile
import unittest

class MenuDispatchTests(unittest.TestCase):
    def test_installed_menu_never_checks_packages_or_downloads(self):
        root = Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory() as tmp:
            d = Path(tmp)
            menu = d/'ggstunnel'
            menu.write_text('#!/bin/sh\nprintf "MENU_ONLY\\n"\n')
            menu.chmod(0o755)
            for command in ('apt-get', 'dpkg-query', 'curl', 'python3', 'modprobe'):
                p=d/command
                p.write_text('#!/bin/sh\necho UNEXPECTED_COMMAND >&2\nexit 97\n')
                p.chmod(0o755)
            for source in ('setup.sh','install.sh'):
                script=d/source
                script.write_text((root/source).read_text().replace('/usr/local/bin/ggstunnel', str(menu)))
                for args in ([], ['menu'], ['--menu']):
                    p=subprocess.run(['/bin/bash', str(script), *args], env={**os.environ,'PATH':str(d)+':/usr/bin:/bin'}, capture_output=True,text=True)
                    self.assertEqual(p.returncode,0,p.stderr)
                    self.assertEqual(p.stdout,'MENU_ONLY\n')

if __name__=='__main__': unittest.main()
