"""The shipped CLI must generate the same performance recipe as the installer."""
import json
from pathlib import Path
import platform
import subprocess
import tempfile
import unittest


class CLISamples(unittest.TestCase):
    def test_generated_samples_match_release_examples_and_validate(self):
        root = Path(__file__).resolve().parents[1]
        architecture = {'x86_64': 'amd64', 'aarch64': 'arm64'}.get(platform.machine())
        binary = root / 'dist' / ('ggstunnel-linux-' + str(architecture))
        if platform.system() != 'Linux' or not binary.exists():
            self.skipTest('Requires native Linux release binary')
        for role in ('server', 'client'):
            with self.subTest(role=role):
                actual = json.loads(subprocess.check_output([binary, '-gen', role], text=True))
                expected = json.loads((root / 'examples' / (role + '.json')).read_text())
                for section in ('transport', 'performance', 'tuner'):
                    self.assertEqual({key: actual[section].get(key) for key in expected[section]}, expected[section])
                self.assertEqual(actual['tun']['tx_queue_len'], expected['tun']['tx_queue_len'])
                with tempfile.TemporaryDirectory() as work:
                    config = Path(work) / 'sample.json'
                    config.write_text(json.dumps(actual))
                    subprocess.run([binary, '-c', config, '-check'], check=True, capture_output=True)
