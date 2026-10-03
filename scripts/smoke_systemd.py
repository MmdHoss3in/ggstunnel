"""Short real installation/lifecycle check, only on disposable GitHub runners."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import tempfile

import manage as m


def main():
    if os.geteuid() != 0 or os.environ.get('GITHUB_ACTIONS') != 'true':
        raise RuntimeError('Requires root on a disposable GitHub Actions runner')
    source = Path(__file__).resolve().parents[1]
    name = 'ggssmoke'
    path = m.confpath(name)
    if path.exists():
        raise RuntimeError('Refusing to replace an existing smoke configuration')
    m.install(source)
    m.run(['systemd-analyze', 'verify', m.UNITS / 'ggstunnel@.service'])
    cfg = json.loads((source / 'examples/server.json').read_text())
    cfg['psk'] = 'ci-only-key-' + 'a' * 32
    cfg['real'].update(local_ip='127.0.0.1', peer_ip='127.0.0.2')
    cfg['tun'].update(name=name, local_addr='10.199.1.1', remote_addr='10.199.1.2')
    m.atomic(path, json.dumps(cfg))
    try:
        m.action('on', name)
        first = (m.OPT / 'current').resolve()
        with tempfile.TemporaryDirectory() as tmp:
            candidate = Path(tmp) / 'package'
            shutil.copytree(source, candidate, ignore=shutil.ignore_patterns('.git', '.github', 'artifacts', '__pycache__'))
            readme = candidate / 'README.md'
            readme.write_text(readme.read_text() + '\n<!-- CI upgrade fixture -->\n')
            lines = []
            for line in (candidate / 'SHA256SUMS').read_text().splitlines():
                _, rel = line.split()
                lines.append(hashlib.sha256((candidate / rel).read_bytes()).hexdigest() + '  ' + rel)
            (candidate / 'SHA256SUMS').write_text('\n'.join(lines) + '\n')
            m.install(candidate)
            if (m.OPT / 'current').resolve() == first or not m.active(name):
                raise RuntimeError('Upgrade failed to preserve the running service')
            m.rollback()
            if (m.OPT / 'current').resolve() != first or not m.active(name):
                raise RuntimeError('Rollback failed to restore the running release')
        m.action('stop', name)
        if m.active(name) or not m.enabled(name):
            raise RuntimeError('Temporary stop changed boot enable state')
        m.action('off', name)
        if m.active(name) or m.enabled(name):
            raise RuntimeError('OFF did not disable the service')
        m.run(['/usr/local/bin/ggstunnel', 'status'])
        print('PASS: real systemd install, ON, active upgrade, rollback, STOP and OFF')
    finally:
        m.run(['systemctl', 'disable', '--now', m.unit(name)], check=False)
        path.unlink(missing_ok=True)


if __name__ == '__main__':
    main()
