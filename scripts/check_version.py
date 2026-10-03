"""Keep standalone bootstrap and release documentation on the embedded version."""
import re
from pathlib import Path

root = Path(__file__).resolve().parents[1]
version = (root / 'internal/version/VERSION').read_text().strip()
if not re.fullmatch(r'\d+\.\d+\.\d+(?:-[A-Za-z0-9.]+)?', version):
    raise SystemExit('Invalid embedded version')
bootstrap = (root / 'install.sh').read_text()
if '${GGS_VERSION:-v' + version + '}' not in bootstrap:
    raise SystemExit('Bootstrap version does not match binary')
for name in ('README.md', 'README-fa.md', 'RELEASE_NOTES.md'):
    if 'v' + version not in (root / name).read_text():
        raise SystemExit(name + ' does not document the current version')
print('Consistent version:', version)
