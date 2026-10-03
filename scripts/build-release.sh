#!/usr/bin/env bash
set -Eeuo pipefail
cd "$(dirname "$0")/.."
VERSION="${VERSION:-0.3.0-rc3}"
mkdir -p dist
# Validation is run by CI before packaging; this script builds deterministic
# target binaries and manifests and can also be called locally after testing.
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -buildvcs=false -trimpath -ldflags="-s -w -X main.version=$VERSION" -o dist/ggstunnel-linux-amd64 ./cmd/ggstunnel
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -buildvcs=false -trimpath -ldflags="-s -w -X main.version=$VERSION" -o dist/ggstunnel-linux-arm64 ./cmd/ggstunnel
(cd dist && sha256sum ggstunnel-linux-* > SHA256SUMS)
echo "release binaries built for $VERSION"
python3 - <<'PY'
from pathlib import Path
import hashlib
root=Path('.')
lines=[]
for p in sorted(root.rglob('*')):
    if not p.is_file() or p==Path('SHA256SUMS') or any(x in p.parts for x in ('__pycache__','develop-state','.git','.github','artifacts')):
        continue
    lines.append(hashlib.sha256(p.read_bytes()).hexdigest()+'  '+p.as_posix())
Path('SHA256SUMS').write_text('\n'.join(lines)+'\n')
PY
