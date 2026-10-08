#!/usr/bin/env bash
set -Eeuo pipefail
MODE="${1:-auto}"
case "$MODE" in
  menu|--menu) shift; exec /usr/local/bin/ggstunnel "$@" ;;
  auto)
    if [[ -x /usr/local/bin/ggstunnel ]]; then exec /usr/local/bin/ggstunnel; fi
    ;;
  install|update) ;;
  *) echo 'Usage: install.sh [menu|install|update]'; exit 2 ;;
esac
[[ $EUID == 0 ]] || { echo 'Run with sudo/root'; exit 1; }
VERSION="${GGS_VERSION:-v0.3.4-rc4}"
[[ "$VERSION" =~ ^v[0-9]+\.[0-9]+\.[0-9]+(-[A-Za-z0-9.]+)?$ ]] || { echo 'Invalid version'; exit 2; }
command -v curl >/dev/null || { echo 'Install curl and ca-certificates first: apt-get install -y curl ca-certificates'; exit 1; }
WORK=$(mktemp -d)
trap 'rm -rf -- "$WORK"' EXIT
BASE="https://github.com/MmdHoss3in/ggstunnel/releases/download/$VERSION"
curl --fail --location --retry 3 --proto '=https' --tlsv1.2 "$BASE/ggstunnel-linux.tar.gz" -o "$WORK/ggstunnel-linux.tar.gz"
curl --fail --location --retry 3 --proto '=https' --tlsv1.2 "$BASE/SHA256SUMS" -o "$WORK/SHA256SUMS"
(cd "$WORK" && sha256sum --check SHA256SUMS)
tar -xzf "$WORK/ggstunnel-linux.tar.gz" -C "$WORK"
bash "$WORK/ggstunnel/setup.sh" install
