#!/usr/bin/env bash
set -Eeuo pipefail
cd "$(dirname -- "$0")"
# Menu dispatch deliberately precedes OS/package/TUN checks: opening an
# installed manager is an offline operation, not another installation.
case "${1:-auto}" in
  menu|--menu)
    shift
    exec /usr/local/bin/ggstunnel "$@"
    ;;
  auto)
    if [[ -x /usr/local/bin/ggstunnel ]]; then
      exec /usr/local/bin/ggstunnel
    fi
    ;;
  install|update) shift ;;
  develop) shift; exec python3 scripts/develop.py "$@" ;;
  *) echo 'Usage: setup.sh [menu|install|update|develop]'; exit 2 ;;
esac
[[ $EUID == 0 ]] || { echo 'Run with sudo/root'; exit 1; }
source /etc/os-release
[[ "$ID" == ubuntu && "$VERSION_ID" =~ ^(22\.04|24\.04)$ ]] || { echo 'Supported: Ubuntu 22.04 / 24.04'; exit 1; }
[[ -d /run/systemd/system ]] || { echo 'systemd must be running'; exit 1; }
missing=()
for package in python3 iproute2 iputils-ping iperf3 nano kmod ca-certificates unzip procps; do
  if [[ "$(dpkg-query -W -f='${Status}' "$package" 2>/dev/null || true)" != 'install ok installed' ]]; then
    missing+=("$package")
  fi
done
if ((${#missing[@]})); then
  apt-get update
  DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends "${missing[@]}"
fi
modprobe tun || true
[[ -c /dev/net/tun ]] || { echo 'Kernel/container must expose /dev/net/tun'; exit 1; }
python3 scripts/manage.py install "$PWD"
exec python3 scripts/manage.py menu
