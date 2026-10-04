"""Privileged BIP echo-filter scope and real systemd cleanup on disposable CI."""
import json
import os
import time

from cloud_extended import OUT, Pair, run


PROBE = r'''
import socket, struct, sys, time
kind = int(sys.argv[3])
body = (b'BIP5' if kind >= 0 else b'PING') + bytes([max(kind, 0)]) + bytes(67)
ident, seq = 53471, max(kind, 0) + 1
packet = struct.pack('!BBHHH', 8, 0, 0, ident, seq) + body
words = struct.unpack('!%dH' % (len(packet)//2), packet)
total = sum(words)
while total >> 16: total = (total & 65535) + (total >> 16)
packet = packet[:2] + struct.pack('!H', (~total)&65535) + packet[4:]
s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
s.bind((sys.argv[1], 0)); s.settimeout(.5)
s.sendto(packet, (sys.argv[2], 0))
deadline = time.monotonic() + .5
found = False
while time.monotonic() < deadline:
    try: p, addr = s.recvfrom(2048)
    except socket.timeout: break
    h = (p[0]&15)*4
    if addr[0] == sys.argv[2] and len(p) >= h+8 and p[h] == 0 and p[h+4:h+8] == struct.pack('!HH', ident, seq):
        found = True; break
print(int(found))
'''


def rules(pair, i):
    return run('ip', 'netns', 'exec', pair.names[i], 'iptables-save', '-c').stdout


def wait_absent(pair, i):
    deadline = time.monotonic() + 12
    while time.monotonic() < deadline:
        if 'ggstunnel-bip-echo-' not in rules(pair, i): return
        time.sleep(.1)
    raise RuntimeError('Owned echo rule survived service stop')


def main():
    if os.geteuid() != 0 or os.environ.get('GITHUB_ACTIONS') != 'true':
        raise RuntimeError('Disposable privileged GitHub Actions runner required')
    OUT.mkdir(exist_ok=True)
    with Pair('bip', supervised=True) as pair:
        # Prevent restart racing the assertion after deliberately killing it.
        import manage as m
        for unit in pair.units:
            drop = m.UNITS / (unit + '.d') / 'echo-test.conf'
            m.atomic(drop, '[Service]\nRestart=no\n', 0o644)
            pair.installed_paths.append(drop)
        run('systemctl', 'daemon-reload')
        for name in pair.names:
            run('ip', 'netns', 'exec', name, 'iptables', '-A', 'OUTPUT', '-p', 'tcp',
                '-m', 'comment', '--comment', 'ci-unrelated-keep', '-j', 'ACCEPT')
        pair.restart()
        observations = []
        for i in range(2):
            if rules(pair, i).count('ggstunnel-bip-echo-') != 1:
                raise RuntimeError('Expected exactly one installed scoped rule per endpoint')
            for kind in (-1, 1, 2, 3, 4, 5, 6, 7):
                actual = run('ip', 'netns', 'exec', pair.names[1-i], 'python3', '-c', PROBE,
                             pair.outer[1-i], pair.outer[i], kind).stdout.strip() == '1'
                expected = kind not in (3, 4, 7)
                observations.append(dict(endpoint=i, kind=kind, reply=actual))
                if actual != expected: raise RuntimeError(f'Wrong filter scope: endpoint={i}, kind={kind}')
        # Same magic/kind from a different outer peer must not match the rule.
        run('ip', '-n', pair.names[0], 'addr', 'add', '192.0.2.99/24', 'dev', pair.devs[0])
        actual = run('ip', 'netns', 'exec', pair.names[0], 'python3', '-c', PROBE,
                     '192.0.2.99', pair.outer[1], 4).stdout.strip()
        if actual != '1': raise RuntimeError('Filter affected an unrelated outer peer')
        pair.reachable()
        time.sleep(1.1)
        if not all(p.get('telemetry', {}).get('carrier', {}).get('kernel_echo_filter')
                   for p in pair.sample()['peers']): raise RuntimeError('Installed filter absent from telemetry')
        before = [rules(pair, i) for i in range(2)]
        pair.stop_peer(0); wait_absent(pair, 0)
        pair.start_peer(0); pair.reachable()
        run('systemctl', 'kill', '--kill-whom=main', '--signal=SIGKILL', pair.units[0])
        wait_absent(pair, 0)
        pair.stop_peer(1); wait_absent(pair, 1)
        after = [rules(pair, i) for i in range(2)]
        if not all('ci-unrelated-keep' in text for text in after):
            raise RuntimeError('Cleanup removed an unrelated rule')
        result = dict(status='pass', scope=observations, unrelated_peer_pass=True,
                      inner_ping_pass=True, normal_stop_cleanup=True, sigkill_exec_stop_post_cleanup=True,
                      rules_before=before, rules_after=after)
        (OUT / 'echo-filter-scope.json').write_text(json.dumps(result, indent=2))
        print('PASS: BIP kernel echo scope, DATA/ACK/FAST/FAST_ACK/ordinary ping, unrelated peer/rule, normal stop and SIGKILL ExecStopPost')


if __name__ == '__main__': main()
