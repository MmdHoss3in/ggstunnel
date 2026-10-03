#!/usr/bin/env python3
"""Restart the owned developer tunnel with bounded metadata tracing enabled."""
import os
from pathlib import Path
import subprocess
import time

base = Path(__file__).resolve().parent.parent
if os.geteuid() != 0:
    raise SystemExit('Run with sudo')
subprocess.run(['bash', str(base/'setup.sh'), 'develop', 'stop'], check=True)
trace = base/'develop-state/bip-trace.jsonl'
if trace.exists():
    trace.rename(trace.with_name('bip-trace.previous-'+str(time.time_ns())+'.jsonl'))
env = dict(os.environ, GGSTUNNEL_BIP_TRACE=str(trace))
subprocess.run(['bash', str(base/'setup.sh'), 'develop', 'start'], env=env, check=True)
for _ in range(30):
    if trace.exists():
        print('Diagnostic trace enabled: '+str(trace))
        break
    time.sleep(.1)
else:
    raise SystemExit('Trace not created; inspect develop-state/tunnel.log before testing')
