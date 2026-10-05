"""Verify real batching of a prequeued 100-datagram native socket test."""
import json
from pathlib import Path
import re
import sys

text=Path(sys.argv[1]).read_text()
counts=[int(x) for x in re.findall(r'(?:sendmmsg\(.*|<\.\.\. sendmmsg resumed>.*)\s=\s(\d+)\s*$',text,re.M)]
report=dict(successful_calls=len(counts),datagrams_sent=sum(counts),counts=counts)
print(json.dumps(report))
if sum(counts)!=100 or len(counts)!=4:raise RuntimeError('Queued UDP test did not emit 100 distinct datagrams in four native batches')
