"""Print bounded retry histories and retain private raw traces on disposable CI."""
import json
from pathlib import Path


def main():
    root = Path('extended-results')
    for path in sorted(root.glob('*tunnel-*.log')):
        lines = [line for line in path.read_text().splitlines()
                 if 'delivery exhausted' in line or 'recovering transport' in line]
        for line in lines: print(path.name + ': ' + line, flush=True)
    for path in sorted(root.glob('*retry-*.jsonl')):
        events = [json.loads(line) for line in path.read_text().splitlines()]
        exhausted = [event for event in events if event['event'] == 'delivery_exhausted']
        for last in exhausted:
            history = [event for event in events if event.get('seq') == last['seq']
                       and event['session'] == last['session']]
            print(json.dumps(dict(trace=path.name, exhausted_sequence=last['seq'], history=history)), flush=True)
        if exhausted:
            nearby = [event for event in events if event.get('retries', 0) >= 6]
            print(json.dumps(dict(trace=path.name, late_attempts=nearby[-50:])), flush=True)


if __name__ == '__main__': main()
