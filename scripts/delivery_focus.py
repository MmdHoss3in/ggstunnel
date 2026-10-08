"""Short focused recovery gates; never publishes or replaces full tagged CI."""
import os
import time
from cloud_extended import OUT, Pair, recovery_trial, record, stop


def main():
    if os.geteuid() != 0 or os.environ.get('GITHUB_ACTIONS') != 'true':
        raise RuntimeError('Disposable privileged GitHub runner required')
    OUT.mkdir(exist_ok=True)
    failures = 0
    with Pair(supervised=True, label='focus-') as pair:
        for trial, scenario in ((1004, 'reorder'), (1007, 'policing')):
            failures += recovery_trial(pair, trial, scenario, 45)
    with Pair(label='focus-loss-') as pair:
        for loss in ('1%', '3%'):
            for reverse in (False, True):
                row = dict(kind='focused-loss', loss=loss, reverse=reverse, status='fail')
                echo = None
                try:
                    pair.shape(200, 80, loss); pair.restart(); time.sleep(1.2)
                    echo = pair.probe_server(); probe = pair.probe(12)
                    row.update(pair.finish_iperf(*pair.iperf('10.77.1.2', 8, 2, reverse, 16), 35))
                    progress = pair.finish_probe(probe, 20)
                    row.update(verified_frames=progress['verified_frames'], max_gap_sec=progress['max_gap_sec'])
                    if row['received_mbps'] < (3 if loss == '1%' else 2) or row['verified_frames'] < 10 or row['max_gap_sec'] > 5:
                        raise RuntimeError('Useful throughput or progress failed')
                    row['status'] = 'pass'
                except Exception as error: row['error'] = str(error); failures += 1
                finally:
                    stop(echo)
                    for child in pair.children: stop(child)
                    pair.children = []; record(row)
    if failures: raise RuntimeError(f'{failures} focused gates failed')


if __name__ == '__main__': main()
