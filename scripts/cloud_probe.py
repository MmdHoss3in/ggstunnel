"""Numbered, hashed TCP echo probe through the encrypted TUN; standard library."""
import hashlib
import json
import socket
import sys
import threading
import time

SIZE = 4096


def read_full(conn, size):
    data = bytearray()
    while len(data) < size:
        part = conn.recv(size - len(data))
        if not part:
            raise EOFError('TCP peer closed')
        data.extend(part)
    return bytes(data)


def echo(conn):
    with conn:
        try:
            while True:
                data = read_full(conn, SIZE)
                if hashlib.sha256(data[:-32]).digest() != data[-32:]:
                    raise ValueError('Request integrity failure')
                conn.sendall(data)
        except (EOFError, OSError):
            pass


def main():
    mode, address, seconds = sys.argv[1], sys.argv[2], float(sys.argv[3])
    if mode == 'server':
        with socket.socket() as server:
            server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server.bind((address, 25443))
            server.listen(32)
            print(json.dumps({'kind': 'server_ready'}), flush=True)
            while True:
                conn, _ = server.accept()
                threading.Thread(target=echo, args=(conn,), daemon=True).start()
    else:
        began = time.monotonic()
        completions = []
        with socket.create_connection((address, 25443), timeout=15) as conn:
            conn.settimeout(150)
            conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            seq = 0
            while time.monotonic() - began < seconds:
                body = seq.to_bytes(8, 'big') + bytes([seq % 251]) * (SIZE - 40)
                payload = body + hashlib.sha256(body).digest()
                conn.sendall(payload)
                if read_full(conn, SIZE) != payload:
                    raise ValueError('Reply corruption, duplication or wrong sequence')
                completions.append(time.monotonic())
                seq += 1
                if seq == 1:
                    print(json.dumps({'kind': 'probe_ready'}), flush=True)
        gaps = [b - a for a, b in zip(completions, completions[1:])]
        print(json.dumps({'kind': 'probe_result', 'verified_frames': seq,
                          'max_gap_sec': max(gaps, default=0), 'completions': completions}), flush=True)


if __name__ == '__main__':
    main()
