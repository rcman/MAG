#!/usr/bin/env python3
"""
MAG Game Server Listener
Captures and logs data sent by the MAG game client
"""

import socket
import sys
import os
from datetime import datetime

HOST = '192.168.10.200'
PORT = 10073
LOG_DIR = '/home/franco/mag3/mag-captures'

def hexdump(data, prefix=''):
    """Format binary data as hex dump"""
    lines = []
    for i in range(0, len(data), 16):
        chunk = data[i:i+16]
        hex_part = ' '.join(f'{b:02x}' for b in chunk)
        ascii_part = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
        lines.append(f'{prefix}{i:04x}  {hex_part:<48}  {ascii_part}')
    return '\n'.join(lines)

def main():
    # Create log directory
    os.makedirs(LOG_DIR, exist_ok=True)

    # Create log file
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    log_file = os.path.join(LOG_DIR, f'mag_capture_{timestamp}.log')
    raw_file = os.path.join(LOG_DIR, f'mag_capture_{timestamp}.bin')

    print(f'MAG Game Server Listener')
    print(f'========================')
    print(f'Listening on {HOST}:{PORT}')
    print(f'Log file: {log_file}')
    print(f'Raw file: {raw_file}')
    print(f'Press Ctrl+C to stop')
    print()

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((HOST, PORT))
        server.listen(5)

        while True:
            print('Waiting for connection...')
            conn, addr = server.accept()

            with conn:
                print(f'\n[{datetime.now()}] Connection from {addr[0]}:{addr[1]}')

                with open(log_file, 'a') as lf, open(raw_file, 'ab') as rf:
                    lf.write(f'\n=== Connection from {addr[0]}:{addr[1]} at {datetime.now()} ===\n')

                    total_bytes = 0
                    packet_num = 0

                    while True:
                        try:
                            data = conn.recv(4096)
                            if not data:
                                print(f'Connection closed by client')
                                lf.write(f'\n--- Connection closed by client ---\n')
                                break

                            packet_num += 1
                            total_bytes += len(data)

                            # Log to console
                            print(f'\n[Packet {packet_num}] Received {len(data)} bytes:')
                            print(hexdump(data, '  '))

                            # Log to file
                            lf.write(f'\n[Packet {packet_num}] {len(data)} bytes at {datetime.now()}\n')
                            lf.write(hexdump(data) + '\n')

                            # Save raw bytes
                            rf.write(data)
                            rf.flush()
                            lf.flush()

                        except ConnectionResetError:
                            print(f'Connection reset by client')
                            lf.write(f'\n--- Connection reset by client ---\n')
                            break
                        except Exception as e:
                            print(f'Error: {e}')
                            lf.write(f'\n--- Error: {e} ---\n')
                            break

                    print(f'\nTotal received: {total_bytes} bytes in {packet_num} packets')
                    lf.write(f'\nTotal: {total_bytes} bytes in {packet_num} packets\n')

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print('\nStopped.')
    except PermissionError:
        print(f'Permission denied. Try: sudo python3 {sys.argv[0]}')
        sys.exit(1)
