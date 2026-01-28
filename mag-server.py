#!/usr/bin/env python3
"""
MAG Game Server - Protocol Explorer
Responds to MAG client and captures further communication
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

def create_response_v1():
    """
    Create a simple acknowledgment response.
    Based on the header pattern: 24 XX XX XX...
    """
    # Simple ACK - echo the magic byte with minimal response
    return bytes([
        0x24,  # Magic byte (same as client)
        0x00, 0x00,  # Length placeholder
        0x02,  # Response type (guess)
        0x00, 0x00, 0x00, 0x00  # Padding/status
    ])

def create_response_v2():
    """
    Create a response mimicking the header structure.
    Header seems to be: 24 d4 02 01 00 70 00 03 00 00 06 00 04 01 00 c2
    """
    return bytes([
        0x24,  # Magic
        0x00, 0x00,  # Shorter length
        0x02,  # Type 2 = response?
        0x01,  # Version
        0x00,  # Status OK
        0x00, 0x00,  # Reserved
    ])

def create_response_v3():
    """
    Minimal response - just acknowledge
    """
    return bytes([0x24, 0x04, 0x00, 0x00])

def main():
    os.makedirs(LOG_DIR, exist_ok=True)

    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    log_file = os.path.join(LOG_DIR, f'mag_session_{timestamp}.log')

    print(f'MAG Game Server - Protocol Explorer')
    print(f'====================================')
    print(f'Listening on {HOST}:{PORT}')
    print(f'Log file: {log_file}')
    print()
    print('Response modes:')
    print('  1 = Simple ACK')
    print('  2 = Header mimic')
    print('  3 = Minimal')
    print('  0 = No response (just listen)')
    print()

    response_mode = input('Select response mode [0-3, default=0]: ').strip()
    response_mode = int(response_mode) if response_mode.isdigit() else 0

    print(f'\nUsing response mode: {response_mode}')
    print('Press Ctrl+C to stop\n')

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((HOST, PORT))
        server.listen(5)

        while True:
            print('Waiting for MAG client...')
            conn, addr = server.accept()
            conn.settimeout(30)  # 30 second timeout

            with conn:
                client_ip = f'{addr[0]}:{addr[1]}'
                print(f'\n[{datetime.now()}] Connection from {client_ip}')

                with open(log_file, 'a') as lf:
                    lf.write(f'\n{"="*60}\n')
                    lf.write(f'Connection from {client_ip} at {datetime.now()}\n')
                    lf.write(f'Response mode: {response_mode}\n')
                    lf.write(f'{"="*60}\n')

                    packet_num = 0

                    while True:
                        try:
                            data = conn.recv(4096)
                            if not data:
                                print('Connection closed by client')
                                lf.write('\n--- Connection closed by client ---\n')
                                break

                            packet_num += 1

                            # Log received data
                            print(f'\n[RECV Packet {packet_num}] {len(data)} bytes:')
                            print(hexdump(data, '  '))

                            lf.write(f'\n[RECV {packet_num}] {len(data)} bytes at {datetime.now()}\n')
                            lf.write(hexdump(data) + '\n')

                            # Save raw packet
                            raw_file = os.path.join(LOG_DIR, f'packet_{timestamp}_{packet_num:03d}_recv.bin')
                            with open(raw_file, 'wb') as rf:
                                rf.write(data)

                            # Send response based on mode
                            if response_mode > 0:
                                if response_mode == 1:
                                    response = create_response_v1()
                                elif response_mode == 2:
                                    response = create_response_v2()
                                elif response_mode == 3:
                                    response = create_response_v3()
                                else:
                                    response = None

                                if response:
                                    print(f'\n[SEND] {len(response)} bytes:')
                                    print(hexdump(response, '  '))

                                    lf.write(f'\n[SEND] {len(response)} bytes\n')
                                    lf.write(hexdump(response) + '\n')

                                    conn.sendall(response)

                                    # Save sent packet
                                    sent_file = os.path.join(LOG_DIR, f'packet_{timestamp}_{packet_num:03d}_sent.bin')
                                    with open(sent_file, 'wb') as sf:
                                        sf.write(response)

                            lf.flush()

                        except socket.timeout:
                            print('Connection timed out (30s)')
                            lf.write('\n--- Connection timed out ---\n')
                            break
                        except ConnectionResetError:
                            print('Connection reset by client')
                            lf.write('\n--- Connection reset by client ---\n')
                            break
                        except Exception as e:
                            print(f'Error: {e}')
                            lf.write(f'\n--- Error: {e} ---\n')
                            break

                    print(f'\nSession ended. {packet_num} packets captured.')

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print('\nStopped.')
    except PermissionError:
        print(f'Permission denied. Try: sudo python3 {sys.argv[0]}')
        sys.exit(1)
