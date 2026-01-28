#!/usr/bin/env python3
"""
MAG Game Server v2 - Protocol Explorer
Handles different message types (0x24, 0x20)
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

def respond_0x24(data, mode):
    """Response to certificate message (0x24)"""
    if mode == 0:
        return None
    elif mode == 1:
        # Simple ACK
        return bytes([0x24, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00])
    elif mode == 2:
        # Echo header style
        return bytes([0x24, 0x04, 0x02, 0x01, 0x00, 0x00, 0x00, 0x00])
    elif mode == 3:
        # Success status
        return bytes([0x24, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00])

def respond_0x20(data, mode):
    """Response to 0x20 message type"""
    if mode == 0:
        return None
    elif mode == 1:
        # Echo same prefix
        return bytes([0x20, 0x01, 0x00, 0x00])
    elif mode == 2:
        # ACK with success
        return bytes([0x20, 0x02, 0x00, 0x00])
    elif mode == 3:
        # Longer response
        return bytes([0x20, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00])
    elif mode == 4:
        # Try 0x21 as response type
        return bytes([0x21, 0x01, 0x00, 0x00])
    elif mode == 5:
        # Status OK pattern
        return bytes([0x20, 0x00, 0x00, 0x00])
    elif mode == 6:
        # Larger payload with zeros
        return bytes([0x20, 0x01, 0x00, 0x01] + [0x00] * 32)
    elif mode == 7:
        # DNAS Success response from docs: 0x01 0x00 0x00 0x00
        return bytes([0x01, 0x00, 0x00, 0x00])
    elif mode == 8:
        # DNAS Success with 0x20 prefix
        return bytes([0x20, 0x01, 0x00, 0x00, 0x00])
    elif mode == 9:
        # Try echoing back exact bytes + DNAS success
        return bytes([0x20, 0x01, 0x00, 0x01, 0x01, 0x00, 0x00, 0x00])

def main():
    os.makedirs(LOG_DIR, exist_ok=True)

    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    log_file = os.path.join(LOG_DIR, f'mag_v2_{timestamp}.log')

    print('MAG Game Server v2 - Protocol Explorer')
    print('======================================')
    print(f'Listening on {HOST}:{PORT}')
    print(f'Log file: {log_file}')
    print()
    print('0x24 response modes (certificate):')
    print('  0 = No response')
    print('  1 = Simple ACK [24 00 00 02...]')
    print('  2 = Echo header [24 04 02 01...]')
    print('  3 = Success status')
    print()
    print('0x20 response modes:')
    print('  0 = No response')
    print('  1 = Echo [20 01 00 00]')
    print('  2 = ACK success [20 02 00 00]')
    print('  3 = Longer [20 01 00 01 00 00 00 00]')
    print('  4 = Type 0x21 [21 01 00 00]')
    print('  5 = Status OK [20 00 00 00]')
    print('  6 = Large payload')
    print('  7 = DNAS Success [01 00 00 00] <-- TRY THIS')
    print('  8 = DNAS + prefix [20 01 00 00 00]')
    print('  9 = Echo + DNAS [20 01 00 01 01 00 00 00]')
    print()

    mode_24 = input('0x24 response mode [0-3, default=1]: ').strip()
    mode_24 = int(mode_24) if mode_24.isdigit() else 1

    mode_20 = input('0x20 response mode [0-9, default=7]: ').strip()
    mode_20 = int(mode_20) if mode_20.isdigit() else 7

    print(f'\nUsing: 0x24 mode={mode_24}, 0x20 mode={mode_20}')
    print('Press Ctrl+C to stop\n')

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((HOST, PORT))
        server.listen(5)

        while True:
            print('Waiting for MAG client...')
            conn, addr = server.accept()
            conn.settimeout(30)

            with conn:
                client_ip = f'{addr[0]}:{addr[1]}'
                print(f'\n[{datetime.now()}] Connection from {client_ip}')

                with open(log_file, 'a') as lf:
                    lf.write(f'\n{"="*60}\n')
                    lf.write(f'Connection from {client_ip} at {datetime.now()}\n')
                    lf.write(f'0x24 mode: {mode_24}, 0x20 mode: {mode_20}\n')
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
                            msg_type = data[0] if data else 0

                            # Log received
                            print(f'\n[RECV {packet_num}] {len(data)} bytes (type 0x{msg_type:02x}):')
                            print(hexdump(data, '  '))

                            lf.write(f'\n[RECV {packet_num}] {len(data)} bytes (type 0x{msg_type:02x})\n')
                            lf.write(hexdump(data) + '\n')

                            # Save raw
                            raw_file = os.path.join(LOG_DIR, f'v2_{timestamp}_{packet_num:03d}_recv.bin')
                            with open(raw_file, 'wb') as rf:
                                rf.write(data)

                            # Determine response based on message type
                            response = None
                            if msg_type == 0x24:
                                response = respond_0x24(data, mode_24)
                            elif msg_type == 0x20:
                                response = respond_0x20(data, mode_20)
                            else:
                                print(f'  Unknown message type: 0x{msg_type:02x}')
                                lf.write(f'  Unknown message type: 0x{msg_type:02x}\n')

                            # Send response
                            if response:
                                print(f'\n[SEND] {len(response)} bytes:')
                                print(hexdump(response, '  '))

                                lf.write(f'\n[SEND] {len(response)} bytes\n')
                                lf.write(hexdump(response) + '\n')

                                conn.sendall(response)

                                sent_file = os.path.join(LOG_DIR, f'v2_{timestamp}_{packet_num:03d}_sent.bin')
                                with open(sent_file, 'wb') as sf:
                                    sf.write(response)

                            lf.flush()

                        except socket.timeout:
                            print('Connection timed out')
                            lf.write('\n--- Timeout ---\n')
                            break
                        except ConnectionResetError:
                            print('Connection reset')
                            lf.write('\n--- Reset ---\n')
                            break
                        except Exception as e:
                            print(f'Error: {e}')
                            lf.write(f'\n--- Error: {e} ---\n')
                            break

                    print(f'\nSession ended. {packet_num} packets.')

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print('\nStopped.')
    except PermissionError:
        print(f'Permission denied. Try: sudo python3 {sys.argv[0]}')
        sys.exit(1)
