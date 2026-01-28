# MAG Protocol Capture Analysis

**Date:** January 27, 2026
**Game:** MAG (Massive Action Game) - PS3
**Title ID:** BCUS98110 (US)
**Developer:** Zipper Interactive / SCEA

---

## 1. Connection Details

| Parameter | Value |
|-----------|-------|
| Domain | `mag.ps3.online.scea.com` |
| Port | **10073** (TCP) |
| Protocol | Custom binary with X.509 certificate exchange |
| PS3 IP | 192.168.10.201 |
| Server IP | 192.168.10.200 |

---

## 2. Protocol Flow

```
PS3 (Client)                                    Server
     |                                              |
     |-------- [0x24] Certificate (727 bytes) ---->|
     |                                              |
     |<------- [0x24] Response (8 bytes) ----------|
     |                                              |
     |-------- [0x20] Query (4 bytes) ------------>|
     |                                              |
     |<------- [0x20] Response -------------------|
     |                                              |
     X         Connection closed by client         X
```

---

## 3. Message Type 0x24 - Client Certificate

### Raw Hex Dump (727 bytes)

```
0000  24 d4 02 01 00 70 00 03 00 00 06 00 04 01 00 c2   $....p..........
0010  02 30 82 02 be 30 82 01 a6 a0 03 02 01 02 02 14   .0...0..........
0020  01 00 00 00 00 00 00 00 00 00 00 00 42 00 00 00   ............B...
0030  00 00 00 90 30 0d 06 09 2a 86 48 86 f7 0d 01 01   ....0...*.H.....
0040  05 05 00 30 81 96 31 0b 30 09 06 03 55 04 06 13   ...0..1.0...U...
0050  02 55 53 31 0b 30 09 06 03 55 04 08 13 02 43 41   .US1.0...U....CA
0060  31 12 30 10 06 03 55 04 07 13 09 53 61 6e 20 44   1.0...U....San D
0070  69 65 67 6f 31 31 30 2f 06 03 55 04 0a 13 28 53   iego110/..U...(S
0080  4f 4e 59 20 43 6f 6d 70 75 74 65 72 20 45 6e 74   ONY Computer Ent
0090  65 72 74 61 69 6e 6d 65 6e 74 20 41 6d 65 72 69   ertainment Ameri
00a0  63 61 20 49 6e 63 2e 31 14 30 12 06 03 55 04 0b   ca Inc.1.0...U..
00b0  13 0b 53 43 45 52 54 20 47 72 6f 75 70 31 1d 30   ..SCERT Group1.0
00c0  1b 06 03 55 04 03 13 14 53 43 45 52 54 20 52 6f   ...U....SCERT Ro
00d0  6f 74 20 41 75 74 68 6f 72 69 74 79 30 1e 17 0d   ot Authority0...
00e0  30 35 31 31 32 32 30 30 32 36 32 39 5a 17 0d 33   051122002629Z..3
00f0  35 31 31 32 31 32 33 35 39 35 39 5a 30 63 31 0c   51121235959Z0c1.
0100  30 0a 06 03 55 04 06 13 03 55 53 41 31 0b 30 09   0...U....USA1.0.
0110  06 03 55 04 08 13 02 43 41 31 12 30 10 06 03 55   ..U....CA1.0...U
0120  04 07 13 09 53 61 6e 20 44 69 65 67 6f 31 0d 30   ....San Diego1.0
0130  0b 06 03 55 04 0a 13 04 53 43 45 41 31 0f 30 0d   ...U....SCEA1.0.
0140  06 03 55 04 0b 13 06 5a 69 70 70 65 72 31 12 30   ..U....Zipper1.0
0150  10 06 03 55 04 03 13 09 4d 41 47 20 32 30 32 33   ...U....MAG 2023
0160  31 30 5c 30 0d 06 09 2a 86 48 86 f7 0d 01 01 01   10\0...*.H......
0170  05 00 03 4b 00 30 48 02 41 00 c2 2b ea ac e0 82   ...K.0H.A..+....
0180  a8 b1 95 e2 00 6f b2 29 c8 f9 b8 62 6e b0 84 3b   .....o.)...bn..;
0190  5e 2f 9b 0b f0 41 5d d7 3b 97 48 f7 d5 76 00 b9   ^/...A].;.H..v..
01a0  32 86 10 c8 21 72 5a 8c d0 34 3d 17 ef 48 1b 45   2...!rZ..4=..H.E
01b0  9a a7 6a d1 df 17 27 2c db 37 02 03 00 00 11 30   ..j...',.7.....0
01c0  0d 06 09 2a 86 48 86 f7 0d 01 01 05 05 00 03 82   ...*.H..........
01d0  01 01 00 8a b2 c7 b3 97 22 ea e9 7a bc 20 aa 84   ........"..z. ..
01e0  65 29 85 42 15 21 c5 83 fd 4c 9d 29 0c 92 ef e1   e).B.!...L.)....
01f0  8e 18 ba 30 37 6d 8e ac 85 39 59 c0 fc d0 b6 37   ...07m...9Y....7
0200  ce 19 9e 06 6c 8e 09 63 cf 19 38 a0 ee 84 43 19   ....l..c..8...C.
0210  ac c2 b8 2a 0f 99 62 06 46 91 e4 bc c3 b6 6e b6   ...*..b.F.....n.
0220  f5 04 0d cc 6d d8 86 51 46 32 db 32 6e 81 81 72   ....m..QF2.2n..r
0230  4e 4b 13 75 83 2d 1f 68 be eb 6d 98 38 65 05 f6   NK.u.-.h..m.8e..
0240  ca 07 99 09 79 38 a7 e3 51 c5 4d 60 85 c6 0b b6   ....y8..Q.M`....
0250  72 78 67 86 0b 91 ca d3 8f b6 63 ee ea 55 e0 05   rxg.......c..U..
0260  c5 51 22 25 81 28 d4 80 77 79 c8 63 e8 74 ac 57   .Q"%.(..wy.c.t.W
0270  c8 a5 b3 ba 56 7b 0d 66 f6 78 93 b3 76 2f 6f 2b   ....V{.f.x..v/o+
0280  bb 05 db 62 67 08 51 10 b9 c5 f2 7c 70 bc ca 9f   ...bg.Q....|p...
0290  83 ef ed ab a6 eb b9 4d fe e1 44 82 e9 a8 2a 20   .......M..D...*
02a0  6c 94 9c 44 20 95 0a 68 b0 ec 29 a7 a8 45 c4 8d   l..D ..h..)..E..
02b0  94 41 88 21 87 77 24 ce 44 6f f8 ed 9d e7 47 95   .A.!.w$.Do....G.
02c0  b5 d4 4c c8 19 32 f8 59 3e 68 4a 31 9d 19 94 3d   ..L..2.Y>hJ1...=
02d0  bf 48 63 00 00 00 00                              .Hc....
```

### Header Analysis

| Offset | Bytes | Value | Description |
|--------|-------|-------|-------------|
| 0x00 | 1 | `24` | Magic byte / Message type |
| 0x01-02 | 2 | `d4 02` | Length? (0x02d4 = 724 little-endian) |
| 0x03 | 1 | `01` | Version? |
| 0x04-05 | 2 | `00 70` | Unknown |
| 0x06-07 | 2 | `00 03` | Unknown |
| 0x08+ | ... | ... | Certificate data |

### Certificate Chain (X.509)

**Root CA Certificate:**
| Field | Value |
|-------|-------|
| Country | US |
| State | CA |
| City | San Diego |
| Organization | SONY Computer Entertainment America Inc. |
| OU | SCERT Group |
| CN | SCERT Root Authority |
| Valid From | 2005-11-22 |
| Valid Until | 2035-11-21 |

**Game Certificate:**
| Field | Value |
|-------|-------|
| Country | USA |
| State | CA |
| City | San Diego |
| Organization | SCEA |
| OU | Zipper |
| CN | MAG 202310 |

---

## 4. Message Type 0x20 - Query/Command

### Raw Hex Dump (4 bytes)

```
0000  20 01 00 01                                        ...
```

### Structure Analysis

| Offset | Bytes | Description |
|--------|-------|-------------|
| 0x00 | `20` | Message type |
| 0x01 | `01` | Command/request type? |
| 0x02-03 | `00 01` | Sequence number or parameter? |

---

## 5. Response Attempts

### 0x24 Responses Tested

| Response | Hex | Result |
|----------|-----|--------|
| None (empty) | - | Client waits indefinitely, no 0x20 sent |
| Simple ACK (8 bytes) | `24 00 00 02 00 00 00 00` | Triggers 0x20, then disconnect |
| Mirror header (16 bytes) | `24 08 00 02 00 00 00 00 00 00 00 00 00 00 00 00` | Triggers 0x20, then disconnect |
| Type 2 + fields | `24 04 00 02 00 70 00 03 00 00 06 00 04 01 00 00` | Triggers 0x20, then disconnect |

**Conclusion:** Any response triggers 0x20, but client expects proper server certificate.

### 0x20 Responses Tested

| Response | Hex | Result |
|----------|-----|--------|
| Echo | `20 01 00 00` | Disconnect |
| ACK | `20 02 00 00` | Disconnect |
| Longer | `20 01 00 01 00 00 00 00` | Disconnect |
| Type 0x21 | `21 01 00 00` | Disconnect |
| Status OK | `20 00 00 00` | Disconnect |
| DNAS Success | `01 00 00 00` | Disconnect |
| DNAS + prefix | `20 01 00 00 00` | Disconnect |
| Echo + DNAS | `20 01 00 01 01 00 00 00` | Disconnect |
| Response ID 02 | `20 02 00 01` | Disconnect |
| Echo exact | `20 01 00 01` | Disconnect |

**Conclusion:** None of the 0x20 responses work - likely because 0x24 handshake isn't complete.

---

## 6. Key Findings

1. **Port 10073** is in the Zipper VoIP/Squad Comms range (10070-10080)

2. **Client requires 0x24 response** before sending 0x20 message

3. **Certificate exchange is required** - Simple ACK responses don't complete handshake

4. **MAG uses Medius v3.0** for lobby/matchmaking (same as SOCOM, Warhawk)

5. **DNAS Authentication** is the main blocker - game won't proceed without valid response

---

## 7. Network Ports (from documentation)

| Protocol | Port Range | Purpose |
|----------|-----------|---------|
| TCP | 80, 443 | HTTP/HTTPS (Login & Store) |
| TCP | 5223 | PSN Chat / Medius Master Server |
| UDP | 3478, 3479 | STUN (NAT Traversal) |
| UDP | 3658 | Main Game Data (standard PSN) |
| UDP | 50000-50100 | Zipper Proprietary (Game State) |
| UDP | 10070-10080 | VoIP and Squad Comms |

---

## 8. DNS Queries Observed

| Domain | Purpose |
|--------|---------|
| `mag.ps3.online.scea.com` | **MAG Game Server** |
| `UP9000-BCUS98110-00.auth.np.ac.playstation.net` | Game Authentication |
| `getprof.*.np.community.playstation.net` | Player Profiles |
| `a0.ww.np.dl.playstation.net` | Downloads |
| `fus01.ps3.update.playstation.net` | Firmware Updates |

---

## 9. Files Generated

### Capture Files
| File | Description |
|------|-------------|
| `mag-captures/mag_capture_*.log` | Session logs with hex dumps |
| `mag-captures/mag_capture_*.bin` | Raw binary captures |
| `mag-captures/packet_*_recv.bin` | Individual received packets |
| `mag-captures/packet_*_sent.bin` | Individual sent packets |
| `mag-captures/mag_v2_*.log` | Protocol v2 server logs |
| `mag-captures/mag_debug_*.log` | Debug server logs |

### Tools Created
| File | Description |
|------|-------------|
| `mag-listener.py` | Simple TCP listener, captures raw data |
| `mag-server.py` | Basic server with response modes |
| `mag-server2.py` | Advanced server with 0x24/0x20 handling |
| `mag-debug.py` | Interactive protocol debugger |

### Usage

```bash
# Simple capture
sudo python3 mag-listener.py

# Response testing
sudo python3 mag-server2.py

# Interactive debugging
sudo python3 mag-debug.py
```

---

## 10. Protocol Behavior Summary

### Key Observations

1. **0x24 Response Required**
   - If server sends NO response to 0x24, client waits indefinitely
   - If server sends ANY response (even wrong), client proceeds to 0x20
   - Client always disconnects after 0x20 exchange

2. **Certificate Exchange is Blocking**
   - Simple ACK responses don't complete the handshake
   - Client likely expects a real server certificate signed by SCERT
   - Without proper cert exchange, 0x20 will always fail

3. **0x20 Message Purpose**
   - Sent immediately after receiving any 0x24 response
   - Format: `20 01 00 01` (4 bytes)
   - Likely a "waiting for handshake completion" or session request
   - All tested responses result in disconnect

### Protocol State Machine

```
[Client]                              [Server]
    |                                     |
    |------ 0x24 (Certificate) --------->|
    |                                     |
    |<----- 0x24 (Server Cert?) ---------|  <-- We fail here
    |                                     |
    |------ 0x20 (Session Request?) ---->|
    |                                     |
    |<----- 0x20 (Session Response?) ----|  <-- Never succeeds
    |                                     |
    |       [Continue to game...]         |
```

---

## 11. Next Steps for Revival

1. **Implement proper certificate response** - Server needs to send valid certificate back, not just header ACK

2. **Study medius-crypto** - https://github.com/hashsploit/medius-crypto for encryption/certificate handling

3. **Contact PSONE community** - https://discord.com/invite/uhZuGX9 - Share these captures

4. **Analyze Clank project** - https://github.com/hashsploit/clank for Medius protocol handling

5. **DNAS bypass** - May require CFW or certificate injection on PS3

6. **Find original PCAPs** - Server certificates from 2010-2014 captures could help

7. **Reverse engineer client** - Analyze MAG EBOOT to understand expected response format

---

## 12. Resources

- **PSONE (PS Online Network Emulated):** https://www.psone.online/home
- **Clank (Medius Server):** https://github.com/hashsploit/clank
- **Medius Crypto:** https://github.com/hashsploit/medius-crypto
- **PSRewired:** https://psrewired.com/

---

---

*Documentation compiled from packet captures on January 27, 2026*
*Last updated: January 27, 2026 - Added protocol behavior analysis and response testing results*
