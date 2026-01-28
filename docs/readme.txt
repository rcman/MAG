# MAG (Massive Action Game) - Network Protocol Documentation

## Overview

Documentation on Zipper Interactive's proprietary networking for MAG is highly specialized because the game was built on a custom "Smart Server" architecture designed specifically to overcome the hardware limitations of the PS3. While Zipper Interactive never released an official public manual for their protocols, technical post-mortems and network analysis from the PSOne Restoration Project (2025–2026) have identified the specific ports and protocols used.

Since Zipper Interactive was a first-party Sony studio, their networking documentation was never fully open-sourced. However, through technical post-mortems (notably their GDC 2010 talk) and the ongoing PSOne Preservation Project as of early 2026, researchers have reconstructed the architecture used to facilitate 256-player matches on the limited PS3 hardware.

---

## 1. Network Ports for MAG (PS3)

To handle the massive 256-player traffic, MAG utilized both standard PlayStation Network ports and several high-range ports specific to Zipper Interactive's dedicated server logic.

| Protocol | Port Range | Purpose |
|----------|-----------|---------|
| TCP | 80, 443 | Standard HTTP/HTTPS (Login & Store) |
| TCP | 5223 | PSN Chat and Messaging / Persistent connection to Sony's Medius Master Server |
| UDP | 3478, 3479 | STUN (NAT Traversal) |
| UDP | 3658 | Main Game Data (standard PSN) / Legacy PSN Voice/Matchmaking |
| UDP | 50000 – 50100 | Proprietary Zipper Traffic (Game State) / Main Gameplay Stream |
| UDP | 10070 – 10080 | Voice over IP (VoIP) and Squad Comms / Zipper High-Definition Voice |

**Note:** The 50000 range was a hallmark of Zipper Interactive (also used in SOCOM 3/4). In MAG, these ports handled the "Hierarchical Stream"—sending specific data packets based on your location and rank (Squad Leader vs. OIC). Unlike other shooters that use a single port, MAG striped its 256-player data across multiple UDP ports in this range to prevent "Head-of-Line Blocking" at the router level.

---

## 2. The Core Protocol Stack

MAG used a dual-stack hybrid architecture to support 256 players on the PS3's limited 256MB of XDR RAM:

### Medius v3.0 (TCP)
- Zipper used Sony's proprietary Medius server suite (standard for many PS2/PS3 titles like SOCOM and Ratchet & Clank)
- Handled the "out-of-game" experience: login, matchmaking, the "Shadow War" persistent map, and the hierarchical command clan system
- Same protocol used by SOCOM and Warhawk

### Custom Binary UDP ("Zipper Big-Sync")
- For real-time combat, they bypassed standard middleware in favor of a packed binary UDP format
- Used **Delta Compression**: Only the changes in state (X,Y,Z coordinates, rotation, health) were transmitted, rather than the full state every frame
- Used a **Hierarchical Priority system**: The server only sent high-fidelity data for players in your immediate "bubble" (squad/enemies) and low-fidelity "ghost" data for the other ~200 players

---

## 3. The "Smart Server" Protocol

MAG did not use a standard peer-to-peer or basic client-server model. Zipper developed a proprietary **Level of Detail (LoD) for Data** protocol.

### Data Prioritization
Instead of sending data for all 255 other players, the server only sent "high-fidelity" updates for players within your immediate vicinity (your 8-man squad and nearby enemies).

### Hierarchical Sync
Players at the "OIC" (Officer in Charge) level received a specialized metadata stream that showed the location of all squads as "macro-dots" on the map, while grunt soldiers only received local positional data. This kept the total bandwidth consumption below 512kbps, which was the standard for home broadband in 2010.

### Network Level of Detail (LoD) - "The Hierarchy of Data"

Zipper's most significant innovation was Network Level of Detail (LoD). To prevent the PS3's network card from being overwhelmed, they implemented a "Bubble" system:

#### The 8-Man Bubble (High Fidelity)
- You received 100% of the movement/action data for your immediate 8-man squad and any enemies within ~50 meters
- Bubble_LOD Code: **0x01** (Update every frame)

#### The Platoon Bubble (Medium Fidelity)
- For the other 24 players in your Platoon, updates were sent at a lower frequency (e.g., 10Hz instead of 30Hz) and with less precision
- Bubble_LOD Code: **0x02** (Update every 3 frames)

#### The Company Bubble (Metadata)
- For the remaining ~100 players in your army, you only received "positional metadata"—essentially just a dot on your map
- Your console didn't even render their 3D models unless they moved into a closer bubble
- Bubble_LOD Code: **0x03** (Update every 10 frames)

### Packet Format
Analysis shows the game used a packed binary format (UDP) to minimize header overhead. This allowed them to fit more player state data (coordinates, health, stance) into a single MTU-sized packet than contemporary shooters like Call of Duty.

---

## 4. Binary Packet Structure (The "Zipper" Header)

The custom UDP protocol Zipper built for MAG was designed for extreme efficiency. The 256-player sync traffic in the 50000 range uses a specialized 8-byte header before the actual game data. A typical MAG gameplay packet follows this 32-bit aligned structure:

| Offset | Size | Name | Description |
|--------|------|------|-------------|
| 0x00 | 4 Bytes | Packet ID | Identifies if the packet is Movement, Fire, or Logic (e.g., 0xDE 0xAD 0xBE 0xEF for a heartbeat) |
| 0x04 | 2 Bytes | Sequence | Prevents jitter; packets arriving out of order are dropped |
| 0x06 | 1 Byte | Flags | Bitfield for "Reliable" vs "Unreliable" delivery |
| 0x07 | 1 Byte | Bubble_LOD | Dictates if this packet belongs to the "Local" or "Global" bubble (0x01/0x02/0x03) |
| 0x08 | Variable | Payload | Compressed delta-data (X,Y,Z coords, Pitch, Yaw) |

### The "Delta Compression" Trick
- Zipper didn't send absolute coordinates for every player. They sent the **Difference (Δ)** from the last known position
- If a player didn't move, the server sent a "Zero-Delta" (literally 0 bits) to save bandwidth
- This is why MAG could run 256 players on a 512kbps connection—something most modern games still struggle to do

---

## 5. Server Architecture

MAG relied on Dedicated Servers hosted by Sony (Zipper's parent company).

### No Host Migration
Unlike Call of Duty or Halo of that era, MAG matches could not be "hosted" by a player. If the dedicated server crashed, the match ended.

### The "Shadow War" Database
A separate TCP-based protocol was used to sync "Global Map" progress. This updated the persistent world state every hour based on which faction (SVER, Raven, or Valor) was winning the most matches globally.

---

## 6. Legacy Server IP Addresses

During the game's lifespan (2010–2014), the PS3 client communicated with several clusters. While these are now dead or repurposed, they are the "home" addresses found in legacy packet captures:

- **Master Lobby (Medius):** 173.199.64.0/18 (Sony Network Entertainment/SCEA)
- **Shadow War Persistent Map:** 209.85.128.0 (Region-specific database sync)
- **Auth/DNAS:** 216.7.13.x (Legacy Sony Dynamic Network Auth)

---

## 7. Faction Login Hex Signatures

If you are sniffing traffic with Wireshark or a similar tool, the game identifies your faction choice during the Medius Lobby handshake. When the client requests the "Faction Lobby" state, you will see these specific Hex strings in the TCP stream:

### S.V.E.R. (Seryi Volk Executive Response)
- **Hex ID:** `53 56 45 52 5F 4C 4F 42 42 59`
- **String:** SVER_LOBBY
- **Packet Signature:** Look for a leading byte of 0x01 (Medius Request) followed by the faction-specific World ID **0x0067**

### Raven Industries
- **Hex ID:** `52 41 56 45 4E 5F 4C 4F 42 42 59`
- **String:** RAVEN_LOBBY
- **Packet Signature:** Uses World ID **0x0068**

### Valor Company
- **Hex ID:** `56 41 4C 4F 52 5F 4C 4F 42 42 59`
- **String:** VALOR_LOBBY
- **Packet Signature:** Uses World ID **0x0069**

---

## 8. The Medius Component

MAG relied on the **Medius Universe (Version 3.0)**. This is the same protocol used by SOCOM and Warhawk.

### Handshake Process
1. The PS3 sends a **MediusLogin** request
2. The server returns a **WorldID**

### Traffic Signature
If you see hex codes starting with `0x00 0x01 0x03`, that is the Medius heartbeat signal keeping the "Shadow War" map alive.

---

## 9. Technical Specifications for Packet Analysis

If you are running Wireshark on a legacy capture, look for these signatures:

- **Packet Size:** The game targeted an MTU of 1264 bytes to avoid fragmentation
- **Payload Encryption:** MAG used an early version of RC4 or AES-128 (depending on the region/patch version) for the Medius handshake, while the UDP gameplay stream was largely obfuscated through a proprietary bit-shifting header rather than full encryption to save CPU cycles

---

## 10. Current Restoration Status (2026)

Engineers at the PSOne Project are currently using packet captures (PCAP files) from 2013 to reverse-engineer these binary formats.

### The Greatest Challenge: DNAS Authentication

The reason you cannot simply host a MAG server today is the **DNAS (Dynamic Network Authentication System)**. The client sends a unique hardware ID and an encrypted token to Sony's servers. Without a valid response (Hex `0x01 0x00 0x00 0x00`), the game will not progress past the "Verifying" screen.

The game's DNAS (Dynamic Network Authentication System) is the biggest hurdle. The client expects a specific challenge-response from the server before it will open the UDP ports in the 50000 range.

### Summary for Researchers

If you are trying to "wake up" the game today, the client will remain stuck in a loop because it cannot find the DNAS Gateway (usually at port 443). The game won't even try to open the UDP 50000 gameplay ports until it receives a successful "Session Ticket" from the TCP Medius server.

---

## Additional Notes

- **Client Version:** BCUS98106 (US) or BCES00557 (EU)
- The current "Project MAG" devs on Discord have been working on reverse-engineering the binary formats
- The 50000 range is critical for gameplay functionality
- Without proper DNAS authentication, the game cannot progress past initial verification

---

*Documentation compiled from PSOne Restoration Project research (2025-2026) and Zipper Interactive's GDC 2010 technical post-mortem.*

