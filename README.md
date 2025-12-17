## Overview

C-Shark is a terminal-only network packet sniffer written in C using the libpcap library.
It captures live traffic from a selected network interface and performs layer-by-layer packet dissection, inspired by tools like Wireshark, but entirely from the command line.

The tool decodes packets across Ethernet, Network, Transport, and Application layers, displaying both human-readable fields and raw hex data for inspection.

## Key Features

- Live packet capture using libpcap
- Interactive interface discovery and selection
- Layer-by-layer decoding:
  - L2: Ethernet
  - L3: IPv4, IPv6, ARP
  - L4: TCP, UDP, ICMP
  - L7: DNS, HTTP, HTTPS (TLS), and unknown payloads
- Combined hex + ASCII payload dump
- Protocol-based filtering (TCP, UDP, DNS, HTTP, HTTPS, ARP)
- In-memory storage of last capture session
- Deep inspection of individual packets
- Graceful runtime controls:
  - Ctrl+C → stop capture and return to menu
  - Ctrl+D → exit cleanly

## Build & Run

### Requirements

- Linux / WSL / Unix-like OS
- libpcap

Install dependencies:

```bash
sudo apt update
sudo apt install build-essential libpcap-dev
```

Compile:

```bash
gcc cshark.c -o cshark -lpcap
```

Run (requires root):

```bash
sudo ./cshark
```

## Usage Flow

1. Select a network interface from the detected list
2. Choose an action:
   - Start sniffing (all packets)
   - Start sniffing with protocol filters
   - Inspect packets from the last session
3. View decoded packets live in the terminal
4. Stop capture with Ctrl+C
5. Inspect any packet in detail by Packet ID

## Packet Decoding Capabilities

### Ethernet (L2)

- Source & destination MAC
- EtherType identification

### Network Layer (L3)

- IPv4: source/destination IP, TTL, flags, ID, protocol
- IPv6: addresses, hop limit, flow label
- ARP: request/reply, sender/target IP & MAC

### Transport Layer (L4)

- TCP: ports, sequence/ack numbers, flags, window size
- UDP: ports, length, checksum
- ICMP: echo requests/replies

### Application Layer (L7)

- Protocol identification using ports
- Payload length
- Hex + ASCII dump (first bytes)

## Project Origin

This project was designed and implemented entirely by me as part of the
CS3 – Operating Systems & Networks (Monsoon 2025) course at IIIT Hyderabad.

This repository contains a cleaned, standalone public version of the project.

## Notes

- Must be run with sudo to access raw packets
- Designed as a passive sniffer (no packet injection)
- Intended for learning and inspection, not production use
- Verified against Wireshark for correctness

**[C-Shark] Silent. Precise. Watching the wire.**
