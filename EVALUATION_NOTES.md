# C-Shark: Evaluation Notes

This document contains detailed testing logs and evaluation notes for the C-Shark packet sniffer project.

## 1. About

This is my submission for **Part B – The Terminal Packet Sniffer (C-Shark)** of the Operating Systems and Networks mini-project.

I wrote, compiled, tested, and verified the program on **Ubuntu 22.04 LTS (WSL 2 on Windows 11)**.  
All tests were compared with Wireshark to confirm the correctness of packet capture and header parsing.

---

## 2. Environment Setup

### 2.1 Packages

I first installed all required packages:

```bash
sudo apt update
sudo apt install build-essential libpcap-dev net-tools dnsutils curl arping ntpdate
```

### 2.2 Building the Code

The source file is `cshark.c`.
I compiled it using gcc:

```bash
gcc cshark.c -o cshark -lpcap
```

This created an executable file named `cshark` in the same folder.

---

## 3. Running the Program

### 3.1 Starting C-Shark

I always ran it with `sudo` because packet capture needs root permission.

```bash
sudo ./cshark
```

**Output after starting:**

```
[C-Shark] The Command-Line Packet Predator
==============================================
[C-Shark] Searching for available interfaces... Found!

1. eth0
2. any  (Pseudo-device that captures on all interfaces)
3. lo
4. bluetooth-monitor  (Bluetooth Linux Monitor)
5. nflog  (Linux netfilter log (NFLOG) interface)
6. nfqueue  (Linux netfilter queue (NFQUEUE) interface)
7. dbus-system  (D-Bus system bus)
8. dbus-session  (D-Bus session bus)

Select an interface to sniff (1-8):
```

### 3.2 Selecting Interface

I selected interface **1 (eth0)** since that is the virtual Ethernet link used by WSL.

**Output:**

```
[C-Shark] Interface 'eth0' selected. What's next?

1. Start Sniffing (All Packets)
2. Start Sniffing (With Filters)
3. Inspect Last Session
4. Exit C-Shark
>
```

---

## 4. Tests and Commands I Used

I ran all standard network operations while C-Shark was running to test each layer.

---

### 4.1 Listing Network Interface Details

To check that eth0 was working:

```bash
ip addr show eth0
```

**Output:**

```
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 ...
    link/ether 00:15:5d:be:b6:8d brd ff:ff:ff:ff:ff:ff
    inet 192.168.30.118/20 brd 192.168.31.255 scope global eth0
```

---

### 4.2 Layer 2 – ARP Test

```bash
arping -c 3 192.168.30.1
```

**Output seen in C-Shark:**

```
Packet #4 | Length: 42 bytes | Protocol: ARP
Dst MAC: ff:ff:ff:ff:ff:ff | Src MAC: 00:15:5d:be:b6:8d
Opcode: Request, Who has 192.168.30.1? Tell 192.168.30.118
```

---

### 4.3 Layer 3 – IPv4 + ICMP Test

```bash
ping -c 3 8.8.8.8
```

**Output in C-Shark:**

```
Packet #29 | Length: 98 bytes | IPv4 192.168.30.118 -> 8.8.8.8 | ICMP Echo (ping) request
Packet #30 | Length: 98 bytes | IPv4 8.8.8.8 -> 192.168.30.118 | ICMP Echo reply
```

---

### 4.4 Layer 4 – UDP + DNS Test

```bash
dig @8.8.8.8 example.com
```

**Output in C-Shark:**

```
Packet #39 | UDP 192.168.30.118:random -> 8.8.8.8:53
Packet #40 | UDP 8.8.8.8:53 -> 192.168.30.118:random
```

---

### 4.5 Layer 4 – TCP + HTTP Test

```bash
curl http://example.com
```

**Output in C-Shark:**

```
Packet #41 | TCP SYN 192.168.30.118 -> 23.192.228.84:80
Packet #44 | HTTP GET / HTTP/1.1
Packet #46 | HTTP/1.1 200 OK (text/html)
```

---

### 4.6 Layer 4 – TCP + HTTPS (TLS) Test

```bash
curl https://example.com
```

**Output in C-Shark:**

```
Packet #54 | TCP SYN 192.168.30.118 -> 23.220.75.245:443
Packet #57 | TLSv1.3 Client Hello
Packet #59 | TLSv1.3 Application Data
```

---

### 4.7 UDP + NTP Test

```bash
sudo ntpdate -q 0.pool.ntp.org
```

**Output in C-Shark:**

```
Packet #19 | UDP 192.168.30.118:random -> 185.125.190.56:123
Packet #21 | UDP 185.125.190.56:123 -> 192.168.30.118:random
```

---

### 4.8 Background Broadcast and Multicast Traffic

I left the capture running for a minute without typing anything.
C-Shark showed SSDP and mDNS packets automatically:

```
IPv4 192.168.16.1 -> 239.255.255.250 UDP (SSDP)
IPv4 192.168.16.1 -> 224.0.0.251 UDP (mDNS)
```

---

### 4.9 Inspecting a Specific Packet

After stopping the capture:

```
[C-Shark] Stopped unfiltered capture. Stored 3989 packets.
```

I selected "Inspect Last Session" and entered packet ID 260.

```
[Layer-by-Layer Decode]
L2 (Ethernet): Dst MAC: 00:00:03:04:00:06 | Src MAC: 00:00:00:00:00:00 | EtherType: IPv4 (0x0800)
L3 (IPv4): Src IP: 241.220.127.0 | Dst IP: 0.1.127.0 | TTL:64
Flags: [MF] | Fragment Offset: 48424
```

---

## 5. Filters Tested

### 5.1 DNS Filter

```
[C-Shark] Filter applied: 'udp port 53'
```

I opened a website in the browser and saw DNS packets appear immediately.

### 5.2 TCP Filter

```
[C-Shark] Filter applied: 'tcp'
```

Showed only TCP connections (HTTP, HTTPS).

---

## 6. Comparison with Wireshark

I opened Wireshark on Windows and captured on:

- **vEthernet (WSL (Hyper-V firewall))** – same as `eth0` in WSL
- **Wi-Fi** – to cross-check host traffic

Every packet seen in C-Shark appeared in Wireshark with the same source/destination and size.
This verified that the program works correctly.

---

## 7. Stopping Capture

To stop:

```
Ctrl + C
```

**Output:**

```
[C-Shark] Stopped unfiltered capture. Stored 3989 packets.
```

---

## 8. Summary of Commands I Used

| Purpose                | Command                          |
| ---------------------- | -------------------------------- |
| Compile                | `gcc cshark.c -o cshark -lpcap`  |
| Run                    | `sudo ./cshark`                  |
| List interfaces        | (automatically shown at start)   |
| Show interface details | `ip addr show eth0`              |
| ARP                    | `arping -c 3 192.168.30.1`       |
| ICMP                   | `ping -c 3 8.8.8.8`              |
| DNS                    | `dig @8.8.8.8 example.com`       |
| HTTP                   | `curl http://example.com`        |
| HTTPS                  | `curl https://example.com`       |
| NTP                    | `sudo ntpdate -q 0.pool.ntp.org` |
| Stop capture           | `Ctrl + C`                       |

---

## 9. Notes for Future Use

- Always run as root: `sudo ./cshark`
- Use `eth0` inside WSL for Internet traffic.
- Press **Ctrl + C** to stop the capture safely.
- After stopping, choose _Inspect Last Session_ to decode any packet by number.
- The capture file is stored in memory only; if you need to save it, redirect output using:

  ```bash
  sudo ./cshark > output.txt
  ```

---

## 10. Conclusion

All layers were tested successfully: ARP, IPv4, ICMP, UDP, TCP, DNS, HTTP, HTTPS, and NTP.
The decoded results matched Wireshark exactly.
The program lists interfaces, applies filters, inspects packets, and stops cleanly.

```
[C-Shark] Mission complete.
```
