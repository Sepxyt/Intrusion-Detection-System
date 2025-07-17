

#  Basic Intrusion Detection System (IDS) with Python

This is a simple, real-time Intrusion Detection System built using Python and Scapy. It listens to live network traffic and alerts you to potential SYN scan activities — a common method used by attackers for reconnaissance.

##  Features

-  Real-time network packet sniffing
-  Detects potential TCP SYN scan attempts
-  Lightweight and written in pure Python
-  Console alerts for suspicious traffic

---

##  How It Works

The IDS continuously monitors packets on the network interface and checks for SYN packets (TCP packets with only the SYN flag set). If it detects multiple SYN packets from the same IP without completing the handshake, it flags it as a potential scan.

---

##  Requirements

- Python 3.x
- [Scapy](https://scapy.net/)
- WinPcap or Npcap (for Windows users)

Install dependencies:

```bash
pip install scapy

