# 🛰️ net-sniff

A high-performance, real-time network protocol analyzer built with **Rust**, featuring a terminal-based UI (TUI) powered by `ratatui`. Designed for low-level packet inspection with an emphasis on clarity and high-end terminal aesthetics.



[Image of network OSI model layers]


## ✨ Features

* **Live Traffic Feed**: Real-time packet capture with protocol identification (HTTP, HTTPS, DNS, TCP, UDP, ARP, ICMP).
* **Process Mapping**: Automatically identifies which local applications (e.g., Spotify, Zen Browser) are generating traffic.
* **Deep Inspector**: Multi-layered breakdown of Network (IPv4/v6) and Transport (TCP/UDP) layers including flags, sequence numbers, and TTL.
* **Hex/ASCII Dual View**: View raw packet payloads with side-by-side hexadecimal and ASCII representations.
* **Vim-style Navigation**: Fast scrolling with `j`/`k` and instant jumps with `g`/`G`.
* **Smart Filtering**: Real-time search and protocol filtering to isolate specific traffic streams.

## 🚀 Getting Started

### Prerequisites

Ensure you have the necessary PCAP development headers installed:

```bash
# Arch Linux
sudo pacman -S libpcap

# Ubuntu/Debian
sudo apt-get install libpcap-dev
