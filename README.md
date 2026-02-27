# 🛰️ net-sniff-rs

A high-performance, real-time network protocol analyzer built with **Rust**, featuring a terminal-based UI (TUI) powered by `ratatui`. Designed for low-level packet inspection with an emphasis on clarity and high-end terminal aesthetics.



## ✨ Features

* **Live Traffic Feed**: Real-time packet capture with protocol identification (HTTP, DNS, TCP, UDP, ARP, ICMP).
* **Time-Slice "Spike" Inspection**: 
    * Pause the feed to "freeze" the network history.
    * Scrub through the throughput graph with `←`/`→` to isolate specific 1-second windows.
    * The packet list automatically filters to show only traffic that occurred during that specific spike.
* **🏆 Top Talker Heuristics**: While in Spike Mode, the app automatically identifies the primary application responsible for the bandwidth burst.
* **Dual-Pane Deep Inspector**: 
    * **Upper Panel**: Statistical summary of the selected time window (Total Load, Packet Count, Top App).
    * **Lower Panel**: Full packet breakdown including **Hex/ASCII Dual View** and transport layer headers.
* **Process Mapping**: Automatically correlates socket inodes to local process names (Linux via `procfs`).
* **Cross-Platform Support**: Specialized builds for both **Linux (Hyprland/Wayland optimized)** and **macOS (Apple Silicon/Intel)**.
* **Vim-style Navigation**: Fast scrolling with `j`/`k` and instant search with `/`.

---

## 🚀 Getting Started

### Prerequisites

Ensure you have the necessary PCAP development headers installed:

```bash
# Arch Linux
sudo pacman -S libpcap

# Ubuntu/Debian
sudo apt-get install libpcap-dev

# macOS
brew install libpcap
```
### Building from source

```bash
# Clone the repository
git clone [https://github.com/xmax17/net-sniff.git](https://github.com/xmax17/net-sniff.git)
cd net-sniff

# Compile the release binary
cargo build --release
```

Run it with sudo

```bash
# On Linux or macOS
sudo ./target/release/net-sniff
```
