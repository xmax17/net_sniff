

# 🛰️ net-sniff-rs

[![Rust](https://img.shields.io/badge/language-rust-orange.svg)](https://www.rust-lang.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Platform](https://img.shields.io/badge/platform-linux%20%7C%20macos-lightgrey.svg)]()

A high-performance, real-time network protocol analyzer built with **Rust**, featuring a terminal-based UI (TUI) powered by `ratatui`. Designed for low-level packet inspection with high-end terminal aesthetics and "time-travel" debugging capabilities.

---

## ✨ Features

### 🔍 Deep Inspection & Search
* **Scoped Search**: Instantly filter traffic by `App Name`, `Summary (IP/Port)`, or even raw `Hex Dump` payloads.
* **Dual-Pane Inspector**: View transport layer headers alongside a **Hex/ASCII Dual View** for deep packet analysis.
* **Process Mapping**: Correlates socket inodes to local process names (via `procfs` on Linux).

### ⚡ Spike Analysis (Time-Travel)
* **Freeze-Frame**: Pause the live feed to capture a snapshot of current network history.
* **Timeline Scrubbing**: Use `←`/`→` to navigate the throughput graph and isolate specific 1-second windows.
* **Spike Heuristics**: Automatically identifies the "Top Talker" (the app responsible for the bandwidth burst) within any selected window.

### 🎨 Aesthetics & Recording
* **Live Hot-Reload Themes**: Swap `.toml` color presets in real-time from the `./themes` folder without restarting.
* **One-Touch PCAP**: Toggle `w` to record live traffic to a timestamped PCAP file for external analysis in Wireshark.
* **Vim-style UX**: Efficient navigation with `j`/`k`, `h` for help, and `/` for instant filtering.

---

## ⌨️ Controls

| Key | Action |
| :--- | :--- |
| `1` / `2` | Switch between **Connections** and **Feed** tabs |
| `Space` | **Pause/Resume** live capture (Enables Inspector Mode) |
| `←` / `→` | **Scrub History** to analyze specific traffic spikes |
| `/` | Enter **Search Mode** |
| `Tab` | Cycle Search Scope (**App** → **Summary** → **Hex**) |
| `w` | Toggle **PCAP Recording** to disk |
| `t` | Open **Theme Browser** |
| `c` | Clear current session buffer |
| `h` | Toggle **Shortcuts Help** popup |
| `q` | Quit |

---

## 🎨 Theme Customization

`net-sniff-rs` supports dynamic themes via TOML. Create a `.toml` file in the `./themes` directory and select it in-app with `t`. The watcher will automatically update the UI on save.

**Example: `themes/matrix.toml`**
```toml
[colors]
rx = [0, 255, 70]
tx = [0, 150, 0]
total = [50, 255, 50]
border_focus = [200, 255, 200]
highlight_bg = [0, 255, 0]
# See template.toml for a full list of keys
```

---

## 🚀 Installation

### 1. Prerequisites

Ensure you have the necessary PCAP development headers installed:

```bash
# Arch Linux
sudo pacman -S libpcap

# Ubuntu/Debian
sudo apt-get install libpcap-dev

# macOS
brew install libpcap
```

### 2. Build & Run

```bash
git clone [https://github.com/xmax17/net-sniff.git](https://github.com/xmax17/net-sniff.git)
cd net-sniff

# Compile release binary
cargo build --release

# Run with elevated privileges (required for raw socket access)
sudo ./target/release/net-sniff
```

---

## 🛡️ Requirements
- **Linux**: Kernel 2.6.27+ for `procfs` process mapping.
- **Privileges**: Requires `sudo` or `CAP_NET_RAW` capabilities to capture traffic.
- **Terminal**: A GPU-accelerated terminal (Alacritty, Kitty, WezTerm) is recommended for best sparkline performance.


