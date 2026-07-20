# 🔍 Basic Network Sniffer

A beginner-friendly Python packet sniffer built for the **CodeAlpha Cyber Security Internship** (Task 1). It captures live network traffic and displays useful details about each packet: timestamp, source/destination IP address, protocol, ports, TCP flags, and a preview of the payload.

---

## What this project does

- Captures packets flowing through your network interface in real time.
- Parses each packet's **Ethernet / IP / TCP / UDP / ICMP** layers.
- Prints a clean, human-readable summary of each packet to the terminal.
- Optionally saves the capture to a `.pcap` file you can open in Wireshark.

### Two versions are included

| File | Requires | Works on |
|---|---|---|
| `sniffer.py` | Scapy | Windows, macOS, Linux |


> Use `sniffer.py` unless you specifically want to see how sniffing works with zero external libraries.

---

## ⚠️ Legal & Ethical Notice

> Only capture traffic on networks and devices you **own** or have **explicit permission** to monitor (e.g., your own home network, or a lab VM). Sniffing traffic on networks you don't control or don't have permission to inspect is **illegal** in many places. This project is for **learning purposes only**.

---

## Getting started

### Step 1: Install Python

You need **Python 3.8** or newer.

Check if you already have it:

```bash
python3 --version
```

If not installed, download it from [python.org/downloads](https://www.python.org/downloads/) and install it (on Windows, tick **"Add Python to PATH"** during install).

### Step 2: Get the project files

If you're following along locally, create a folder and put `sniffer.py`, `sniffer_socket.py`, `requirements.txt`, `.gitignore`, and this `README.md` inside it. (If you got these files from GitHub, they're already grouped together — just clone the repo.)

### Step 3: Create a virtual environment (recommended)

This keeps your project's dependencies separate from other Python projects.

```bash
cd network-sniffer

# Create the environment
python3 -m venv venv

# Activate it
# On Linux/Mac:
source venv/bin/activate
# On Windows (PowerShell):
venv\Scripts\Activate.ps1
```

You'll see `(venv)` appear in your terminal prompt when it's active.

### Step 4: Install dependencies

```bash
pip install -r requirements.txt
```

#### Extra step for Windows users

Scapy needs a packet-capture driver on Windows called **Npcap**.

1. Download it from [npcap.com](https://npcap.com/).
2. Install it, leaving all default options checked (including **"Install Npcap in WinPcap API-compatible Mode"**).

#### Extra step for Linux users

Nothing extra needed — Linux has built-in raw socket support.

#### Extra step for macOS users

Nothing extra needed, but you'll need to run the script with `sudo`.

### Step 5: Run the sniffer

Packet sniffing requires **elevated privileges** because it reads raw traffic directly off the network interface.

**Linux / macOS:**

```bash
sudo python3 sniffer.py
```

**Windows (run terminal "as Administrator"):**

```bash
python sniffer.py
```

You should see output like this as traffic flows through your machine:

```
[14:02:11]     192.168.1.10 -> 142.250.183.14  [TCP]  sport=54210 dport=443 flags=PA
    Payload: ...................
    Summary: Ether / IP / TCP 192.168.1.10:54210 > 142.250.183.14:https PA / Raw
--------------------------------------------------------------------------------
```

> To generate some traffic to see while it runs, open a browser and visit any website, or run `ping google.com` in another terminal.

---

## Useful options

```bash
# Capture only 20 packets, then stop automatically
sudo python3 sniffer.py -c 20

# Only capture web traffic (HTTP/HTTPS)
sudo python3 sniffer.py -f "tcp port 80 or tcp port 443"

# Only capture ping (ICMP) traffic
sudo python3 sniffer.py -f "icmp"

# Choose a specific network interface (list yours with `ifconfig` / `ipconfig`)
sudo python3 sniffer.py -i eth0

# Save the capture to a .pcap file to open later in Wireshark
sudo python3 sniffer.py -c 50 -o capture.pcap

# List available network interfaces
python3 sniffer.py --list-interfaces
```

Run `python3 sniffer.py --help` to see all options.

---



## Project structure

```
network-sniffer/
├── sniffer.py          # Main sniffer (Scapy-based, cross-platform)
├── sniffer_socket.py   # Alternative sniffer (raw socket, Linux only)
├── requirements.txt    # Python dependencies
├── .gitignore
└── README.md
```

---



## Credits

Built for the **CodeAlpha Cyber Security Internship**, Task 1.
