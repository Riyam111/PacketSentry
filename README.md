# PacketSentry — Deep Packet Inspection Engine

> A high-performance, multi-threaded Deep Packet Inspection (DPI) engine with **live network capture**, **real-time application classification**, and a **Next.js web dashboard** — all running locally on Windows.

---

## Table of Contents

- [Overview](#overview)
- [Architecture](#architecture)
- [Features](#features)
- [Project Structure](#project-structure)
- [Prerequisites](#prerequisites)
- [Building the C++ Engine](#building-the-c-engine)
- [Running the Engine](#running-the-engine)
- [Live Dashboard](#live-dashboard)
- [How It Works](#how-it-works)
- [C++ Module Reference](#c-module-reference)
- [Dashboard Stack](#dashboard-stack)

---

## Overview

PacketSentry is a two-part system:

| Component | Technology | Role |
|---|---|---|
| **DPI Engine** | C++17 + Npcap | Captures packets, classifies flows, writes `live_data.json` |
| **Web Dashboard** | Next.js 16 + React 19 | Reads `live_data.json` via API, renders live charts & flow log |

The C++ engine runs in the background capturing real traffic (or reading a `.pcap` file), and the Next.js dashboard polls for updates every second to give you a real-time view of what applications are using your network.

---

## Architecture

```
┌──────────────────────────────────────────────────────────────┐
│                      C++ DPI Engine                          │
│                                                              │
│  NIC / .pcap ──► LiveCapture / PcapReader                   │
│                        │                                     │
│                        ▼                                     │
│               PacketParser (Eth/IP/TCP/UDP)                  │
│                        │                                     │
│                        ▼                                     │
│              LoadBalancer (5-tuple hash)                     │
│               /           \           \                      │
│        FP Thread 0    FP Thread 1  ... FP Thread N           │
│        (ConnectionTracker + SNI + HTTP DPI)                  │
│               \           /           /                      │
│                ▼                                             │
│         StatisticsAggregator                                 │
│                │   (every 1 s)                               │
│                ▼                                             │
│         live_data.json  ◄──── JSON broadcaster thread        │
└──────────────────────────────────────────────────────────────┘
                      │
          (Next.js API route reads file)
                      │
┌──────────────────────────────────────────────────────────────┐
│               Next.js Dashboard (port 3000)                  │
│  ┌──────────┐  ┌──────────────┐  ┌─────────────────────┐   │
│  │ Metric   │  │ Pie Chart    │  │ Bar Chart           │   │
│  │ Cards    │  │ App Bytes    │  │ Top Domains (SNI)   │   │
│  └──────────┘  └──────────────┘  └─────────────────────┘   │
│  ┌──────────────────────┐  ┌──────────────────────────────┐ │
│  │ Worker Load Table    │  │ Live Application Flows Log   │ │
│  └──────────────────────┘  └──────────────────────────────┘ │
└──────────────────────────────────────────────────────────────┘
```

---

## Features

### C++ Engine

| Feature | Description |
|---|---|
| **Live Capture** | Capture from any Npcap-visible interface in real time (`--live`) |
| **PCAP Offline Mode** | Replay and analyse existing capture files (`--file`) |
| **Multi-threaded Fast Path** | N worker threads, each with its own lock-free queue and connection table (`--live-mt`) |
| **Load Balancing** | 5-tuple hash distributes flows deterministically across Fast Path workers |
| **TLS/SNI Extraction** | Parses TLS Client Hello to identify encrypted HTTPS destinations |
| **HTTP Host Extraction** | Reads the `Host:` header from plaintext HTTP traffic |
| **Connection Tracking** | Per-worker stateful TCP lifecycle tracking (NEW → ESTABLISHED → CLOSED) |
| **Application Classification** | Maps SNI/host to known app types (YouTube, Netflix, Google, etc.) |
| **Statistics Aggregator** | Thread-safe counters for packets, bytes, connections, and per-app traffic |
| **JSON IPC** | Writes `live_data.json` every second for the dashboard to consume |
| **ASCII Dashboard** | Prints a live classification report to the terminal every 10 seconds |
| **Rule Engine** | Drop or allow by IP, port, application type, or domain |
| **Graceful Shutdown** | `Ctrl+C` handler drains queues and writes a final JSON snapshot |

### Web Dashboard

| Feature | Description |
|---|---|
| **Live Connection Indicator** | Green pulsing dot when data is flowing from the C++ engine |
| **Metric Cards** | Total packets, bandwidth processed, active flows, classification rate |
| **Application Distribution** | Interactive donut chart (bytes per app) powered by Recharts |
| **Top Domains** | Horizontal bar chart of the most-seen SNI domains |
| **Worker Load Table** | Per-thread packet count, queue backpressure, and classification count |
| **Live Application Flows** | Auto-scrolling real-time log of classified flows (src IP → dst IP → app → domain) |
| **CSV Export** | One-click export of the full report (metrics, apps, domains, flow log) |
| **Scroll Pause** | Automatically pauses auto-scroll when you scroll up; resumes at the bottom |

---

## Project Structure

```
PacketSentry/
├── CMakeLists.txt                  # CMake build configuration
├── packet_analyzer.exe             # Compiled binary (Windows)
├── live_data.json                  # IPC file — C++ writes, Next.js reads
│
├── src/                            # C++ source files
│   ├── main.cpp                    # Entry point & run-mode dispatch
│   ├── live_capture.cpp            # Npcap live capture wrapper
│   ├── pcap_reader.cpp             # Offline .pcap file reader
│   ├── packet_parser.cpp           # Ethernet / IP / TCP / UDP parser
│   ├── sni_extractor.cpp           # TLS Client Hello SNI parser
│   ├── connection_tracker.cpp      # Per-worker TCP flow state machine
│   ├── load_balancer.cpp           # 5-tuple hash load balancer
│   ├── fast_path.cpp               # Worker thread DPI engine + FPManager
│   ├── rule_manager.cpp            # Block/allow rule evaluation
│   ├── statistics_aggregator.cpp   # Thread-safe metrics & JSON serialiser
│   └── types.cpp                   # Shared type helpers
│
├── include/                        # C++ header files
│   ├── types.h
│   ├── packet_parser.h
│   ├── live_capture.h
│   ├── pcap_reader.h
│   ├── sni_extractor.h
│   ├── connection_tracker.h
│   ├── load_balancer.h
│   ├── fast_path.h
│   ├── rule_manager.h
│   ├── statistics_aggregator.h
│   ├── thread_safe_queue.h
│   ├── platform.h
│   └── json.hpp                    # nlohmann/json (single-header)
│
└── packet-dashboard/               # Next.js web dashboard
    ├── src/app/
    │   ├── page.tsx                # Main dashboard UI
    │   ├── layout.tsx
    │   ├── globals.css
    │   └── api/                    # Next.js API routes
    ├── package.json
    └── next.config.ts
```

---

## Prerequisites

### C++ Engine

| Requirement | Version | Notes |
|---|---|---|
| CMake | ≥ 3.16 | |
| MSVC / MinGW | C++17 | Visual Studio 2019+ recommended |
| [Npcap](https://npcap.com/) | latest | Install with *WinPcap API compatibility* enabled |
| Npcap SDK | 1.16 | Extract to `C:\Users\<you>\Downloads\npcap-sdk-1.16` |

> **Important:** If you change the Npcap SDK path, update `CMakeLists.txt` line 10:
> ```cmake
> set(NPCAP_SDK_DIR "C:/path/to/your/npcap-sdk-1.16")
> ```

### Dashboard

| Requirement | Version |
|---|---|
| Node.js | ≥ 18 |
| npm | ≥ 9 |

---

## Building the C++ Engine

```powershell
# From the project root
mkdir build
cd build
cmake .. -G "Visual Studio 17 2022" -A x64
cmake --build . --config Release
```

The compiled `packet_analyzer.exe` will be output to the project root (configured via `CMAKE_RUNTIME_OUTPUT_DIRECTORY`).

---

## Running the Engine

### List available network interfaces

```powershell
./packet_analyzer.exe --list-interfaces
```

### Offline analysis (`.pcap` file)

```powershell
# Analyse all packets
./packet_analyzer.exe --file test_dpi.pcap
./packet_analyzer.exe --file output.pcap
./packet_analyzer.exe --file test_dpi.pcap 10    # show only first 10 packets
```

### Single-threaded live capture

```powershell
./packet_analyzer.exe --live "\Device\NPF_{YOUR-INTERFACE-GUID}"
```

### Multi-threaded live capture

```powershell
# Default: 4 Fast Path worker threads
./packet_analyzer.exe --live-mt "\Device\NPF_{YOUR-INTERFACE-GUID}"

# Custom thread count
./packet_analyzer.exe --live-mt "\Device\NPF_{YOUR-INTERFACE-GUID}" 4
```

> Run `--list-interfaces` first to get the correct `\Device\NPF_{GUID}` string for your adapter.

### Stop the engine

Press **`Ctrl+C`** — the engine drains its queues, writes a final `live_data.json` snapshot, and exits cleanly.

---

## Live Dashboard

### Start the dashboard

```powershell
cd packet-dashboard
npm install
npm run dev
```

Open **http://localhost:3000** in your browser.

### How the IPC works

1. The C++ engine runs a background **JSON broadcaster thread** that serialises `StatisticsAggregator` state and writes it to `live_data.json` every **1 second**.
2. A Next.js API route (`/api/data`) reads that file on the server side.
3. The dashboard polls `/api/data` every **1 second** and updates all charts and counters.

The connection indicator in the top-right shows:
- 🟢 **Engine Connected** — fresh data is arriving
- 🔴 **Awaiting C++ Engine…** — no data yet (start the engine first)

### Exporting results

Click **Export CSV** in the dashboard header to download a timestamped report containing:
- System metrics
- Per-application breakdown (bytes / packets / connections)
- Top detected domains (SNI)
- Full recent flow log

---

## How It Works

### Packet Pipeline

```
Capture (Npcap / pcap)
    │
    ▼
PacketParser          — decodes Ethernet, IPv4/IPv6, TCP, UDP headers
    │
    ▼
LoadBalancer          — hashes 5-tuple (src_ip, dst_ip, src_port, dst_port, proto)
    │                   to pick a deterministic Fast Path worker
    ▼
FastPathProcessor     — one thread per FP worker
  ├─ ConnectionTracker   tracks TCP state per flow (NEW/ESTABLISHED/CLOSED/BLOCKED)
  ├─ SNIExtractor        parses TLS 1.2/1.3 Client Hello extension (type 0x0000)
  ├─ HTTPHostExtractor   scans plaintext payload for "Host:" header
  └─ RuleManager         evaluates block/allow rules; returns DROP or FORWARD
    │
    ▼
StatisticsAggregator  — atomic counters aggregated from all worker threads
    │
    ▼
JSON Broadcaster      — background thread writes live_data.json every 1 s
```

### Application Classification

The SNI or HTTP `Host` value is matched against a built-in keyword table to assign an `AppType`:

| AppType | Example SNI patterns |
|---|---|
| `YOUTUBE` | `youtube.com`, `googlevideo.com` |
| `NETFLIX` | `netflix.com`, `nflxvideo.net` |
| `GOOGLE` | `google.com`, `googleapis.com` |
| `FACEBOOK` | `facebook.com`, `fbcdn.net` |
| `MICROSOFT` | `microsoft.com`, `live.com` |
| `HTTPS` | Port 443, SNI extraction failed |
| `HTTP` | Port 80, no Host header |
| `DNS` | Port 53 |
| `UNKNOWN` | Everything else |

### JSON Data Schema

`live_data.json` conforms to this schema (consumed by the dashboard):

```jsonc
{
  "system": {
    "active_connections": 12,
    "total_connections": 104,
    "classified_connections": 87,
    "unknown_connections": 17,
    "total_packets": 4821,
    "total_bytes": 3145728,
    "classification_rate": 83.7
  },
  "applications": [
    { "name": "YOUTUBE", "bytes": 1048576, "packets": 800, "connections": 14 }
  ],
  "domains": [
    { "domain": "www.youtube.com", "connections": 9 }
  ],
  "workers": [
    { "id": 0, "packets_processed": 2400, "queue_length": 3, "classifications": 42 }
  ],
  "recent_flows": [
    { "timestamp": 1718776800, "src_ip": "192.168.1.5", "dst_ip": "142.250.64.46",
      "application": "YOUTUBE", "domain": "www.youtube.com" }
  ]
}
```

---

## C++ Module Reference

| File | Class / Namespace | Responsibility |
|---|---|---|
| `main.cpp` | `main()` | CLI parsing, mode dispatch (`--file`, `--live`, `--live-mt`) |
| `live_capture.cpp` | `PacketAnalyzer::LiveCapture` | Npcap real-time capture; `startCapture(callback)`, `setFilter()`, `listInterfaces()` |
| `pcap_reader.cpp` | `PacketAnalyzer::PcapReader` | Reads `.pcap` files packet-by-packet |
| `packet_parser.cpp` | `PacketAnalyzer::PacketParser` | Parses raw bytes into `ParsedPacket` struct |
| `sni_extractor.cpp` | `DPI::SNIExtractor` | Extracts SNI from TLS Client Hello; `extract(payload, len)` → `std::optional<string>` |
| `connection_tracker.cpp` | `DPI::ConnectionTracker` | Hash-map of `FiveTuple → Connection`; `getOrCreateConnection()`, `classifyConnection()`, `cleanupStale()` |
| `load_balancer.cpp` | `DPI::LoadBalancer` | Distributes `PacketJob`s to FP queues via 5-tuple hash |
| `fast_path.cpp` | `DPI::FastPathProcessor`, `DPI::FPManager` | Worker DPI loop; payload inspection; rule evaluation; `generateClassificationReport()` |
| `rule_manager.cpp` | `DPI::RuleManager` | Manages block/allow rules by IP, port, app type, domain |
| `statistics_aggregator.cpp` | `DPI::StatisticsAggregator` | Atomic counters; ring buffer of last 50 flow events; `generateDashboardJSON()` |
| `types.cpp` | `PacketAnalyzer`, `DPI` | Shared enums and helpers (`appTypeToString`, `sniToAppType`) |

---

## Dashboard Stack

| Library | Version | Purpose |
|---|---|---|
| Next.js | 16 | Framework, file-based API routes |
| React | 19 | UI rendering |
| TypeScript | 5 | Type safety |
| Recharts | 3 | Pie chart (app distribution), bar chart (top domains) |
| Lucide React | 1.20 | Icons (Activity, Server, Network, ShieldAlert, …) |
| Tailwind CSS | 4 | Utility-first styling |

---

## License

This project is for educational and research purposes. Network packet capture may be subject to local laws — only capture traffic on networks you own or have explicit permission to monitor.
