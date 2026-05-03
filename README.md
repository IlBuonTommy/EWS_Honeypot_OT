# OT Early Warning System (EWS)

> Passive probe + honeypot for industrial networks (OT/ICS).  
> Detects scans, “alien” protocols, and unauthorized hosts **before** exploitation.

---

## Table of contents

- [The idea](#the-idea)
- [Architecture](#architecture)
- [Supported protocols](#supported-protocols)
- [Detection rules](#detection-rules)
- [REST API](#rest-api)
- [Web UI](#web-ui)
- [Deploy](#deploy)
- [Configuration](#configuration)
- [Security](#security)
- [Repository structure](#repository-structure)

---

## The idea

OT networks are **deterministic and cyclical**: the same devices run the same protocols in predictable cycles. An attack almost always starts with a **reconnaissance** phase (IP/port scanning) to map the network before exploitation (ICS Cyber Kill Chain).

This system leverages two principles:

| Principle | How it works (example) |
|---|---|
| **Alien protocol** | If the network only uses Profinet, any Modbus/OPC UA traffic is an immediate IoC |
| **Silent device** | The honeypot has no role in the production process: any contact to it is suspicious |

Unlike traditional signature-based IDS, the EWS works on **network telemetry**, collecting only minimal metadata (no PCAP / full payload capture). This choice significantly reduces resource impact and makes it a low-footprint solution, suitable for widespread deployment in industrial environments, where hardware resources are often limited.

---

## Architecture

```
┌─────────────────────────────────────────────────┐
│                Container EWS                    │
│                                                 │
│  ┌──────────┐   ┌──────────┐   ┌─────────────┐  │
│  │ Sniffer  │   │ Sniffer  │   │  Honeypot   │  │
│  │  eth0    │   │  eth1    │   │  TCP/UDP    │  │
│  │ (mgmt)   │   │ (SPAN)   │   │  Traps      │  │
│  └────┬─────┘   └────┬─────┘   └──────┬──────┘  │
│       │              │                │         │
│       └──────────────┼────────────────┘         │
│                      ▼                          │
│              ┌──────────────┐                   │
│              │   Engine     │──► Webhook/SIEM   │
│              │  Detection   │                   │
│              └──────┬───────┘                   │
│                     ▼                           │
│              ┌──────────────┐                   │
│              │   SQLite     │                   │
│              │  /data/ews.db│                   │
│              └──────┬───────┘                   │
│                     ▼                           │
│              ┌──────────────┐                   │
│              │  FastAPI     │                   │
│              │  Web UI/API  │                   │
│              └──────────────┘                   │
└─────────────────────────────────────────────────┘
```

### Network interfaces

| Interface | Role | Traffic |
|---|---|---|
| `eth0` | Management / Honeypot | Web UI, API, TCP/UDP traps on OT ports |
| `eth1` | SPAN mirror (full mode only) | Passive sniffing of process traffic |

> **Note:** traffic to the Web UI (port `EWS_WEB_PORT`) and the ARP traffic required for address resolution are automatically excluded from detection rules on eth0. Any device can access the web interface without generating WARNING or ALARM.

### Operating modes

| Mode | Interfaces | Docker networking | Features |
|---|---|---|---|
| **full** | eth0 + eth1 | `network_mode: host` + `privileged` | Honeypot + baseline learning + alien detection |
| **light** | eth0 only | macvlan (dedicated IP) | Honeypot only (no mirror/baseline) |

### State machine

| State | Behavior |
|---|---|
| **OFF** | Baseline learning: protocols, hosts, and ARP mappings are recorded as “normal” |
| **ON** | Active monitoring: any deviation from the baseline generates WARNING or ALARM |

The state is persisted in SQLite and survives restarts.

---

## Supported protocols

### L2 protocols (classified by EtherType)

| Protocol | EtherType | Full name |
|---|---|---|
| Profinet | `0x8892` | Profinet RT/IRT |
| EtherCAT | `0x88A4` | EtherCAT frame |
| Powerlink | `0x88AB` | ETHERNET Powerlink |
| CC-Link IE | `0x890F` | CC-Link IE Field |
| IEC 61850 GOOSE | `0x88B8` | Generic Object Oriented Substation Event |
| IEC 61850 SV | `0x88BA` | Sampled Values |

### L4 protocols (classified by TCP/UDP port)

| Protocol | Ports | Transport |
|---|---|---|
| Modbus TCP | 502 | TCP |
| EtherNet/IP | 44818 (TCP/UDP), 2222 (UDP) | TCP + UDP |
| OPC UA | 4840, 4843 (TLS) | TCP |
| DNP3 | 20000 | TCP + UDP |
| S7comm (Siemens) | 102 | TCP (TPKT/COTP) |
| IEC 61850 MMS | 102 | TCP (TPKT/COTP) |
| BACnet/IP | 47808 | UDP |
| FINS (Omron) | 9600 | TCP + UDP |
| Profinet (via UDP ports) | 34962, 34963, 34964, 53247 | UDP |
| CC-Link IE (via port) | 61450 | — |
| Powerlink (via ports) | 3819, 3820 | — |

### Ethernet parser

- **802.1Q VLAN tagging** support (including Q-in-Q `0x88A8` / `0x9100`)
- **IPv4** and **IPv6** parsing (with extension headers)
- **ARP** parsing for spoofing detection
- **TCP flags** extraction for SYN-scan detection
- **ICMP / ICMPv6** support

### Known limitations

- Classification is based on EtherType and ports; no full Deep Packet Inspection is performed
- Port 102 is ambiguous: S7comm and IEC 61850 MMS share TPKT/COTP — both are flagged
- Modbus payload is analyzed only in honeypot traps (function code), not in passive sniffing

---

## Detection rules (IoC)

### WARNING

| Trigger | Interface | Description |
|---|---|---|
| Contact to EWS | eth0 | Any traffic to the honeypot IP/MAC (excluding Web UI port and ARP traffic) |
| SYN-scan contact | eth0 | TCP SYN packets without ACK to the honeypot (tagged `[SYN scan]`) |
| New host | eth1 | IP or MAC not present in the baseline learned in `OFF` |
| TCP trap connection | eth0 | TCP connection attempt to an OT port on the honeypot |
| UDP trap datagram (empty) | eth0 | Receipt of an empty UDP datagram on an OT trap port |

### ALARM

| Trigger | Interface | Description |
|---|---|---|
| Alien protocol | eth1 | OT protocol observed on eth1 that is not present in the baseline |
| Payload on TCP trap | eth0 | Application data sent to a TCP trap port on the honeypot (log first 128 bytes in hex) |
| Payload on UDP trap | eth0 | UDP datagram with payload received on a honeypot trap port |
| Port scan | eth0 | Source IP contacts ≥ N distinct ports in T seconds |
| Gateway discovery / ARP spoofing | eth0 | Packet destined to the local MAC but with a destination IP different from the local IP |
| ARP spoofing | eth1 | IP↔MAC mapping different from the learned baseline |

### Automatic exclusions (no false positives)

| Excluded traffic | Interface | Reason |
|---|---|---|
| TCP to `EWS_WEB_PORT` | eth0 | Legitimate access to the Web UI |
| ARP (request/reply) | eth0 | Address resolution required for any IP communication, including access to the Web UI |
| Traffic not directed to EWS | eth0 | Only packets with honeypot dst_ip or dst_mac are analyzed |

### Deduplication

Duplicate events (same `dedup_key`) are aggregated within a configurable time window, incrementing the `occurrences` counter.

### Rate limiting

A configurable limit (default: 100 events/sec) prevents database flooding in case of volumetric attacks.

---

## REST API

All GET endpoints are accessible without authentication.  
Mutable endpoints (POST) require the `X-Api-Key` header **if** the `EWS_API_KEY` variable is configured.

| Method | Endpoint | Auth | Description |
|---|---|---|---|
| `GET` | `/health` | — | Container healthcheck |
| `GET` | `/api/status` | — | System status, mode, interfaces |
| `GET` | `/api/metrics` | — | Per-protocol metrics (packets, PPS, BPS) |
| `GET` | `/api/events` | — | Event list with filters (severity/protocol/host/time) |
| `GET` | `/api/config` | — | Runtime configuration |
| `POST` | `/api/state` | `X-Api-Key` | Switch OFF ↔ ON |
| `POST` | `/api/config` | `X-Api-Key` | Change dedup window at runtime |
| `POST` | `/api/baseline/export` | — | Export baseline JSON |
| `POST` | `/api/baseline/import` | `X-Api-Key` | Import baseline JSON |
| `POST` | `/api/events/emit-test` | — | Generate a test event |
| `POST` | `/api/events/clear` | `X-Api-Key` | Clear all WARNING and ALARM events |

---

## Web UI

Accessible via HTTP at `http://<IP_eth0>:<EWS_WEB_PORT>/`.

| Section | Content |
|---|---|
| **Dashboard** | 15 protocol cards with a status color (gray/green/yellow/red), PPS, BPS, observed addresses, latest events. Summary stats bar. Button to clear all events. |
| **Events** | Filterable table by severity, protocol, host, time window. ALARM rows highlighted. |
| **State** | OFF/ON toggle, baseline protocol list |
| **Configuration** | Dedup window, baseline JSON export/import |

### Sound alerts

The Web UI automatically plays alert sounds when the system is in **ON** state:

| Severity | Audio file | Behavior |
|---|---|---|
| **WARNING** | `warning.mp3` | Played when new WARNING events appear |
| **ALARM** | `allarm.mp3` | Played with higher priority, interrupts the WARNING sound |

Sounds are checked every 15 seconds by polling recent events. On the first page load, sounds are not played (to avoid alerting on pre-existing events).

### Other UI characteristics

- **API Key** field integrated in the header with `localStorage` persistence for seamless authentication
- Live updates via REST polling (5s metrics, 7s events)
- All renderings use XSS escaping (`textContent` / `esc()` function)

---

## Deploy

### Prerequisites

- Docker + Docker Compose
- A network interface for management (and optionally one for SPAN mirroring)

### 1. Full mode (eth0 + eth1)

Full mode uses `network_mode: host` with `privileged: true` to get direct access to all host network interfaces.

Create `.env`:

```env
# Network interfaces
EWS_ETH0_IFACE=eth0
EWS_ETH1_IFACE=eth1

# Web UI
EWS_WEB_PORT=8080

# Detection
EWS_DEDUP_WINDOW_SECONDS=30

# Security (recommended)
EWS_API_KEY=una-chiave-segreta-lunga

# External alerting (optional)
EWS_WEBHOOK_URL=https://siem.azienda.it/webhook/ews

# Port scan detection
EWS_SCAN_THRESHOLD_PORTS=5
EWS_SCAN_THRESHOLD_SECONDS=60

# Event rate limiting
EWS_EVENT_RATE_LIMIT=100
```

Start:

```bash
docker compose -f docker-compose.full.yml up -d --build
```

Requirements: `privileged: true` (raw socket access + promiscuous mode on both interfaces).

### 2. Light mode (eth0 only)

Light mode uses a **macvlan** network to assign the honeypot a dedicated IP/MAC on the OT network, making it indistinguishable from a real physical asset.

`.env`:

```env
# macvlan network
EWS_ETH0_IP=192.168.10.250
OT_MGMT_PARENT_IFACE=eth0
OT_MGMT_SUBNET=192.168.10.0/24
OT_MGMT_GATEWAY=192.168.10.1

# Web UI
EWS_WEB_PORT=8080

# Detection
EWS_DEDUP_WINDOW_SECONDS=30

# Security (recommended)
EWS_API_KEY=una-chiave-segreta-lunga

# External alerting (optional)
EWS_WEBHOOK_URL=https://siem.azienda.it/webhook/ews

# Port scan detection
EWS_SCAN_THRESHOLD_PORTS=5
EWS_SCAN_THRESHOLD_SECONDS=60

# Event rate limiting
EWS_EVENT_RATE_LIMIT=100
```

Start:

```bash
docker compose -f docker-compose.light.yml up -d --build
```

Required capability: `NET_RAW`.

---

## Configuration

### Environment variables

| Variable | Default | Description |
|---|---|---|
| `EWS_MODE` | `full` | Mode: `full` or `light` |
| `EWS_WEB_HOST` | `0.0.0.0` | Web UI bind address |
| `EWS_WEB_PORT` | `8080` | Web UI and API port |
| `EWS_ETH0_IFACE` | `eth0` | Management/honeypot interface |
| `EWS_ETH1_IFACE` | `eth1` | SPAN mirror interface |
| `EWS_DATA_DIR` | `/data` | SQLite persistence directory |
| `EWS_DEDUP_WINDOW_SECONDS` | `30` | Event deduplication window (1–3600) |
| `EWS_EVENTS_RETENTION_DAYS` | `30` | Event retention in days |
| `EWS_RECENT_WINDOW_SECONDS` | `600` | Window used for card severity color |
| `EWS_API_KEY` | *(empty)* | API key for mutable endpoints. If empty, authentication is disabled |
| `EWS_WEBHOOK_URL` | *(empty)* | Webhook URL for ALARM alerts (JSON POST) |
| `EWS_SCAN_THRESHOLD_PORTS` | `5` | Distinct ports required to trigger ALARM port scan |
| `EWS_SCAN_THRESHOLD_SECONDS` | `60` | Time window for port scan detection |
| `EWS_EVENT_RATE_LIMIT` | `100` | Max events recorded per second (0 = unlimited) |

### Persistence

Required volume: `./data:/data`

The `/data/ews.db` file contains:
- State machine (OFF/ON)
- Baseline: protocols, hosts, indicators, ARP mappings
- WARNING/ALARM events with occurrences
- Per-protocol aggregated statistics

### Webhook

When `EWS_WEBHOOK_URL` is configured, each **ALARM** severity event generates a JSON POST:

```json
{
  "source": "OT-EWS",
  "timestamp": 1739612345.123,
  "event": {
    "severity": "ALARM",
    "protocol": "Modbus TCP",
    "src_ip": "192.168.10.100",
    "description": "Protocollo alieno osservato su eth1: Modbus TCP",
    "..."
  }
}
```

Compatible with SIEMs, Slack, Microsoft Teams, or any HTTP endpoint.

---

## Security

| Measure | Status |
|---|---|
| API key on mutable endpoints | Enabled if `EWS_API_KEY` is configured |
| XSS protection in the dashboard | All rendered data is escaped |
| Event rate limiting | Configurable, default 100/sec |
| ARP spoofing detection | Compare IP↔MAC vs baseline (eth1) |
| Gateway discovery detection | Packets with local MAC but different IP (eth0) |
| Port scan detection | Correlate distinct ports per IP |
| Web UI + ARP exclusion on eth0 | No false positives for legitimate dashboard access |

### Operational recommendations

- **Always configure `EWS_API_KEY`** in production
- **Do not expose the Web UI on untrusted networks** — use it only on an isolated OT network or behind a VPN
- **Terminate TLS externally** (nginx/traefik reverse proxy) if needed
- **Do not connect eth1 to non-mirror networks** — sniffing is designed for SPAN ports

### Honeypot traps

The honeypot opens listeners on all major OT ports:

**TCP ports:** 102 (S7comm/IEC 61850), 502 (Modbus), 4840 (OPC UA), 4843 (OPC UA TLS), 9600 (FINS), 20000 (DNP3), 44818 (EtherNet/IP)

**UDP ports:** 2222 (EtherNet/IP implicit), 9600 (FINS), 20000 (DNP3), 44818 (EtherNet/IP), 47808 (BACnet/IP)

For each connection:
1. **WARNING** on TCP connection attempt or UDP datagram reception
2. **ALARM** if application data is sent (logging the first 128 bytes in hex)
3. Minimal fake response (Modbus error, TPKT/COTP CC, EtherNet/IP ListIdentity) to prolong interaction and collect more information about the attacker
4. Modbus payload analysis (unit ID and function code) to add more detail to events

---

## Repository structure

```
EWS_Honeypot_OT/
├── app/
│   ├── config.py          # Configuration from environment variables
│   ├── parser.py          # Ethernet parser: VLAN, IPv4/v6, ARP, TCP/UDP/ICMP
│   ├── protocols.py       # Classification of 15 OT protocols (L2 + L4)
│   ├── sniffer.py         # Raw socket sniffer thread (AF_PACKET, promiscuous)
│   ├── honeypot.py        # TCP/UDP traps with fake responses
│   ├── storage.py         # SQLite (WAL mode) + rate limiter + scan detector + ARP cache
│   └── main.py            # FastAPI app, detection engine, webhook
├── static/
│   └── index.html         # Dashboard SPA (vanilla JS, XSS-safe, sound alerts)
├── sound/
│   ├── warning.mp3        # Alert sound for WARNING events
│   └── allarm.mp3         # Alert sound for ALARM events
├── Dockerfile
├── docker-compose.full.yml   # Deploy full mode (host networking + privileged)
├── docker-compose.light.yml  # Deploy light mode (macvlan networking)
├── requirements.txt
└── README.md
```

---

## Technology stack

| Component | Technology |
|---|---|
| Runtime | Python 3.12 |
| Web framework | FastAPI + Uvicorn |
| Database | SQLite (WAL mode) |
| Packet capture | `AF_PACKET` raw socket (Linux) |
| Container | Docker with macvlan networking |
| Frontend | Vanilla HTML/JS (zero dependencies) |
