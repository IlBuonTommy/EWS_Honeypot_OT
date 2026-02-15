# OT Early Warning System (EWS)

> Sonda passiva + Honeypot per reti industriali (OT/ICS).  
> Rileva scansioni, protocolli alieni e host non autorizzati **prima** dell'exploitation.

---

## Indice

- [Razionale](#razionale)
- [Architettura](#architettura)
- [Protocolli supportati](#protocolli-supportati)
- [Regole di detection](#regole-di-detection)
- [API REST](#api-rest)
- [Web UI](#web-ui)
- [Deploy](#deploy)
- [Configurazione](#configurazione)
- [Sicurezza](#sicurezza)
- [Struttura repository](#struttura-repository)

---

## Razionale

Le reti OT sono **deterministiche e cicliche**: gli stessi dispositivi eseguono gli stessi protocolli in cicli prevedibili. Un attacco inizia quasi sempre con una fase di **Reconnaissance** (scansione IP/porte) per mappare la rete prima dell'exploitation (ICS Cyber Kill Chain).

Questo sistema sfrutta due principi:

| Principio | Come funziona |
|---|---|
| **Protocollo alieno** | Se la rete usa solo Profinet, qualsiasi traffico Modbus/OPC UA è un IoC immediato |
| **Dispositivo silente** | L'honeypot non ha ruolo nel processo produttivo: ogni contatto verso di esso è sospetto |

A differenza degli IDS tradizionali basati su firme, l'EWS opera sulla **telemetria di rete** raccogliendo solo metadati minimi (nessun PCAP/payload completo), con footprint ridotto adatto ad ambienti industriali.

---

## Architettura

```
┌─────────────────────────────────────────────────┐
│                Container EWS                     │
│                                                  │
│  ┌──────────┐   ┌──────────┐   ┌─────────────┐  │
│  │ Sniffer  │   │ Sniffer  │   │  Honeypot   │  │
│  │  eth0    │   │  eth1    │   │  TCP/UDP    │  │
│  │ (mgmt)  │   │ (SPAN)   │   │  Traps      │  │
│  └────┬─────┘   └────┬─────┘   └──────┬──────┘  │
│       │              │                 │         │
│       └──────────────┼─────────────────┘         │
│                      ▼                           │
│              ┌──────────────┐                    │
│              │   Engine     │──► Webhook/SIEM    │
│              │  Detection   │                    │
│              └──────┬───────┘                    │
│                     ▼                            │
│              ┌──────────────┐                    │
│              │   SQLite     │                    │
│              │  /data/ews.db│                    │
│              └──────────────┘                    │
│                     ▼                            │
│              ┌──────────────┐                    │
│              │  FastAPI     │                    │
│              │  Web UI/API  │                    │
│              └──────────────┘                    │
└─────────────────────────────────────────────────┘
```

### Interfacce di rete

| Interfaccia | Ruolo | Traffico |
|---|---|---|
| `eth0` | Management / Honeypot | Web UI, API, trap TCP/UDP sulle porte OT |
| `eth1` | SPAN mirror (solo full mode) | Sniffing passivo del traffico di processo |

### Modalità operative

| Modalità | Interfacce | Funzionalità |
|---|---|---|
| **full** | eth0 + eth1 | Honeypot + baseline learning + alien detection |
| **light** | solo eth0 | Solo honeypot (nessun mirror/baseline) |

### Macchina a stati

| Stato | Comportamento |
|---|---|
| **OFF** | Apprendimento baseline: protocolli, host e mapping ARP vengono registrati come "normali" |
| **ON** | Sorveglianza attiva: ogni deviazione dalla baseline genera WARNING o ALARM |

Lo stato è persistente in SQLite e sopravvive ai riavvii.

---

## Protocolli supportati

### Protocolli L2 (classificazione per EtherType)

| Protocollo | EtherType | Note |
|---|---|---|
| Profinet | `0x8892` | Profinet RT/IRT |
| EtherCAT | `0x88A4` | Frame EtherCAT |
| Powerlink | `0x88AB` | ETHERNET Powerlink |
| CC-Link IE | `0x890F` | CC-Link IE Field |
| IEC 61850 GOOSE | `0x88B8` | Generic Object Oriented Substation Event |
| IEC 61850 SV | `0x88BA` | Sampled Values |

### Protocolli L4 (classificazione per porta TCP/UDP)

| Protocollo | Porte | Trasporto |
|---|---|---|
| Modbus TCP | 502 | TCP |
| EtherNet/IP | 44818 (TCP/UDP), 2222 (UDP) | TCP + UDP |
| OPC UA | 4840, 4843 (TLS) | TCP |
| DNP3 | 20000 | TCP + UDP |
| S7comm (Siemens) | 102 | TCP (TPKT/COTP) |
| IEC 61850 MMS | 102 | TCP (TPKT/COTP) |
| BACnet/IP | 47808 | UDP |
| FINS (Omron) | 9600 | TCP + UDP |
| Powerlink (via porte) | 3819, 3820 | — |

### Parser Ethernet

- Supporto **802.1Q VLAN tagging** (incluso Q-in-Q `0x88A8` / `0x9100`)
- Parsing **IPv4** e **IPv6** (con extension headers)
- Parsing **ARP** per rilevamento spoofing
- Estrazione **TCP flags** per rilevamento SYN scan
- Supporto **ICMP / ICMPv6**

### Limiti noti

- La classificazione è basata su EtherType e porte; non viene eseguita Deep Packet Inspection completa
- La porta 102 è ambigua: S7comm e IEC 61850 MMS condividono TPKT/COTP — entrambi vengono segnalati
- Il payload Modbus viene analizzato solo nelle trap honeypot (function code), non nello sniffing passivo

---

## Regole di detection

### WARNING

| Trigger | Interfaccia | Descrizione |
|---|---|---|
| Contatto verso EWS | eth0 | Qualsiasi traffico verso IP/MAC dell'honeypot (esclusa porta Web UI) |
| Nuovo host | eth1 | IP o MAC non presente nella baseline apppresa in `OFF` |
| Connessione trap | eth0 | Tentativo di connessione TCP/UDP su una porta OT dell'honeypot |

### ALARM

| Trigger | Interfaccia | Descrizione |
|---|---|---|
| Protocollo alieno | eth1 | Protocollo OT rilevato su eth1 non presente nella baseline |
| Payload su trap | eth0 | Dati applicativi inviati a una porta trap dell'honeypot |
| Port scan | eth0 | IP sorgente contatta ≥ N porte distinte in T secondi |
| ARP spoofing | eth1 | Mapping IP↔MAC diverso dalla baseline appresa |

### Deduplicazione

Gli eventi duplicati (stessa `dedup_key`) vengono aggregati entro una finestra temporale configurabile, incrementando il contatore `occurrences`.

### Rate limiting

Un limite configurabile (default: 100 eventi/sec) previene il flooding del database in caso di attacchi volumetrici.

---

## API REST

Tutti gli endpoint GET sono accessibili senza autenticazione.  
Gli endpoint mutabili (POST) richiedono l'header `X-Api-Key` **se** la variabile `EWS_API_KEY` è configurata.

| Metodo | Endpoint | Auth | Descrizione |
|---|---|---|---|
| `GET` | `/health` | — | Healthcheck container |
| `GET` | `/api/status` | — | Stato sistema, modalità, interfacce |
| `GET` | `/api/metrics` | — | Metriche per protocollo (pacchetti, PPS, BPS) |
| `GET` | `/api/events` | — | Lista eventi con filtri (severity/protocol/host/time) |
| `GET` | `/api/config` | — | Configurazione runtime |
| `POST` | `/api/state` | `X-Api-Key` | Switch OFF ↔ ON |
| `POST` | `/api/config` | `X-Api-Key` | Modifica dedup window runtime |
| `POST` | `/api/baseline/export` | — | Export baseline JSON |
| `POST` | `/api/baseline/import` | `X-Api-Key` | Import baseline JSON |
| `POST` | `/api/events/emit-test` | — | Genera evento di test |

---

## Web UI

Accessibile via HTTP su `http://<IP_eth0>:<EWS_WEB_PORT>/`.

| Sezione | Contenuto |
|---|---|
| **Dashboard** | 14 card protocollo con colore stato (grigio/verde/giallo/rosso), PPS, BPS, indirizzi rilevati, ultimi eventi. Barra statistiche riepilogativa. |
| **Eventi** | Tabella filtrabile per severity, protocollo, host, finestra temporale. Righe ALARM evidenziate. |
| **Stato** | Toggle OFF/ON, lista protocolli baseline |
| **Configurazione** | Dedup window, export/import baseline JSON |

Campo **API Key** integrato nell'header per autenticazione trasparente.  
Aggiornamento live via polling REST (5s metriche, 7s eventi).

Tutte le renderizzazioni usano escaping XSS (`textContent` / funzione `esc()`).

---

## Deploy

### Prerequisiti

- Docker + Docker Compose
- Interfaccia di rete per management (e opzionalmente una per SPAN mirror)

### 1. Full mode (eth0 + eth1)

Creare `.env`:

```env
# Rete management
EWS_WEB_PORT=8080
EWS_ETH0_IP=192.168.10.250
OT_MGMT_PARENT_IFACE=eth0
OT_MGMT_SUBNET=192.168.10.0/24
OT_MGMT_GATEWAY=192.168.10.1

# Mirror SPAN
OT_SPAN_PARENT_IFACE=eth1

# Detection
EWS_DEDUP_WINDOW_SECONDS=30

# Sicurezza (consigliato)
EWS_API_KEY=una-chiave-segreta-lunga

# Alerting esterno (opzionale)
EWS_WEBHOOK_URL=https://siem.azienda.it/webhook/ews

# Port scan detection
EWS_SCAN_THRESHOLD_PORTS=5
EWS_SCAN_THRESHOLD_SECONDS=60

# Rate limiting eventi
EWS_EVENT_RATE_LIMIT=100
```

Avvio:

```bash
docker compose -f docker-compose.full.yml up -d --build
```

Capability richieste: `NET_RAW`, `NET_ADMIN`.

### 2. Light mode (solo eth0)

`.env` minimale:

```env
EWS_WEB_PORT=8080
EWS_ETH0_IP=192.168.10.250
OT_MGMT_PARENT_IFACE=eth0
OT_MGMT_SUBNET=192.168.10.0/24
OT_MGMT_GATEWAY=192.168.10.1
EWS_DEDUP_WINDOW_SECONDS=30
EWS_API_KEY=una-chiave-segreta-lunga
```

Avvio:

```bash
docker compose -f docker-compose.light.yml up -d --build
```

Capability richieste: `NET_RAW`.

### Rete Docker

Viene usata la rete **macvlan** per assegnare all'honeypot un IP/MAC dedicato sulla rete OT, rendendolo indistinguibile da un asset fisico reale.

---

## Configurazione

### Variabili d'ambiente

| Variabile | Default | Descrizione |
|---|---|---|
| `EWS_MODE` | `full` | Modalità: `full` o `light` |
| `EWS_WEB_HOST` | `0.0.0.0` | Bind address Web UI |
| `EWS_WEB_PORT` | `8080` | Porta Web UI e API |
| `EWS_ETH0_IFACE` | `eth0` | Interfaccia management/honeypot |
| `EWS_ETH1_IFACE` | `eth1` | Interfaccia SPAN mirror |
| `EWS_DATA_DIR` | `/data` | Directory persistenza SQLite |
| `EWS_DEDUP_WINDOW_SECONDS` | `30` | Finestra deduplicazione eventi (1–3600) |
| `EWS_EVENTS_RETENTION_DAYS` | `30` | Retention eventi in giorni |
| `EWS_RECENT_WINDOW_SECONDS` | `600` | Finestra per severity colore card |
| `EWS_API_KEY` | *(vuoto)* | API key per endpoint mutabili. Se vuoto, autenticazione disattivata |
| `EWS_WEBHOOK_URL` | *(vuoto)* | URL webhook per alert ALARM (POST JSON) |
| `EWS_SCAN_THRESHOLD_PORTS` | `5` | Porte distinte per triggerare ALARM port scan |
| `EWS_SCAN_THRESHOLD_SECONDS` | `60` | Finestra temporale port scan detection |
| `EWS_EVENT_RATE_LIMIT` | `100` | Max eventi registrati al secondo (0 = illimitato) |

### Persistenza

Volume obbligatorio: `./data:/data`

Il file `/data/ews.db` contiene:
- Stato macchina (OFF/ON)
- Baseline: protocolli, host, indicatori, mapping ARP
- Eventi WARNING/ALARM con occorrenze
- Statistiche aggregate per protocollo

### Webhook

Quando `EWS_WEBHOOK_URL` è configurato, ogni evento di severity **ALARM** genera un POST JSON:

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

Compatibile con SIEM, Slack, Microsoft Teams, o qualsiasi endpoint HTTP.

---

## Sicurezza

| Misura | Stato |
|---|---|
| API key su endpoint mutabili | Attiva se `EWS_API_KEY` è configurato |
| Protezione XSS nella dashboard | Tutti i dati renderizzati con escaping |
| Rate limiting eventi | Configurabile, default 100/sec |
| ARP spoofing detection | Confronto IP↔MAC vs baseline |
| Port scan detection | Correlazione porte distinte per IP |

### Raccomandazioni operative

- **Configurare sempre `EWS_API_KEY`** in produzione
- **Non esporre la Web UI su reti non fidate** — usarla solo su rete OT isolata o dietro VPN
- **Terminare TLS esternamente** (reverse proxy nginx/traefik) se necessario
- **Non collegare eth1 a reti non-mirror** — lo sniffing è progettato per porte SPAN

### Honeypot trap

L'honeypot apre listener su tutte le porte OT principali. Per ogni connessione:
1. **WARNING** al tentativo di connessione TCP o ricezione datagram UDP
2. **ALARM** se vengono inviati dati applicativi (con log dei primi 128 byte hex)
3. Risposta fake minimale (Modbus error, TPKT/COTP CC, EtherNet/IP ListIdentity) per prolungare l'interazione e raccogliere più informazioni sull'attaccante

---

## Struttura repository

```
EWS_Honeypot_OT/
├── app/
│   ├── config.py          # Configurazione da variabili d'ambiente
│   ├── parser.py          # Parser Ethernet: VLAN, IPv4/v6, ARP, TCP/UDP/ICMP
│   ├── protocols.py       # Classificazione 14 protocolli OT (L2 + L4)
│   ├── sniffer.py         # Raw socket sniffer thread (AF_PACKET)
│   ├── honeypot.py        # TCP/UDP trap con fake responses
│   ├── storage.py         # SQLite (WAL mode) + rate limiter + scan detector
│   └── main.py            # FastAPI app, detection engine, webhook
├── static/
│   └── index.html         # Dashboard SPA (vanilla JS, XSS-safe)
├── Dockerfile
├── docker-compose.full.yml
├── docker-compose.light.yml
├── requirements.txt
└── README.md
```

---

## Stack tecnologico

| Componente | Tecnologia |
|---|---|
| Runtime | Python 3.12 |
| Web framework | FastAPI + Uvicorn |
| Database | SQLite (WAL mode) |
| Packet capture | `AF_PACKET` raw socket (Linux) |
| Container | Docker con macvlan networking |
| Frontend | Vanilla HTML/JS (zero dipendenze) |
