# OT Early Warning System (EWS) — Honeypot + Passive OT Probe

Sistema EWS containerizzato per reti OT, progettato per footprint ridotto:
- **Niente PCAP/payload completi**.
- Solo **metadati minimi**: host, porte/etherType, contatori, timestamp, eventi.

## Scelta tecnologica

Implementazione in **Python** per rapidità operativa, leggibilità e manutenzione veloce in ambiente industriale, mantenendo basso footprint tramite:
- parsing pacchetti con `AF_PACKET` + parser minimale custom (no deep DPI pesante),
- persistenza con **SQLite** su volume `/data`,
- API/UI leggere con FastAPI.

## Architettura

### Interfacce
- `eth0`: rete OT/MGMT, Web UI HTTP, honeypot/dispositivo silente.
- `eth1`: sniffing passivo mirror/SPAN (solo full mode).

### Modalità
- **full**: `eth0 + eth1`.
- **light**: solo `eth0` (honeypot attivo, niente baseline su mirror, niente alien-protocol detection su eth1).

### Stato macchina (persistente)
- `OFF` (SPENTO): apprendimento baseline su `eth1` (se presente).
- `ON` (ACCESO): sorveglianza con warning/alarm su deviazioni baseline.

Stato e baseline sono persistiti in `/data/ews.db`.

## Requisiti runtime e permessi

### Opzione rete consigliata
**macvlan** (raccomandata): più adatta ad asset OT con IP/MAC dedicato e separazione netta `eth0`/`eth1`.

### Capability container
- Full mode: `NET_RAW`, `NET_ADMIN`
- Light mode: `NET_RAW`

## Regole detection

### WARNING
1. Traffico verso IP/MAC EWS su `eth0`, escluso TCP verso porta Web UI.
2. In `ON`, nuovo host (IP/MAC) su `eth1` non presente in baseline.

### ALARM
1. In `ON`, protocollo OT su `eth1` non presente in baseline (`OFF`).

Eventi includono: timestamp, severità, protocollo, src/dst IP, src/dst MAC, porta/etherType, descrizione, contatore occorrenze (dedup/rate limit).

## Protocol detection: layer, indicatori, limiti

| Protocollo | Layer prevalente | Indicatori usati | Limiti noti |
|---|---|---|---|
| Profinet | L2 (+ discovery) | EtherType `0x8892` | Best effort, non include parsing semantico completo PN-DCP/RT |
| EtherNet/IP | L4 (TCP/UDP) | porte `44818` (TCP/UDP), `2222` (UDP) | Classificazione per porte, CIP non decodificato in profondità |
| EtherCAT | L2 | EtherType `0x88A4` | Nessun deep parsing mailbox/process-data |
| Modbus TCP | L4 TCP | porta `502/TCP` | Nessuna validazione applicativa PDU |
| Powerlink | L2/L4 | EtherType `0x88AB`, porte `3819/3820` | Possibili varianti profilo non distinguibili al 100% |
| CC-Link (IE) | L2/L4 | EtherType `0x88B5`, porta `61450` | Classificazione come famiglia CC-Link IE (best effort varianti) |

## API REST minime

- `GET /api/status` — stato, modalità, interfacce, info web.
- `POST /api/state` — switch `OFF`/`ON`.
- `GET /api/metrics` — metriche aggregate per protocollo.
- `GET /api/events` — filtri: severità/protocollo/host/tempo.
- `POST /api/baseline/export` — export baseline JSON.
- `POST /api/baseline/import` — import baseline JSON.
- `GET /health` — healthcheck container.

## Web UI (senza login)

Accesso via HTTP su `eth0`.

Sezioni:
- **Dashboard**: 6 card (Profinet, EtherNet/IP, EtherCAT, Modbus TCP, Powerlink, CC-Link IE) con:
  - colore stato (grigio/verde/giallo/rosso),
  - pacchetti, pps, bps,
  - indirizzi rilevati per protocollo,
  - ultimi eventi per protocollo.
- **Eventi**: tabella filtrabile.
- **Stato**: toggle `OFF`/`ON` + baseline protocolli.
- **Configurazione**: dedup runtime + export/import baseline.

Aggiornamento live tramite polling REST.

## Deploy step-by-step

### 1) Full mode (eth0 + eth1)

Creare file `.env` (esempio):

```env
EWS_WEB_PORT=8080
EWS_ETH0_IP=192.168.10.250

OT_MGMT_PARENT_IFACE=eth0
OT_MGMT_SUBNET=192.168.10.0/24
OT_MGMT_GATEWAY=192.168.10.1

OT_SPAN_PARENT_IFACE=eth1
EWS_DEDUP_WINDOW_SECONDS=30
```

Avvio:

```bash
docker compose -f docker-compose.full.yml up -d --build
```

### 2) Light mode (solo eth0)

`.env` minimale:

```env
EWS_WEB_PORT=8080
EWS_ETH0_IP=192.168.10.250
OT_MGMT_PARENT_IFACE=eth0
OT_MGMT_SUBNET=192.168.10.0/24
OT_MGMT_GATEWAY=192.168.10.1
EWS_DEDUP_WINDOW_SECONDS=30
```

Avvio:

```bash
docker compose -f docker-compose.light.yml up -d --build
```

## Persistenza

Volume obbligatorio: `./data:/data`.

Database: `/data/ews.db` con:
- baseline protocolli/host/indicatori,
- stato macchina,
- eventi warning/alarm,
- statistiche aggregate per protocollo.

## Endpoint UI/API principali

- UI: `http://<IP_eth0>:<EWS_WEB_PORT>/`
- Health: `http://<IP_eth0>:<EWS_WEB_PORT>/health`

## Struttura repository

```
app/
  config.py
  parser.py
  protocols.py
  sniffer.py
  honeypot.py
  storage.py
  main.py
static/
  index.html
Dockerfile
docker-compose.full.yml
docker-compose.light.yml
requirements.txt
```

## Note sicurezza operative

- UI **senza autenticazione**: usare solo su rete OT fidata/isolata.
- HTTP in chiaro: terminare TLS esternamente se necessario.
- Non collegare `eth1` a reti non mirror (sniffing passivo progettato per SPAN).

## Kill-chain rationale

Scansione/recon è spesso fase iniziale della kill-chain OT. Il sistema segnala precocemente:
- contatti inattesi verso asset EWS (honeypot silente),
- nuovi host/protocolli alieni rispetto alla normalità appresa.
