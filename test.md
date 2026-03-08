

# Piano di Test EWS Honeypot OT — Sessione di Validazione

> **Contesto**: rete PROFINET industriale, 1 macchina reale, PC aggiuntivi per generare traffico, EWS su laptop e NUC industriale.  
> **Durata stimata**: 4–5 ore (un pomeriggio)

---

## 0. Preparazione (30 min)

| Attività | Dettagli |
|----------|----------|
| Schema di rete | Disegna e fotografa la topologia: macchina PROFINET ↔ switch ↔ EWS (eth1 mirror port + eth0 management) |
| Software sui PC di attacco | Installa in anticipo tutti i tool elencati sotto |
| Baseline di rete | Cattura 5 min di traffico "pulito" con Wireshark sul mirror port per avere un riferimento |
| Configurazione EWS | Annota i parametri in `.env` / variabili d'ambiente usati per ogni run |
| Monitoraggio risorse | Installa `htop`, `iotop`, `nethogs` sul host EWS; su Windows usa Resource Monitor |

### Tool da installare sui PC di attacco

| Tool | Licenza | Uso nel test | Download |
|------|---------|-------------|----------|
| **Nmap** | GPL | Scansione porte, OS fingerprint, script NSE | nmap.org |
| **arpspoof** (dsniff) | BSD | ARP spoofing | `apt install dsniff` |
| **Ettercap** | GPL | MITM, ARP poisoning con GUI | ettercap.github.io |
| **hping3** | GPL | Flood SYN, pacchetti custom | `apt install hping3` |
| **Scapy** | GPL | Crafting pacchetti PROFINET/ARP custom | scapy.net |
| **Wireshark / tshark** | GPL | Cattura e verifica traffico | wireshark.org |
| **CODESYS Gateway** (free) | Freeware | Generare traffico PROFINET/Industrial Ethernet reale | codesys.com |
| **iperf3** | BSD | Test di throughput per stress test | iperf.fr |
| **stress-ng** | GPL | Carico CPU/RAM sul host EWS | `apt install stress-ng` |
| **mz (mausezahn)** | GPL | Generatore di pacchetti ad alta velocità | `apt install netsniff-ng` |
| **Python 3 + scapy** | — | Script personalizzati per i test | — |

---

## 1. Test Funzionali

### TEST F1 — Rilevamento traffico PROFINET legittimo (eth1 mirror)

**Obiettivo**: verificare che il traffico PROFINET normale della macchina venga osservato e catalogato senza generare falsi positivi.

| Step | Azione | Risultato atteso |
|------|--------|-----------------|
| 1 | Avvia la macchina industriale in funzionamento normale | — |
| 2 | Avvia EWS e lascia girare per 10 min | — |
| 3 | Controlla dashboard (`/api/stats`, `/api/events`) | Nessun WARNING o ALARM; contatori di pacchetti in crescita |
| 4 | Verifica su Wireshark che il mirror port riceva i frame | Frame PROFINET (EtherType `0x8892`) visibili |

**Metrica**: conteggio falsi positivi in 10 min di traffico pulito → **deve essere 0**.

---

### TEST F2 — Rilevamento Port Scan

**Obiettivo**: verificare che una scansione porte generi un ALARM.

````bash
# Dal PC attaccante, diretto verso un IP nella subnet del mirror
# Scansione SYN su 100 porte (supera la soglia di 5 porte in 60s)
nmap -sS -p 1-100 --max-rate 50 <IP_TARGET>
````

| Step | Azione | Risultato atteso |
|------|--------|-----------------|
| 1 | Lancia il comando Nmap | — |
| 2 | Controlla dashboard entro 60s | ALARM "Port scan detected" con IP sorgente corretto |
| 3 | Verifica che il suono `allarm.mp3` venga riprodotto | Audio alarm udibile |
| 4 | Verifica che non si riproduca in loop | Un solo playback |

**Varianti da testare**:
- `nmap -sT` (TCP connect)
- `nmap -sU -p 1-50` (UDP scan)
- `nmap -sS -p 1-3` (sotto soglia → **non** deve generare alarm)

---

### TEST F3 — Rilevamento ARP Spoofing / ARP Poisoning (eth1)

**Obiettivo**: verificare il rilevamento di inconsistenze ARP sulla rete PROFINET.

````bash
# Opzione A: arpspoof
sudo arpspoof -i <IFACE> -t <IP_MACCHINA> <IP_GATEWAY>

# Opzione B: Ettercap (GUI)
# Seleziona "ARP Poisoning" tra IP macchina e gateway

# Opzione C: Scapy (preciso e ripetibile)
python3 -c "
from scapy.all import *
# ARP reply falsificato: associa IP della macchina al MAC dell'attaccante
pkt = ARP(op=2, pdst='<IP_MACCHINA>', hwdst='ff:ff:ff:ff:ff:ff',
          psrc='<IP_GATEWAY>', hwsrc='<MAC_ATTACCANTE>')
sendp(Ether(dst='ff:ff:ff:ff:ff:ff')/pkt, iface='<IFACE>', count=10, inter=0.5)
"
````

| Step | Risultato atteso |
|------|-----------------|
| Invio ARP spoofati | ALARM/WARNING con descrizione ARP inconsistency |
| Dashboard | Evento con MAC sorgente e IP coinvolti |
| Audio | Riproduzione suono corrispondente alla severity |

---

### TEST F4 — Gateway Discovery / ARP Spoofing su eth0 (NUOVA FUNZIONE)

**Obiettivo**: verificare che pacchetti destinati al MAC di eth0 ma con IP destinazione diverso dall'IP locale generino un ALARM.

````python
# Script Scapy dal PC nella stessa subnet di eth0
from scapy.all import *
import sys

target_mac = "<MAC_ETH0_EWS>"   # MAC reale di eth0
target_ip  = "<IP_ETH0_EWS>"    # IP reale di eth0
fake_dst_ip = "192.168.1.254"   # IP diverso dall'EWS

# Pacchetto ICMP indirizzato al MAC dell'EWS ma con IP destinazione errato
pkt = Ether(dst=target_mac) / IP(src="192.168.1.100", dst=fake_dst_ip) / ICMP()
sendp(pkt, iface="<IFACE>", count=5, inter=1)
print("Inviati 5 pacchetti gateway discovery")
````

| Step | Risultato atteso |
|------|-----------------|
| Invio pacchetti | ALARM "Gateway Discovery o ARP Spoofing" |
| Dettagli evento | Contiene IP sorgente, IP destinazione fake, MAC locale |
| Audio | `allarm.mp3` riprodotto |

**Test negativo**: inviare pacchetti con IP destinazione corretta → **nessun alarm**.

---

### TEST F5 — Trap su porte aperte eth0

**Obiettivo**: Provare a collegarsi da un altro dispositivo su una delle trap di eth0

````bash
echo "ping" | nc -u -v -w2 <IP_EWS_ETH0> 2222
````

| Risultato atteso | ALARM registrato in caso di pacchetto ricevuto |
|-----------------|------------------------------------------------|

---

### TEST F6 — Rate Limiting eventi

**Obiettivo**: verificare che con `EWS_EVENT_RATE_LIMIT=100` non vengano registrati più di 100 eventi/secondo.

````bash
# Flood ad alta velocità con hping3
sudo hping3 -S --flood -p ++1 <IP_TARGET>
````
Fallito su docker
| Verifica | `SELECT COUNT(*) FROM events WHERE ts > datetime('now','-1 second')` ≤ 100 |
|----------|---------------------------------------------------------------------------|

---

## 2. Test di Sicurezza

### TEST S1 — API senza chiave

````bash
# Tentativo di cancellare eventi senza API key
curl -X POST http://<EWS_IP>:8080/api/events/clear
# Risultato atteso: 403 Forbidden (se EWS_API_KEY è configurata)
````

### TEST S2 — L'EWS non genera traffico sulla rete PROFINET

````bash
# Su un PC separato, cattura tutto il traffico su eth1 (mirror) e filtra per MAC dell'EWS
tshark -i <MIRROR_IFACE> -f "ether src <MAC_ETH1_EWS>" -a duration:300
# Risultato atteso: 0 pacchetti (l'EWS è passivo)
````

---

## 3. Test di Prestazioni

### Configurazione

| Parametro | Laptop | NUC industriale |
|-----------|--------|-----------------|
| CPU | Annotare modello | Annotare modello |
| RAM | Annotare GB | Annotare GB |
| Disco | SSD/HDD | SSD/eMMC |
| OS | Linux (specificare) | Linux (specificare) |


````bash
# Registra prestazioni
CONTAINER=ot-ews-full API_URL=http://127.0.0.1:8080/api/metrics
python3 - <<'PY'
import subprocess, time, re, os, json, urllib.request

container = os.getenv("CONTAINER", "ot-ews-full")
api_url = os.getenv("API_URL", "http://127.0.0.1:8080/api/metrics")
duration = 300  # secondi
interval = 5
cpu_vals, mem_vals, pps_vals = [], [], []
end = time.time() + duration
sample = 0

def parse_mem(s):
    m = re.match(r'([\d.]+)([KMG]i?)B', s)
    if not m: return None
    val, unit = float(m.group(1)), m.group(2)
    factor = {'Ki':1024, 'Mi':1024**2, 'Gi':1024**3}.get(unit, 1)
    return val * factor / (1024**2)  # MB

while time.time() < end:
    # docker stats
    try:
        out = subprocess.check_output(
            ["bash","-c", f"docker stats --no-stream --format '{{{{.CPUPerc}}}} {{{{.MemUsage}}}}' {container}"]
        ).decode().strip()
    except subprocess.CalledProcessError:
        print("docker stats error, riprovo...")
        time.sleep(interval); continue
    if not out:
        print("nessun output da docker stats, riprovo...")
        time.sleep(interval); continue
    parts = out.split(None, 1)
    if len(parts) < 2:
        print("formato inatteso:", out)
        time.sleep(interval); continue
    cpu_s, mem_part = parts
    cpu = float(cpu_s.strip('%'))
    first_mem = mem_part.split('/')[0].strip()
    mem = parse_mem(first_mem)
    if mem is None:
        print("formato memoria inatteso:", mem_part)
        time.sleep(interval); continue

    # api metrics (pps)
    pps_total = 0.0
    try:
        with urllib.request.urlopen(api_url, timeout=3) as resp:
            data = json.load(resp)
            pps_total = sum(float(c.get("pps", 0) or 0) for c in data.get("cards", []))
    except Exception as e:
        print("api metrics error:", e)

    cpu_vals.append(cpu)
    mem_vals.append(mem)
    pps_vals.append(pps_total)
    sample += 1
    ts = time.strftime('%H:%M:%S')
    print(f"[{ts}] sample {sample}: CPU {cpu:.2f}% | MEM {mem:.2f} MB | PPS {pps_total:.2f}")
    time.sleep(interval)

def avg(xs): return sum(xs)/len(xs) if xs else 0
print(f"Samples: {len(cpu_vals)} in {duration}s")
print(f"CPU avg: {avg(cpu_vals):.2f}%")
print(f"Mem avg: {avg(mem_vals):.2f} MB")
print(f"PPS avg: {avg(pps_vals):.2f} pkt/s (somma delle card /api/metrics)")
PY
````

````bash
API_URL= \
python3 - <<'PY'
import os, time, json, urllib.request, psutil

host = os.getenv("EWS_WEB_HOST", "127.0.0.1")
port = os.getenv("EWS_WEB_PORT", "8080")
api_url = os.getenv("API_URL") or f"http://{host}:{port}/api/metrics"
duration = int(os.getenv("DURATION_SECONDS", 300))
interval = int(os.getenv("INTERVAL_SECONDS", 5))

def pick_proc():
    candidates = []
    for p in psutil.process_iter(["cmdline", "name", "pid", "memory_info"]):
        try:
            cmd = " ".join(p.info.get("cmdline") or [])
            if "uvicorn" in cmd:
                candidates.append(p)
        except psutil.Error:
            pass
    if not candidates:
        return None
    # scegli quello con RSS maggiore (probabile main worker)
    return max(candidates, key=lambda p: (p.info.get("memory_info") or p.memory_info()).rss)

proc = pick_proc()
if not proc:
    raise SystemExit("Processo uvicorn non trovato. Avvia prima il server.")

cpu_vals, mem_vals, pps_vals = [], [], []
end = time.time() + duration

# prima chiamata per inizializzare il delta CPU
proc.cpu_percent(interval=None)

while time.time() < end:
    # misura CPU bloccando per 'interval' secondi
    cpu = proc.cpu_percent(interval=interval)
    try:
        mem = proc.memory_info().rss / (1024**2)  # MB
    except psutil.Error:
        print("processo terminato"); break

    pps_total = 0.0
    try:
        with urllib.request.urlopen(api_url, timeout=3) as resp:
            data = json.load(resp)
            pps_total = sum(float(c.get("pps", 0) or 0) for c in data.get("cards", []))
    except Exception as e:
        print("api metrics error:", e)

    cpu_vals.append(cpu); mem_vals.append(mem); pps_vals.append(pps_total)
    ts = time.strftime('%H:%M:%S')
    print(f"[{ts}] CPU {cpu:.2f}% | MEM {mem:.2f} MB | PPS {pps_total:.2f}")

def avg(xs): return sum(xs)/len(xs) if xs else 0
print(f"Samples: {len(cpu_vals)} in {duration}s")
print(f"CPU avg: {avg(cpu_vals):.2f}%")
print(f"Mem avg: {avg(mem_vals):.2f} MB")
print(f"PPS avg: {avg(pps_vals):.2f} pkt/s (somma delle card /api/metrics)")
PY
````

### TEST P1 — Baseline a riposo

````bash
# Avvia EWS senza traffico, misura dopo 2 minuti di stabilizzazione
# Terminale 1:
htop  # annota CPU%, RSS memory

# Terminale 2:
du -sh /data/ews.db   # dimensione DB

# Terminale 3:
curl -o /dev/null -s -w "%{time_total}\n" http://localhost:8080/api/stats
# → tempo di risposta API a riposo
````

| Metrica | Laptop | NUC | Edge |
|---------|--------|-----|------|
| CPU % idle | | | |
| RAM RSS (MB) | | | |
| PPS | | | |

Media 5min 5sec ogni rilevamento

### TEST P2 — Carico crescente di pacchetti

Usa **mausezahn** o **hping3** per generare traffico a rate controllato sul mirror port:

````bash
# 100 pkt/s
sudo mz eth1 -t tcp "sp=1-65535,dp=502" -c 0 -d 10ms &
# Misura per 5 minuti, poi annota

# 1.000 pkt/s
sudo mz eth1 -t tcp "sp=1-65535,dp=502" -c 0 -d 1ms &

# 10.000 pkt/s
sudo mz eth1 -t tcp "sp=1-65535,dp=502" -c 0 -d 100us &

# 50.000 pkt/s (stress)
sudo hping3 -S --flood -p 502 <IP_TARGET>
````

Per ogni livello di traffico misura **per 5 minuti**:

| Metrica | 100 pkt/s | 1K pkt/s | 10K pkt/s | 50K pkt/s |
|---------|-----------|----------|-----------|-----------|
| CPU % (laptop) | | | | |
| CPU % (NUC) | | | | |
| RAM RSS MB (laptop) | | | | |
| RAM RSS MB (NUC) | | | | |
| Pacchetti persi (%) | | | | |
| Latenza API /stats (ms) | | | | |
| Eventi/s registrati | | | | |
| Dim. DB dopo 5 min | | | | |

**Come misurare i pacchetti persi**: confronta il contatore di pacchetti in EWS (`/api/stats`) con il contatore di `tshark -q -z io,stat,5` sullo stesso interfaccia.

### TEST P3 — Crescita del database nel tempo

````bash
# Genera traffico a 1000 pkt/s per 1 ora
# Ogni 10 minuti annota:
du -sh /data/ews.db
sqlite3 /data/ews.db "SELECT COUNT(*) FROM events;"
curl -s -w "\n%{time_total}" http://localhost:8080/api/events?limit=100
````

| T (min) | N. eventi DB | Dim. DB (MB) | Latenza API (ms) |
|---------|-------------|-------------|-----------------|
| 0 | | | |
| 10 | | | |
| 20 | | | |
| 30 | | | |
| 40 | | | |
| 50 | | | |
| 60 | | | |

### TEST P4 — Retention e pulizia

````bash
# Imposta retention a 0 giorni per forzare la pulizia
EWS_EVENTS_RETENTION_DAYS=0
# Riavvia EWS, verifica che il DB si riduca
````

### TEST P5 — Dashboard sotto carico

| Test | Azione | Metrica |
|------|--------|---------|
| Apertura dashboard con 0 eventi | GET `/` | Tempo di caricamento completo |
| Apertura dashboard con 10.000 eventi | GET `/` + GET `/api/events` | Tempo di caricamento |
| Refresh automatico (polling 5s) sotto flood | Osserva la dashboard per 2 min | Fluidità, ritardi, blocchi browser |

---

## 4. Test PROFINET-specifici

### TEST PN1 — Traffico PROFINET reale

| Step | Azione | Verifica |
|------|--------|---------|
| 1 | Macchina in ciclo produttivo | EWS vede frame EtherType `0x8892` |
| 2 | Arresta la macchina | Verifica che EWS rilevi il cambio di pattern (se implementato) |
| 3 | Riavvia la macchina | Traffico riprende normalmente, nessun falso positivo |

### TEST PN2 — Pacchetti PROFINET malformati

````python
# Scapy: invia frame con EtherType PROFINET ma payload invalido
from scapy.all import *
pkt = Ether(dst="<MAC_PLC>", type=0x8892) / Raw(load=b"\x00" * 100)
sendp(pkt, iface="<IFACE>", count=10)
````

---

## 5. Checklist di Documentazione per la Tesi

Per ogni test, raccogli:

- [ ] **Screenshot** della dashboard prima e dopo
- [ ] **Cattura pcap** (Wireshark) del traffico generato
- [ ] **Log** dell'EWS (`docker logs` o output terminale)
- [ ] **Screenshot htop/Resource Monitor** durante i test di prestazioni
- [ ] **Fotografie** del setup fisico (cablaggio, switch, macchina)
- [ ] **Tabelle compilate** con i dati numerici
- [ ] **Timestamp** di inizio e fine di ogni test

---

> **Nota per la tesi**: questo piano di test copre le tre dimensioni fondamentali — **funzionalità** (il sistema rileva ciò che deve), **sicurezza** (il sistema non introduce rischi), **prestazioni** (il sistema è adeguato all'hardware industriale). I risultati quantitativi dei test P1–P5 permetteranno un confronto diretto laptop vs NUC e la definizione dei requisiti minimi hardware.