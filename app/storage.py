from __future__ import annotations

import collections
import json
import os
import sqlite3
import threading
import time

from app.protocols import SUPPORTED_PROTOCOLS


class Storage:
    def __init__(self, data_dir: str):
        os.makedirs(data_dir, exist_ok=True)
        self.db_path = os.path.join(data_dir, "ews.db")
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(self.db_path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._last_metric_snapshot: dict[str, tuple[int, int, float]] = {}

        # ── Rate limiter state ───────────────────────────────────────
        self._event_count_window: int = 0
        self._event_window_start: float = time.time()
        self._event_rate_limit: int = 0  # set by caller

        # ── Port scan detector state ─────────────────────────────────
        # {src_ip: deque of (timestamp, dst_port)}
        self._scan_tracker: dict[str, collections.deque] = {}
        self._scan_alerted: set[str] = set()  # IPs already alerted in current window

        # ── ARP cache for spoofing detection ─────────────────────────
        # {ip: mac} learned from baseline or ARP traffic
        self._arp_cache: dict[str, str] = {}

        self._init_schema()

    def _init_schema(self) -> None:
        with self._conn:
            # Enable WAL mode for better read/write concurrency
            self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.execute("PRAGMA synchronous=NORMAL")
            self._conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS settings (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS baseline_protocols (
                    protocol TEXT PRIMARY KEY,
                    first_seen REAL NOT NULL,
                    last_seen REAL NOT NULL
                );

                CREATE TABLE IF NOT EXISTS baseline_hosts (
                    address TEXT PRIMARY KEY,
                    addr_type TEXT NOT NULL,
                    first_seen REAL NOT NULL,
                    last_seen REAL NOT NULL
                );

                CREATE TABLE IF NOT EXISTS baseline_indicators (
                    indicator TEXT PRIMARY KEY,
                    indicator_type TEXT NOT NULL,
                    first_seen REAL NOT NULL,
                    last_seen REAL NOT NULL
                );

                CREATE TABLE IF NOT EXISTS protocol_stats (
                    protocol TEXT PRIMARY KEY,
                    packets INTEGER NOT NULL DEFAULT 0,
                    bytes INTEGER NOT NULL DEFAULT 0,
                    updated_at REAL NOT NULL
                );

                CREATE TABLE IF NOT EXISTS protocol_addresses (
                    protocol TEXT NOT NULL,
                    address TEXT NOT NULL,
                    count INTEGER NOT NULL DEFAULT 0,
                    last_seen REAL NOT NULL,
                    PRIMARY KEY (protocol, address)
                );

                CREATE TABLE IF NOT EXISTS events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ts REAL NOT NULL,
                    last_seen REAL NOT NULL,
                    severity TEXT NOT NULL,
                    protocol TEXT,
                    src_ip TEXT,
                    dst_ip TEXT,
                    src_mac TEXT,
                    dst_mac TEXT,
                    port INTEGER,
                    ethertype TEXT,
                    description TEXT NOT NULL,
                    dedup_key TEXT,
                    occurrences INTEGER NOT NULL DEFAULT 1
                );

                CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts DESC);
                CREATE INDEX IF NOT EXISTS idx_events_sev ON events(severity);
                CREATE INDEX IF NOT EXISTS idx_events_proto ON events(protocol);
                CREATE INDEX IF NOT EXISTS idx_events_dedup ON events(dedup_key, last_seen DESC);

                -- ARP baseline table (IP ↔ MAC mapping learned in OFF mode)
                CREATE TABLE IF NOT EXISTS baseline_arp (
                    ip TEXT PRIMARY KEY,
                    mac TEXT NOT NULL,
                    first_seen REAL NOT NULL,
                    last_seen REAL NOT NULL
                );
                """
            )

        if self.get_setting("system_state") is None:
            self.set_setting("system_state", "OFF")

        # Preload ARP cache from baseline
        self._load_arp_cache()

    def _load_arp_cache(self) -> None:
        with self._lock:
            rows = self._conn.execute("SELECT ip, mac FROM baseline_arp").fetchall()
        self._arp_cache = {row["ip"]: row["mac"] for row in rows}

    # ── Rate limiter ─────────────────────────────────────────────────

    def _check_rate_limit(self) -> bool:
        """Return True if event should be allowed, False if rate-limited."""
        if self._event_rate_limit <= 0:
            return True
        now = time.time()
        if now - self._event_window_start >= 1.0:
            self._event_window_start = now
            self._event_count_window = 0
        self._event_count_window += 1
        return self._event_count_window <= self._event_rate_limit

    # ── Port scan detection ──────────────────────────────────────────

    def track_port_contact(self, src_ip: str, dst_port: int | None,
                           threshold_ports: int, threshold_seconds: int) -> bool:
        """Track a port contact from src_ip. Returns True if scan threshold exceeded."""
        if not src_ip or dst_port is None:
            return False

        now = time.time()
        cutoff = now - threshold_seconds

        if src_ip not in self._scan_tracker:
            self._scan_tracker[src_ip] = collections.deque()

        q = self._scan_tracker[src_ip]
        q.append((now, dst_port))

        # Purge old entries
        while q and q[0][0] < cutoff:
            q.popleft()

        # Count distinct ports
        distinct_ports = {port for _, port in q}
        if len(distinct_ports) >= threshold_ports:
            if src_ip not in self._scan_alerted:
                self._scan_alerted.add(src_ip)
                return True
        else:
            self._scan_alerted.discard(src_ip)

        return False

    # ── ARP spoofing detection ───────────────────────────────────────

    def upsert_baseline_arp(self, ip: str, mac: str) -> None:
        """Learn IP↔MAC mapping during baseline (OFF mode)."""
        if not ip or not mac:
            return
        now = time.time()
        mac = mac.lower()
        self._arp_cache[ip] = mac
        with self._lock, self._conn:
            self._conn.execute(
                """
                INSERT INTO baseline_arp(ip, mac, first_seen, last_seen)
                VALUES(?, ?, ?, ?)
                ON CONFLICT(ip) DO UPDATE SET mac=excluded.mac, last_seen=excluded.last_seen
                """,
                (ip, mac, now, now),
            )

    def check_arp_consistency(self, ip: str, mac: str) -> str | None:
        """Return alert description if IP↔MAC changed vs baseline. None if OK."""
        if not ip or not mac:
            return None
        mac = mac.lower()
        known_mac = self._arp_cache.get(ip)
        if known_mac is None:
            return None  # IP not in baseline, handled by new-host detection
        if known_mac != mac:
            return (
                f"ARP spoofing sospetto: IP {ip} associato a MAC {mac}, "
                f"baseline atteso {known_mac}"
            )
        return None

    # ── Core CRUD ────────────────────────────────────────────────────

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    def set_setting(self, key: str, value: str) -> None:
        with self._lock, self._conn:
            self._conn.execute(
                "INSERT INTO settings(key, value) VALUES(?, ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                (key, value),
            )

    def get_setting(self, key: str) -> str | None:
        with self._lock:
            row = self._conn.execute("SELECT value FROM settings WHERE key=?", (key,)).fetchone()
        return row["value"] if row else None

    def get_state(self) -> str:
        return self.get_setting("system_state") or "OFF"

    def set_state(self, state: str) -> None:
        self.set_setting("system_state", state)

    def upsert_baseline_protocol(self, protocol: str) -> None:
        now = time.time()
        with self._lock, self._conn:
            self._conn.execute(
                """
                INSERT INTO baseline_protocols(protocol, first_seen, last_seen)
                VALUES(?, ?, ?)
                ON CONFLICT(protocol) DO UPDATE SET last_seen=excluded.last_seen
                """,
                (protocol, now, now),
            )

    def get_baseline_protocols(self) -> set[str]:
        with self._lock:
            rows = self._conn.execute("SELECT protocol FROM baseline_protocols").fetchall()
        return {row["protocol"] for row in rows}

    def upsert_baseline_host(self, address: str, addr_type: str) -> None:
        if not address:
            return
        now = time.time()
        with self._lock, self._conn:
            self._conn.execute(
                """
                INSERT INTO baseline_hosts(address, addr_type, first_seen, last_seen)
                VALUES(?, ?, ?, ?)
                ON CONFLICT(address) DO UPDATE SET last_seen=excluded.last_seen
                """,
                (address, addr_type, now, now),
            )

    def has_baseline_host(self, address: str) -> bool:
        if not address:
            return True
        with self._lock:
            row = self._conn.execute("SELECT 1 FROM baseline_hosts WHERE address=?", (address,)).fetchone()
        return row is not None

    def upsert_baseline_indicator(self, indicator: str) -> None:
        if not indicator:
            return
        now = time.time()
        indicator_type = "port" if indicator.startswith("port:") else "ethertype"
        with self._lock, self._conn:
            self._conn.execute(
                """
                INSERT INTO baseline_indicators(indicator, indicator_type, first_seen, last_seen)
                VALUES(?, ?, ?, ?)
                ON CONFLICT(indicator) DO UPDATE SET last_seen=excluded.last_seen
                """,
                (indicator, indicator_type, now, now),
            )

    def add_protocol_observation(self, protocol: str, packet_size: int, addresses: list[str]) -> None:
        now = time.time()
        with self._lock, self._conn:
            self._conn.execute(
                """
                INSERT INTO protocol_stats(protocol, packets, bytes, updated_at)
                VALUES(?, 1, ?, ?)
                ON CONFLICT(protocol)
                DO UPDATE SET packets=packets+1, bytes=bytes+excluded.bytes, updated_at=excluded.updated_at
                """,
                (protocol, packet_size, now),
            )
            for address in addresses:
                if not address:
                    continue
                self._conn.execute(
                    """
                    INSERT INTO protocol_addresses(protocol, address, count, last_seen)
                    VALUES(?, ?, 1, ?)
                    ON CONFLICT(protocol, address)
                    DO UPDATE SET count=count+1, last_seen=excluded.last_seen
                    """,
                    (protocol, address, now),
                )

    def record_event(self, event: dict, dedup_window_seconds: int) -> None:
        # Rate limiter check
        if not self._check_rate_limit():
            return

        now = time.time()
        dedup_key = event.get("dedup_key")
        with self._lock, self._conn:
            if dedup_key:
                row = self._conn.execute(
                    """
                    SELECT id, occurrences FROM events
                    WHERE dedup_key=? AND last_seen >= ?
                    ORDER BY id DESC LIMIT 1
                    """,
                    (dedup_key, now - dedup_window_seconds),
                ).fetchone()
                if row:
                    self._conn.execute(
                        "UPDATE events SET last_seen=?, occurrences=? WHERE id=?",
                        (now, row["occurrences"] + 1, row["id"]),
                    )
                    return

            self._conn.execute(
                """
                INSERT INTO events(
                    ts, last_seen, severity, protocol, src_ip, dst_ip, src_mac, dst_mac,
                    port, ethertype, description, dedup_key, occurrences
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1)
                """,
                (
                    now,
                    now,
                    event.get("severity"),
                    event.get("protocol"),
                    event.get("src_ip"),
                    event.get("dst_ip"),
                    event.get("src_mac"),
                    event.get("dst_mac"),
                    event.get("port"),
                    event.get("ethertype"),
                    event.get("description", ""),
                    dedup_key,
                ),
            )

    def purge_old_events(self, retention_days: int) -> None:
        cutoff = time.time() - (retention_days * 86400)
        with self._lock, self._conn:
            self._conn.execute("DELETE FROM events WHERE last_seen < ?", (cutoff,))

    def list_events(
        self,
        severity: str | None = None,
        protocol: str | None = None,
        host: str | None = None,
        since_seconds: int | None = None,
        limit: int = 200,
    ) -> list[dict]:
        clauses = []
        params: list = []

        if severity:
            clauses.append("severity = ?")
            params.append(severity)
        if protocol:
            clauses.append("protocol = ?")
            params.append(protocol)
        if host:
            clauses.append("(src_ip = ? OR dst_ip = ? OR src_mac = ? OR dst_mac = ?)")
            params.extend([host, host, host.lower(), host.lower()])
        if since_seconds:
            clauses.append("last_seen >= ?")
            params.append(time.time() - since_seconds)

        where = " WHERE " + " AND ".join(clauses) if clauses else ""
        query = (
            "SELECT * FROM events"
            + where
            + " ORDER BY last_seen DESC LIMIT ?"
        )
        params.append(limit)

        with self._lock:
            rows = self._conn.execute(query, tuple(params)).fetchall()
        return [dict(row) for row in rows]

    def _recent_severity_map(self, window_seconds: int) -> dict[str, str]:
        cutoff = time.time() - window_seconds
        with self._lock:
            rows = self._conn.execute(
                "SELECT protocol, MAX(CASE WHEN severity='ALARM' THEN 2 WHEN severity='WARNING' THEN 1 ELSE 0 END) AS sev FROM events WHERE last_seen >= ? GROUP BY protocol",
                (cutoff,),
            ).fetchall()
        severity_map: dict[str, str] = {}
        for row in rows:
            if row["protocol"] is None:
                continue
            sev = row["sev"]
            if sev == 2:
                severity_map[row["protocol"]] = "ALARM"
            elif sev == 1:
                severity_map[row["protocol"]] = "WARNING"
        return severity_map

    def get_metrics(self, recent_window_seconds: int = 600) -> dict:
        now = time.time()
        baseline_protocols = self.get_baseline_protocols()
        with self._lock:
            stat_rows = self._conn.execute("SELECT * FROM protocol_stats").fetchall()

        stats_by_proto = {row["protocol"]: dict(row) for row in stat_rows}
        recent_map = self._recent_severity_map(recent_window_seconds)
        cards = []

        for protocol in SUPPORTED_PROTOCOLS:
            stat = stats_by_proto.get(protocol, {"packets": 0, "bytes": 0, "updated_at": now})
            packets = int(stat.get("packets", 0))
            bytes_count = int(stat.get("bytes", 0))

            prev_packets, prev_bytes, prev_ts = self._last_metric_snapshot.get(protocol, (packets, bytes_count, now))
            elapsed = max(now - prev_ts, 1e-3)
            pps = max((packets - prev_packets) / elapsed, 0.0)
            bps = max(((bytes_count - prev_bytes) * 8) / elapsed, 0.0)
            self._last_metric_snapshot[protocol] = (packets, bytes_count, now)

            with self._lock:
                addresses = self._conn.execute(
                    "SELECT address, count FROM protocol_addresses WHERE protocol=? ORDER BY count DESC LIMIT 20",
                    (protocol,),
                ).fetchall()
                proto_events = self._conn.execute(
                    "SELECT * FROM events WHERE protocol=? ORDER BY last_seen DESC LIMIT 10",
                    (protocol,),
                ).fetchall()

            recent = recent_map.get(protocol)
            if recent == "ALARM":
                color = "red"
            elif recent == "WARNING":
                color = "yellow"
            elif protocol in baseline_protocols:
                color = "green"
            else:
                color = "gray"

            cards.append(
                {
                    "protocol": protocol,
                    "color": color,
                    "packets": packets,
                    "pps": round(pps, 2),
                    "bps": round(bps, 2),
                    "addresses": [dict(row) for row in addresses],
                    "events": [dict(row) for row in proto_events],
                }
            )

        return {
            "cards": cards,
            "baseline_protocols": sorted(list(baseline_protocols)),
        }

    def export_baseline(self) -> dict:
        with self._lock:
            protocols = [dict(row) for row in self._conn.execute("SELECT * FROM baseline_protocols").fetchall()]
            hosts = [dict(row) for row in self._conn.execute("SELECT * FROM baseline_hosts").fetchall()]
            indicators = [dict(row) for row in self._conn.execute("SELECT * FROM baseline_indicators").fetchall()]
        return {
            "protocols": protocols,
            "hosts": hosts,
            "indicators": indicators,
        }

    def import_baseline(self, payload: dict) -> None:
        now = time.time()
        protocols = payload.get("protocols", [])
        hosts = payload.get("hosts", [])
        indicators = payload.get("indicators", [])

        with self._lock, self._conn:
            self._conn.execute("DELETE FROM baseline_protocols")
            self._conn.execute("DELETE FROM baseline_hosts")
            self._conn.execute("DELETE FROM baseline_indicators")

            for item in protocols:
                protocol = item["protocol"] if isinstance(item, dict) else str(item)
                self._conn.execute(
                    "INSERT OR REPLACE INTO baseline_protocols(protocol, first_seen, last_seen) VALUES(?, ?, ?)",
                    (protocol, now, now),
                )

            for item in hosts:
                if isinstance(item, dict):
                    address = item.get("address")
                    addr_type = item.get("addr_type", "unknown")
                else:
                    address = str(item)
                    addr_type = "unknown"
                if not address:
                    continue
                self._conn.execute(
                    "INSERT OR REPLACE INTO baseline_hosts(address, addr_type, first_seen, last_seen) VALUES(?, ?, ?, ?)",
                    (address, addr_type, now, now),
                )

            for item in indicators:
                indicator = item["indicator"] if isinstance(item, dict) else str(item)
                indicator_type = "port" if indicator.startswith("port:") else "ethertype"
                self._conn.execute(
                    "INSERT OR REPLACE INTO baseline_indicators(indicator, indicator_type, first_seen, last_seen) VALUES(?, ?, ?, ?)",
                    (indicator, indicator_type, now, now),
                )

    def get_config_snapshot(self) -> dict:
        return {
            "state": self.get_state(),
            "baseline": self.export_baseline(),
        }

    def dump_json(self) -> str:
        return json.dumps(self.get_config_snapshot(), indent=2)
