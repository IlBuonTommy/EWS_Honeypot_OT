from __future__ import annotations

import os
from dataclasses import dataclass


@dataclass(slots=True)
class Settings:
    data_dir: str
    web_host: str
    web_port: int
    eth0_iface: str
    eth1_iface: str
    mode_light: bool
    dedup_window_seconds: int
    events_retention_days: int
    recent_window_seconds: int

    @staticmethod
    def from_env() -> "Settings":
        mode = os.getenv("EWS_MODE", "full").strip().lower()
        mode_light = mode == "light"
        return Settings(
            data_dir=os.getenv("EWS_DATA_DIR", "/data"),
            web_host=os.getenv("EWS_WEB_HOST", "0.0.0.0"),
            web_port=int(os.getenv("EWS_WEB_PORT", "8080")),
            eth0_iface=os.getenv("EWS_ETH0_IFACE", "eth0"),
            eth1_iface=os.getenv("EWS_ETH1_IFACE", "eth1"),
            mode_light=mode_light,
            dedup_window_seconds=int(os.getenv("EWS_DEDUP_WINDOW_SECONDS", "30")),
            events_retention_days=int(os.getenv("EWS_EVENTS_RETENTION_DAYS", "30")),
            recent_window_seconds=int(os.getenv("EWS_RECENT_WINDOW_SECONDS", "600")),
        )
