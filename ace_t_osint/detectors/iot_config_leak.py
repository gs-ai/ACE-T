"""
IoT Configuration Leak Detector
--------------------------------

This module scans captured content for IoT configuration leaks (ESPHome, WMBus,
MQTT, Wi-Fi credentials, AES keys, meter IDs, etc.). It can be used as a
standalone utility or integrated into the scraping pipeline.

Contract:
    process_capture(source_url: str, content: bytes, metadata: dict) -> dict
Returns:
    {
      "flagged": bool,
      "alerts": [<alert-json>],
      "evidence_path": str | None
    }

Safety/Ethics:
    This tool is for defensive research and lawful investigations. Treat any
    keys/PII as sensitive and follow proper disclosure and handling practices.
"""

from __future__ import annotations

import base64
import hashlib
import json
import logging
import os
import re
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

import yaml
from cryptography.fernet import Fernet

# --------------------
# Configuration knobs
# --------------------

DETECT_KEYS = os.getenv("DETECT_KEYS", "true").lower() in {"1", "true", "yes", "on"}
PLAY_SAFETY_REDACT = os.getenv("PLAY_SAFETY_REDACT", "true").lower() in {"1", "true", "yes", "on"}
ALERT_WEBHOOK = os.getenv("ALERT_WEBHOOK")  # optional URL; if set we POST alert JSON
ALERT_QUEUE_PATH = os.getenv("ALERT_QUEUE_PATH")  # optional JSONL queue path


# ----------------
# Logging helpers
# ----------------

def _repo_root() -> Path:
    # ace_t_osint/detectors/iot_config_leak.py -> repo root is parents[2]
    return Path(__file__).resolve().parents[2]


def _get_logger() -> logging.Logger:
    logger = logging.getLogger("scan_detector")
    if logger.handlers:
        return logger
    logger.setLevel(logging.INFO)
    logs_dir = _repo_root() / "logs"
    logs_dir.mkdir(parents=True, exist_ok=True)
    fh = logging.FileHandler(logs_dir / "scan_detector.log")
    ch = logging.StreamHandler()
    fmt = logging.Formatter("%(asctime)s | %(levelname)s | %(message)s")
    fh.setFormatter(fmt)
    ch.setFormatter(fmt)
    logger.addHandler(fh)
    logger.addHandler(ch)
    logger.propagate = False
    return logger


logger = _get_logger()


# ----------------------
# File-type sniffing
# ----------------------

def _try_decode(content: bytes) -> str:
    try:
        return content.decode("utf-8")
    except UnicodeDecodeError:
        return content.decode("latin-1", errors="replace")


def is_yaml_text(text: str) -> bool:
    text_l = text.strip().lower()
    if text_l.startswith("---"):
        return True
    yaml_hints = ("esphome", "wifi:", "mqtt:", "wmbus", "wmbus_meter", "ota:", "api:")
    return any(h in text_l for h in yaml_hints)


def is_json_text(text: str) -> bool:
    t = text.strip()
    return (t.startswith("{") and t.endswith("}")) or (t.startswith("[") and t.endswith("]"))


def is_js_text(text: str) -> bool:
    return "function" in text or "=>" in text or "const " in text or "var " in text


def is_html_text(text: str) -> bool:
    tl = text.strip().lower()
    return tl.startswith("<html") or "<body" in tl or "</html>" in tl


def is_plaintext(text: str) -> bool:
    return not (is_yaml_text(text) or is_json_text(text) or is_js_text(text) or is_html_text(text))


# ----------------------
# Patterns and detectors
# ----------------------

AES_HEX32 = re.compile(r"\b[A-Fa-f0-9]{32}\b")  # AES-128
AES_HEX64 = re.compile(r"\b[A-Fa-f0-9]{64}\b")  # AES-256
BASE64_KEY = re.compile(r"\b[A-Za-z0-9+/]{40,}={0,2}\b")
TOKEN_PATTERN = re.compile(r"(?i)(api[_-]?key|token|secret|passwd|password)\W*[:=]\W*['\"]?([A-Za-z0-9\-\._]{8,})")
SSID_PATTERN = re.compile(r"(?i)\b(ssid|wifi_ssid|wifi)\b.*[:=]\s*['\"]?([^'\"]{1,64})")
MQTT_HOST_PORT = re.compile(r"(?i)\b(mqtt|broker|host)\b\s*[:=]\s*([A-Za-z0-9_.\-]+)(?::(\d{2,5}))?")
IPV4 = re.compile(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b")
MAC = re.compile(r"\b([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}\b")
METER_ID = re.compile(r"\b\d{6,9}\b")
BOARD_NAMES = re.compile(r"(?i)\b(lilygo|sx1276|sx1278|lora|esp32|esp8266|ttgo|esphome|esp-idf|rtl-sdr|wmbus(_meter)?)\b")


@dataclass
class Match:
    type: str
    value: str
    context: str
    lineno: int
    path: Optional[str] = None  # for YAML path context


def _scan_lines_for_patterns(text: str) -> List[Match]:
    matches: List[Match] = []
    for lineno, line in enumerate(text.splitlines(), start=1):
        for regex, mtype in [
            (AES_HEX32, "aes_hex32"),
            (AES_HEX64, "aes_hex64"),
            (BASE64_KEY, "base64_key"),
            (TOKEN_PATTERN, "token_like"),
            (SSID_PATTERN, "ssid"),
            (MQTT_HOST_PORT, "mqtt_host_port"),
            (IPV4, "ipv4"),
            (MAC, "mac"),
            (METER_ID, "meter_id"),
            (BOARD_NAMES, "board_name"),
        ]:
            for m in regex.finditer(line):
                val = m.group(0)
                if mtype == "token_like" and m.groups():
                    val = m.group(2)
                matches.append(Match(type=mtype, value=val, context=line[:240], lineno=lineno))
    return matches


def _yaml_safe_load(text: str) -> Optional[Any]:
    try:
        if len(text) > 2_000_000:  # ~2MB
            return None
        return yaml.safe_load(text)
    except Exception:
        return None


def _walk_yaml(obj: Any, path: str = "") -> Iterable[Tuple[str, Any]]:
    if isinstance(obj, dict):
        for k, v in obj.items():
            p = f"{path}.{k}" if path else str(k)
            yield p, v
            yield from _walk_yaml(v, p)
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            p = f"{path}[{i}]" if path else f"[{i}]"
            yield p, v
            yield from _walk_yaml(v, p)


def _extract_from_yaml(y: Any, raw_text: str) -> List[Match]:
    matches: List[Match] = []
    if not isinstance(y, (dict, list)):
        return matches
    for p, v in _walk_yaml(y):
        s = str(v)
        lineno = raw_text[: raw_text.find(s)].count("\n") + 1 if s and s in raw_text else 1
        for regex, mtype in [
            (AES_HEX32, "aes_hex32"),
            (AES_HEX64, "aes_hex64"),
            (BASE64_KEY, "base64_key"),
            (TOKEN_PATTERN, "token_like"),
            (SSID_PATTERN, "ssid"),
            (MQTT_HOST_PORT, "mqtt_host_port"),
            (IPV4, "ipv4"),
            (MAC, "mac"),
            (METER_ID, "meter_id"),
            (BOARD_NAMES, "board_name"),
        ]:
            m = regex.search(s)
            if m:
                val = m.group(0)
                if mtype == "token_like" and m.groups():
                    val = m.group(2)
                matches.append(Match(type=mtype, value=val, context=p, lineno=lineno, path=p))
    return matches


def _severity_from_matches(matches: List[Match], yaml_features: Dict[str, bool]) -> Tuple[str, str]:
    types = {m.type for m in matches}
    if (
        any(t in types for t in ("aes_hex32", "aes_hex64", "token_like", "ssid"))
        or yaml_features.get("esphome", False)
        or yaml_features.get("wmbus", False)
        or yaml_features.get("wmbus_meter", False)
    ):
        return "HIGH", "Sensitive keys/credentials or ESPHome/WMBus YAML present"
    if any(t in types for t in ("meter_id", "ipv4", "board_name", "mqtt_host_port")):
        return "MEDIUM", "Device identifiers or infrastructure endpoints detected"
    if matches:
        return "LOW", "Potentially sensitive signals (review)"
    return "NONE", "No relevant indicators found"


def _hashes(content: bytes) -> Dict[str, str]:
    return {
        "sha256": hashlib.sha256(content).hexdigest(),
        "md5": hashlib.md5(content).hexdigest(),
    }


def _mask_secrets(text: str) -> str:
    if not PLAY_SAFETY_REDACT:
        return text
    text = AES_HEX64.sub(lambda m: m.group(0)[:8] + "…" + m.group(0)[-4:], text)
    text = AES_HEX32.sub(lambda m: m.group(0)[:8] + "…" + m.group(0)[-4:], text)
    text = BASE64_KEY.sub(lambda m: m.group(0)[:8] + "…" + m.group(0)[-4:], text)
    text = TOKEN_PATTERN.sub(lambda m: f"{m.group(1)}: ********", text)
    text = SSID_PATTERN.sub(lambda m: f"{m.group(1)}: ********", text)
    return text


# ----------------------
# Encryption helpers
# ----------------------

def _get_local_encryption_key() -> Fernet:
    """Derive a symmetric key from environment or fallback secret."""
    secret = os.getenv("ACE_T_SECRET_KEY", "default_local_secret_key")
    key = base64.urlsafe_b64encode(hashlib.sha256(secret.encode()).digest())
    return Fernet(key)


def _write_encrypted_text(filepath: Path, text: str):
    fernet = _get_local_encryption_key()
    token = fernet.encrypt(text.encode("utf-8"))
    with open(filepath, "wb") as f:
        f.write(token)


# ----------------------
# Evidence writer
# ----------------------

def _save_evidence(
    source_url: str,
    content: bytes,
    metadata: Dict[str, Any],
    matches: List[Match],
    detectors: List[str],
    severity: str,
    summary: str,
) -> Tuple[str, Dict[str, Any]]:
    repo = _repo_root()
    day = datetime.now(timezone.utc).strftime("%Y%m%d")
    evidence_dir = repo / "evidence" / day
    evidence_dir.mkdir(parents=True, exist_ok=True)

    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    base_name = metadata.get("capture_file") or f"capture_{ts}"
    base_stem = Path(base_name).stem

    raw_path = evidence_dir / f"{base_stem}.raw"
    with open(raw_path, "wb") as f:
        f.write(content)

    h = _hashes(content)
    with open(evidence_dir / f"{base_stem}.sha256", "w", encoding="utf-8") as f:
        json.dump(h, f)

    # Secure redacted evidence storage (encrypted)
    text = _try_decode(content)
    redacted = _mask_secrets(text)
    outfile = evidence_dir / f"{base_stem}.redacted.enc"
    _write_encrypted_text(outfile, redacted)

    alert = {
        "id": _uuid4(),
        "source_url": source_url,
        "capture_time": metadata.get("scrape_time") or datetime.now(timezone.utc).isoformat(),
        "sha256": h["sha256"],
        "detectors": detectors,
        "matches": [m.__dict__ for m in matches],
        "severity": severity,
        "summary": summary,
        "evidence_path": str(evidence_dir),
        "metadata": metadata,
    }

    flagged_path = evidence_dir / f"flagged_{base_stem}.json"
    with open(flagged_path, "w", encoding="utf-8") as f:
        json.dump(alert, f, ensure_ascii=False, indent=2)

    # Optional queue + webhook
    try:
        if ALERT_QUEUE_PATH:
            qpath = Path(ALERT_QUEUE_PATH)
            qpath.parent.mkdir(parents=True, exist_ok=True)
            with open(qpath, "a", encoding="utf-8") as qf:
                qf.write(json.dumps(alert) + "\n")
    except Exception as e:
        logger.warning(f"Failed to append to alert queue: {e}")

    if ALERT_WEBHOOK:
        try:
            import urllib.request

            req = urllib.request.Request(
                ALERT_WEBHOOK,
                data=json.dumps(alert).encode("utf-8"),
                headers={"Content-Type": "application/json"},
            )
            urllib.request.urlopen(req, timeout=5)
        except Exception as e:
            logger.warning(f"Webhook post failed: {e}")

    return str(flagged_path), alert


def _uuid4() -> str:
    import uuid
    return str(uuid.uuid4())


# ----------------------
# Main process function
# ----------------------

def process_capture(source_url: str, content: bytes, metadata: Dict[str, Any]) -> Dict[str, Any]:
    """Scan content for IoT configuration leaks and write evidence upon detection."""
    start = datetime.now(timezone.utc)
    text = _try_decode(content)
    filetype = (
        "yaml" if is_yaml_text(text) else
        "json" if is_json_text(text) else
        "js" if is_js_text(text) else
        "html" if is_html_text(text) else
        "text"
    )

    all_matches: List[Match] = []
    yaml_features = {"esphome": False, "wmbus": False, "wmbus_meter": False}
    yaml_obj: Any = None

    if is_yaml_text(text):
        yaml_obj = _yaml_safe_load(text)
        if isinstance(yaml_obj, (dict, list)):
            t_low = text.lower()
            yaml_features["esphome"] = "esphome" in t_low
            yaml_features["wmbus"] = "wmbus" in t_low
            yaml_features["wmbus_meter"] = "wmbus_meter" in t_low
            all_matches.extend(_extract_from_yaml(yaml_obj, text))

    all_matches.extend(_scan_lines_for_patterns(text))
    severity, summary = _severity_from_matches(all_matches, yaml_features)

    flagged = severity in {"HIGH", "MEDIUM"}
    alerts: List[dict] = []
    evidence_path: Optional[str] = None

    if flagged and DETECT_KEYS:
        detectors = sorted({m.type for m in all_matches})
        evidence_path, alert = _save_evidence(
            source_url=source_url,
            content=content,
            metadata=metadata,
            matches=all_matches,
            detectors=detectors,
            severity=severity,
            summary=summary,
        )
        alerts.append(alert)
        logger.info(
            f"FLAGGED | url={source_url} | severity={severity} | detectors={','.join(detectors)} | evidence={evidence_path}"
        )
    else:
        logger.info(f"CLEAN | url={source_url} | type={filetype} | signals={len(all_matches)}")

    stop = datetime.now(timezone.utc)
    return {"flagged": flagged, "alerts": alerts, "evidence_path": evidence_path}


# -----------------
# Example Usage
# -----------------
if __name__ == "__main__":
    sample_yaml = b"""
esphome:
  name: demo
wifi:
  ssid: "HomeWiFi"
  password: "supersecret"
mqtt:
  broker: demo-mqtt.local
wmbus_meter:
  - key: 6BD7B8F7B155DBF853021C80476F592F
    meter_id: 12345678
"""
    meta = {"scrape_time": datetime.now(timezone.utc).isoformat(), "capture_file": "demo_capture"}
    result = process_capture("https://example.com/paste", sample_yaml, meta)
    print(json.dumps(result, indent=2))
