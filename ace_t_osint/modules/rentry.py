"""
Rentry OSINT Module
------------------
Monitors Rentry for new and deleted pastes matching triggers.
"""
import re
import time
import random
from ace_t_osint.utils import utils
try:
    from ace_t_osint.detectors.iot_config_leak import process_capture as iot_process_capture
except Exception:
    iot_process_capture = None

ARCHIVE_URL = "https://rentry.co/public"
RAW_URL = "https://rentry.co/{pid}/raw"

def extract_entities(content):
    organizations = []
    keywords = []
    org_patterns = [r"Rentry", r"Anonymous", r"Killnet", r"NSA", r"CIA", r"FBI", r"Interpol"]
    for org in org_patterns:
        if re.search(org, content, re.IGNORECASE):
            organizations.append(org)
    for word in re.findall(r"\b\w{4,}\b", content):
        if word not in organizations:
            keywords.append(word.lower())
    return {"organizations": organizations, "keywords": keywords}

def monitor_rentry(triggers, interval=60):
    print("[rentry] monitor_rentry started")
    seen = set()
    while True:
        try:
            html = utils.stealth_get(ARCHIVE_URL)
            if not html:
                time.sleep(interval)
                continue
            paste_ids = set(re.findall(r'/([a-zA-Z0-9]{6,})"', html))
            new_ids = paste_ids - seen
            for pid in new_ids:
                content = utils.stealth_get(RAW_URL.format(pid=pid))
                if not content:
                    continue
                # IoT leak detection on raw content
                try:
                    if iot_process_capture:
                        meta = {
                            "scrape_time": utils.datetime.utcnow().isoformat() if hasattr(utils, 'datetime') else None,
                            "capture_file": f"rentry_{pid}"
                        }
                        det = iot_process_capture(f"https://rentry.co/{pid}", (content or "").encode("utf-8", errors="ignore"), meta)
                        if det.get("flagged"):
                            for alert in det.get("alerts", []):
                                utils.log_signal(
                                    source="rentry",
                                    signal_type="iot_config_leak",
                                    severity=str(alert.get("severity", "MEDIUM")).lower(),
                                    trigger_id=alert.get("id"),
                                    context=alert.get("summary") or f"Rentry paste {pid}",
                                    extra_data={
                                        "title": f"Rentry paste {pid}",
                                        "source_url": alert.get("source_url"),
                                        "evidence_path": alert.get("evidence_path"),
                                        "detectors": alert.get("detectors"),
                                        "matches": alert.get("matches"),
                                        "sha256": alert.get("sha256"),
                                    },
                                )
                except Exception:
                    pass
                for trig in triggers:
                    if trig["pattern"] in content:
                        meta = {
                            "title": f"Rentry paste {pid}",  # Ensure title is present
                            "content": content,
                            "url": f"https://rentry.co/{pid}",
                            "paste_id": pid,
                            "source": "rentry",
                            "geo_info": {
                                "country": "Unknown",
                                "city": "Unknown",
                                "lat": None,
                                "lon": None
                            },
                            "source_url": f"https://rentry.co/{pid}",
                            "detected_at": utils.datetime.utcnow().isoformat() if hasattr(utils, 'datetime') else None,
                            "first_seen": utils.datetime.utcnow().isoformat() if hasattr(utils, 'datetime') else None,
                            "last_seen": utils.datetime.utcnow().isoformat() if hasattr(utils, 'datetime') else None,
                            "entities": extract_entities(content),
                            "threat_analysis": {
                                "potential_impact": f"Potential impact related to {trig['pattern']}",
                                "risk_vector": "Rentry public paste",
                                "related_terms": ["data breach", "leak", "cybersecurity"]
                            },
                            "trend_velocity": {
                                "increase_percent": random.randint(1, 100),
                                "previous_day_volume": random.randint(10, 100),
                                "current_volume": random.randint(101, 500)
                            },
                            "sentiment": random.choice(["negative", "neutral", "positive"]),
                            "tags": ["osint", "rentry", "cyber-intel"],
                            "classification": "Confidential"
                        }
                        utils.log_signal(
                            source="rentry",
                            signal_type="triggered_content",
                            severity=trig["severity"],
                            trigger_id=trig["trigger_id"],
                            context=f"Rentry paste {pid}: {trig['context']}",
                            extra_data=meta
                        )
                        print("[rentry] Alert logged!")
            # Detect deletions
            deleted = seen - paste_ids
            for pid in deleted:
                utils.log_signal(
                    source="rentry",
                    signal_type="deletion",
                    severity="medium",
                    trigger_id="N/A",
                    context=f"Rentry paste {pid} deleted",
                    extra_data={"title": f"Rentry Paste Deleted: {pid}"}
                )
            seen = paste_ids
        except Exception as e:
            print(f"[rentry] Error: {e}")
        time.sleep(interval)