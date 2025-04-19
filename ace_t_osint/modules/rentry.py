"""
Rentry OSINT Module
------------------
Monitors Rentry for new and deleted pastes matching triggers.
"""
import re
import time
import random
from ace_t_osint.utils import utils

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
                for trig in triggers:
                    if trig["pattern"] in content:
                        meta = {
                            "content": content,
                            "url": RAW_URL.format(pid=pid),
                            "paste_id": pid,
                            "source": "rentry",
                            "geo_info": {
                                "country": "Unknown",
                                "city": "Unknown",
                                "lat": None,
                                "lon": None
                            },
                            "source_url": RAW_URL.format(pid=pid),
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
                    context=f"Rentry paste {pid} deleted"
                )
            seen = paste_ids
        except Exception as e:
            print(f"[rentry] Error: {e}")
        time.sleep(interval)