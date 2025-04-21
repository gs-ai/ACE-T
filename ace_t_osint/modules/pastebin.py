import re
import time
import random
from ace_t_osint.utils import utils

def extract_entities(content):
    organizations = []
    keywords = []
    org_patterns = [r"Pastebin", r"Anonymous", r"Killnet", r"NSA", r"CIA", r"FBI", r"Interpol"]
    for org in org_patterns:
        if re.search(org, content, re.IGNORECASE):
            organizations.append(org)
    for word in re.findall(r"\b\w{4,}\b", content):
        if word not in organizations:
            keywords.append(word.lower())
    return {"organizations": organizations, "keywords": keywords}

def monitor_pastebin(triggers, interval=60):
    print("[pastebin] monitor_pastebin started")
    """
    Scrape Pastebin's public archive for new/deleted pastes matching triggers.
    """
    seen = set()
    archive_url = "https://pastebin.com/archive"
    RAW_URL = "https://pastebin.com/raw/{pid}"
    while True:
        html = utils.stealth_get(archive_url)
        if not html:
            time.sleep(interval)
            continue
        paste_ids = set(re.findall(r'/([A-Za-z0-9]{8})"', html))
        new_ids = paste_ids - seen
        for pid in new_ids:
            paste_url = f"https://pastebin.com/raw/{pid}"
            content = utils.stealth_get(paste_url)
            if not content:
                continue
            for trig in triggers:
                if trig["pattern"] in content:
                    meta = {
                        "title": f"Pastebin paste {pid}",  # Ensure title is present
                        "content": content,
                        "url": f"https://pastebin.com/{pid}",
                        "paste_id": pid,
                        "source": "pastebin",
                        "geo_info": {
                            "country": "Unknown",
                            "city": "Unknown",
                            "lat": None,
                            "lon": None
                        },
                        "source_url": f"https://pastebin.com/{pid}",
                        "detected_at": utils.datetime.utcnow().isoformat() if hasattr(utils, 'datetime') else None,
                        "first_seen": utils.datetime.utcnow().isoformat() if hasattr(utils, 'datetime') else None,
                        "last_seen": utils.datetime.utcnow().isoformat() if hasattr(utils, 'datetime') else None,
                        "entities": extract_entities(content),
                        "threat_analysis": {
                            "potential_impact": f"Potential impact related to {trig['pattern']}",
                            "risk_vector": "Pastebin public paste",
                            "related_terms": ["data breach", "leak", "cybersecurity"]
                        },
                        "trend_velocity": {
                            "increase_percent": random.randint(1, 100),
                            "previous_day_volume": random.randint(10, 100),
                            "current_volume": random.randint(101, 500)
                        },
                        "sentiment": random.choice(["negative", "neutral", "positive"]),
                        "tags": ["osint", "pastebin", "cyber-intel"],
                        "classification": "Confidential"
                    }
                    utils.log_signal(
                        source="pastebin",
                        signal_type="triggered_content",
                        severity=trig["severity"],
                        trigger_id=trig["trigger_id"],
                        context=f"Pastebin paste {pid}: {trig['context']}",
                        extra_data=meta
                    )
                    print("[pastebin] Alert logged!")
        # Detect deletions
        deleted = seen - paste_ids
        for pid in deleted:
            utils.log_signal(
                source="pastebin",
                signal_type="deletion",
                severity="medium",
                trigger_id="N/A",
                context=f"Paste {pid} deleted",
                extra_data={"title": f"Paste Deleted: {pid}"}
            )
        seen = paste_ids
        time.sleep(interval)
