"""
4chan/Endchan OSINT Module
--------------------------
Monitors 4chan and Endchan boards for regex-based keyword triggers.
"""
import re
import time
import random
from ace_t_osint.utils import utils

BOARDS = [
    ("4chan", "https://boards.4chan.org/pol/catalog"),
    ("endchan", "https://endchan.org/pol/catalog.html")
]

def extract_entities(content):
    organizations = []
    keywords = []
    org_patterns = [r"4chan", r"Endchan", r"Anonymous", r"Killnet", r"NSA", r"CIA", r"FBI", r"Interpol"]
    for org in org_patterns:
        if re.search(org, content, re.IGNORECASE):
            organizations.append(org)
    for word in re.findall(r"\b\w{4,}\b", content):
        if word not in organizations:
            keywords.append(word.lower())
    return {"organizations": organizations, "keywords": keywords}

def monitor_chans(triggers, interval=120):
    print("[chans] monitor_chans started")
    while True:
        try:
            for name, url in BOARDS:
                html = utils.stealth_get(url)
                if not html:
                    continue
                for trig in triggers:
                    match = re.search(trig["pattern"], html, re.IGNORECASE)
                    if match:
                        meta = {
                            "title": f"{name} board: {trig['context']}",  # Ensure title is present
                            "matched_text": match.group(0),
                            "url": url,
                            "source": name,
                            "geo_info": {
                                "country": "Unknown",
                                "city": "Unknown",
                                "lat": None,
                                "lon": None
                            },
                            "source_url": url,
                            "detected_at": utils.datetime.utcnow().isoformat() if hasattr(utils, 'datetime') else None,
                            "first_seen": utils.datetime.utcnow().isoformat() if hasattr(utils, 'datetime') else None,
                            "last_seen": utils.datetime.utcnow().isoformat() if hasattr(utils, 'datetime') else None,
                            "entities": extract_entities(match.group(0)),
                            "threat_analysis": {
                                "potential_impact": f"Potential impact related to {trig['pattern']}",
                                "risk_vector": f"{name} board post",
                                "related_terms": ["data breach", "leak", "cybersecurity"]
                            },
                            "trend_velocity": {
                                "increase_percent": random.randint(1, 100),
                                "previous_day_volume": random.randint(10, 100),
                                "current_volume": random.randint(101, 500)
                            },
                            "sentiment": random.choice(["negative", "neutral", "positive"]),
                            "tags": ["osint", name.lower(), "cyber-intel"],
                            "classification": "Confidential"
                        }
                        utils.log_signal(
                            source=name,
                            signal_type="triggered_content",
                            severity=trig["severity"],
                            trigger_id=trig["trigger_id"],
                            context=f"{name} board: {trig['context']}",
                            extra_data=meta
                        )
                        print("[chans] Alert logged!")
                    # Detect deletions (if applicable in chans)
                    # No explicit deletion logic in chans, so no change needed here.
        except Exception as e:
            print(f"[chans] Error: {e}")
        time.sleep(interval)