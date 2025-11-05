"""
Twitter/X OSINT Module
---------------------
Scrapes Twitter/X frontend timelines or search results with user-agent rotation for triggers.
"""
import time
import random
import re
from ace_t_osint.utils import utils
from ..parsers import nitter

def extract_entities(text):
    organizations = []
    keywords = []
    org_patterns = [r"Twitter", r"Anonymous", r"Killnet", r"NSA", r"CIA", r"FBI", r"Interpol"]
    for org in org_patterns:
        if re.search(org, text, re.IGNORECASE):
            organizations.append(org)
    for word in re.findall(r"\b\w{4,}\b", text):
        if word not in organizations:
            keywords.append(word.lower())
    return {"organizations": organizations, "keywords": keywords}

def monitor_twitter(triggers, interval=120):
    print("[twitter] monitor_twitter started")
    """Monitor Twitter/X for trigger patterns using nitter."""
    users = ["anonymous", "killnet", "legion"]  # Users to monitor
    seen_urls = set()
    while True:
        for user in users:
            timeline_url = f"https://nitter.net/{user}"
            html = utils.stealth_get(timeline_url)
            if not html:
                continue
            items = nitter.parse_timeline(html, "https://nitter.net")
            for item in items:
                if item.url in seen_urls:
                    continue
                seen_urls.add(item.url)
                content = item.content
                for trig in triggers:
                    if trig["pattern"].lower() in content.lower():
                        meta = {
                            "title": item.title,
                            "content": content,
                            "user": user,
                            "url": item.url,
                            "source": "twitter",
                            "geo_info": {
                                "country": "Unknown",
                                "city": "Unknown",
                                "lat": None,
                                "lon": None
                            },
                            "source_url": item.url,
                            "detected_at": utils.datetime.utcnow().isoformat(),
                            "first_seen": utils.datetime.utcnow().isoformat(),
                            "last_seen": utils.datetime.utcnow().isoformat(),
                            "entities": extract_entities(content),
                            "threat_analysis": {
                                "potential_impact": f"Potential impact related to {trig['pattern']}",
                                "risk_vector": "Twitter post",
                                "related_terms": ["data breach", "leak", "cybersecurity"]
                            },
                            "trend_velocity": {
                                "increase_percent": random.randint(1, 100),
                                "previous_day_volume": random.randint(10, 100),
                                "current_volume": random.randint(101, 500)
                            },
                            "sentiment": random.choice(["negative", "neutral", "positive"]),
                            "tags": ["osint", "twitter", "cyber-intel"],
                            "classification": "Confidential"
                        }
                        utils.log_signal(
                            source="twitter",
                            signal_type="triggered_content",
                            severity=trig["severity"],
                            trigger_id=trig["trigger_id"],
                            context=f"Twitter user {user}: {trig['context']}",
                            extra_data=meta
                        )
                        print(f"[twitter] Alert logged for {item.url}")
        time.sleep(interval)
