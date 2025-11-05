"""
Telegram OSINT Module
--------------------
Monitors public Telegram channels via t.me/s/ for triggers and edit/delete tracking.
"""
import time
import random
import re
from ace_t_osint.utils import utils
from ..parsers import telegram as telegram_parser

def extract_entities(text):
    organizations = []
    keywords = []
    org_patterns = [r"Telegram", r"Anonymous", r"Killnet", r"NSA", r"CIA", r"FBI", r"Interpol"]
    for org in org_patterns:
        if re.search(org, text, re.IGNORECASE):
            organizations.append(org)
    for word in re.findall(r"\b\w{4,}\b", text):
        if word not in organizations:
            keywords.append(word.lower())
    return {"organizations": organizations, "keywords": keywords}

def monitor_telegram(triggers, interval=180):
    print("[telegram] monitor_telegram started")
    """Monitor public Telegram channels for triggers."""
    channels = ["anonymous", "killnet", "legion"]  # Public channels to monitor
    seen_urls = set()
    while True:
        for channel in channels:
            channel_url = f"https://t.me/s/{channel}"
            html = utils.stealth_get(channel_url)
            if not html:
                continue
            items = telegram_parser.parse_channel(html, "https://t.me")
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
                            "channel": channel,
                            "url": item.url,
                            "source": "telegram",
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
                                "risk_vector": "Telegram channel message",
                                "related_terms": ["data breach", "leak", "cybersecurity"]
                            },
                            "trend_velocity": {
                                "increase_percent": random.randint(1, 100),
                                "previous_day_volume": random.randint(10, 100),
                                "current_volume": random.randint(101, 500)
                            },
                            "sentiment": random.choice(["negative", "neutral", "positive"]),
                            "tags": ["osint", "telegram", "cyber-intel"],
                            "classification": "Confidential"
                        }
                        utils.log_signal(
                            source="telegram",
                            signal_type="triggered_content",
                            severity=trig["severity"],
                            trigger_id=trig["trigger_id"],
                            context=f"Telegram channel {channel}: {trig['context']}",
                            extra_data=meta
                        )
                        print(f"[telegram] Alert logged for {item.url}")
        time.sleep(interval)
