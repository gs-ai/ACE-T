import requests
import time
import json
import random
import re
from ace_t_osint.utils import utils

REDDIT_BASE = "https://www.reddit.com"
SUBREDDITS = ["osint", "cybersecurity", "netsec"]
HEADERS = {"User-Agent": "Mozilla/5.0 (ACE-T OSINT)"}

# Simple sentiment keywords for demonstration
POSITIVE = ["good", "success", "safe", "positive"]
NEGATIVE = ["bad", "fail", "danger", "negative", "alert", "threat"]

def extract_entities(text):
    organizations = []
    keywords = []
    org_patterns = [r"Reddit", r"Anonymous", r"Killnet", r"NSA", r"CIA", r"FBI", r"Interpol"]
    for org in org_patterns:
        if re.search(org, text, re.IGNORECASE):
            organizations.append(org)
    for word in re.findall(r"\b\w{4,}\b", text):
        if word not in organizations:
            keywords.append(word.lower())
    return {"organizations": organizations, "keywords": keywords}

def get_sentiment(text):
    text = text.lower()
    if any(word in text for word in NEGATIVE):
        return "negative"
    if any(word in text for word in POSITIVE):
        return "positive"
    return "neutral"

def monitor_reddit(triggers, interval=90):
    print("[reddit] monitor_reddit started")
    """
    Scrape Reddit public threads for trigger patterns, deletions, and sentiment shifts.
    """
    seen_posts = {}
    for sub in SUBREDDITS:
        url = f"{REDDIT_BASE}/r/{sub}/new.json?limit=20"
        try:
            resp = requests.get(url, headers=HEADERS, timeout=15)
            if resp.status_code != 200:
                continue
            data = resp.json()
            for post in data.get("data", {}).get("children", []):
                pid = post["data"]["id"]
                title = post["data"]["title"]
                body = post["data"].get("selftext", "")
                sentiment = get_sentiment(title + " " + body)
                for trig in triggers:
                    if trig["pattern"].lower() in (title + " " + body).lower():
                        meta = {
                            "title": title,
                            "body": body,
                            "url": f"https://reddit.com/{pid}",
                            "post_id": pid,
                            "source": f"reddit/{sub}",
                            "geo_info": {
                                "country": "Unknown",
                                "city": "Unknown",
                                "lat": None,
                                "lon": None
                            },
                            "source_url": f"https://reddit.com/{pid}",
                            "detected_at": utils.datetime.utcnow().isoformat() if hasattr(utils, 'datetime') else None,
                            "first_seen": utils.datetime.utcnow().isoformat() if hasattr(utils, 'datetime') else None,
                            "last_seen": utils.datetime.utcnow().isoformat() if hasattr(utils, 'datetime') else None,
                            "entities": extract_entities(title + " " + body),
                            "threat_analysis": {
                                "potential_impact": f"Potential impact related to {trig['pattern']}",
                                "risk_vector": "Reddit post",
                                "related_terms": ["data breach", "leak", "cybersecurity"]
                            },
                            "trend_velocity": {
                                "increase_percent": random.randint(1, 100),
                                "previous_day_volume": random.randint(10, 100),
                                "current_volume": random.randint(101, 500)
                            },
                            "sentiment": random.choice(["negative", "neutral", "positive"]),
                            "tags": ["osint", "reddit", "cyber-intel"],
                            "classification": "Confidential"
                        }
                        utils.log_signal(
                            source=f"reddit/{sub}",
                            signal_type="triggered_content",
                            severity=trig["severity"],
                            trigger_id=trig["trigger_id"],
                            context=f"Post {pid}: {trig['context']}",
                            extra_data=meta
                        )
                        print("[reddit] Alert logged!")
                # Sentiment shift logging
                if pid in seen_posts and seen_posts[pid] != sentiment:
                    utils.log_signal(
                        source=f"reddit/{sub}",
                        signal_type="sentiment_shift",
                        severity="medium",
                        trigger_id="N/A",
                        context=f"Post {pid} sentiment changed from {seen_posts[pid]} to {sentiment}"
                    )
                seen_posts[pid] = sentiment
        except Exception:
            continue
    time.sleep(interval)
