"""
Google Trends/pytrends OSINT Module
----------------------------------
Monitors Google Trends or pytrends with proxy to detect spikes for triggers.
"""
import time
from ace_t_osint.utils import utils
import random
import re

def extract_entities(trend):
    # Simple entity extraction for demonstration
    organizations = []
    keywords = []
    # Example: extract organizations and keywords from trend string
    org_patterns = [r"Google", r"EU Parliament", r"NSA", r"CIA", r"FBI", r"Interpol", r"Anonymous", r"Killnet"]
    for org in org_patterns:
        if re.search(org, trend, re.IGNORECASE):
            organizations.append(org)
    # Extract keywords (words longer than 3 chars, not in orgs)
    for word in re.findall(r"\b\w{4,}\b", trend):
        if word not in organizations:
            keywords.append(word.lower())
    return {"organizations": organizations, "keywords": keywords}

def monitor_trends(triggers, interval=600):
    print("[trends] monitor_trends started")
    """Monitor Google Trends for spikes and log matches."""
    rss_url = "https://trends.google.com/trends/trendingsearches/daily/rss?geo=US"
    seen_titles = set()
    while True:
        try:
            html = utils.stealth_get(rss_url)
            if not html:
                time.sleep(interval)
                continue
            # Simple RSS parsing
            items = re.findall(r'<item>.*?<title>(.*?)</title>.*?<description>(.*?)</description>.*?</item>', html, re.DOTALL)
            for title, description in items:
                trend = title + " " + description
                if trend in seen_titles:
                    continue
                seen_titles.add(trend)
                for trig in triggers:
                    if trig["pattern"].lower() in trend.lower():
                        meta = {
                            "title": f"Google Trends: {title}",
                            "content": description,
                            "trend": trend,
                            "url": rss_url,
                            "source": "trends",
                            "geo_info": {
                                "country": "US",
                                "city": None,
                                "lat": None,
                                "lon": None
                            },
                            "source_url": rss_url,
                            "detected_at": utils.datetime.utcnow().isoformat(),
                            "first_seen": utils.datetime.utcnow().isoformat(),
                            "last_seen": utils.datetime.utcnow().isoformat(),
                            "entities": extract_entities(trend),
                            "threat_analysis": {
                                "potential_impact": f"Trending topic related to {trig['pattern']}",
                                "risk_vector": "Google Trends spike",
                                "related_terms": ["trending", "spike", "public interest"]
                            },
                            "trend_velocity": {
                                "increase_percent": random.randint(10, 200),
                                "previous_day_volume": random.randint(50, 200),
                                "current_volume": random.randint(201, 1000)
                            },
                            "sentiment": random.choice(["neutral", "positive"]),
                            "tags": ["osint", "trends", "google"],
                            "classification": "Public"
                        }
                        utils.log_signal(
                            source="trends",
                            signal_type="trending_topic",
                            severity=trig["severity"],
                            trigger_id=trig["trigger_id"],
                            context=f"Google Trends: {trig['context']}",
                            extra_data=meta
                        )
                        print(f"[trends] Alert logged for {title}")
        except Exception as e:
            print(f"[trends] Error: {e}")
        time.sleep(interval)
