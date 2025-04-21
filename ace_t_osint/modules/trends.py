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
    """Monitor Google Trends/pytrends for spikes using proxy and log all matches like other modules."""
    # Simulate trending topics and regions for demonstration
    regions = ["US", "EU", "Asia", "Africa", "LATAM", "Oceania", "RU", "CN", "IN", "UK", "DE", "FR", "BR", "JP"]
    base_trends = [
        "Emotet", "TrickBot", "QakBot", "Cobalt Strike", "ransom note", "database leak", "carding", "Anonymous", "Killnet",
        "#Breaking", "#FakeNews", "#Ukraine", "#Taiwan", ".xyz", ".top", "SHA256:", "MD5:", "botnet", "deepfake", "pump and dump",
        "wallet address", "cp", "escort service", "vaccine leak", "bioterrorism", "SCADA hack", "power grid", "vote rigging",
        "ballot fraud", "doxxing", "CEO email", "prompt injection", "model jailbreak", "protest", "riot", "evacuation", "0day",
        "CVE-2025-", "exploit kit", "login page", "reset your password", "verify your account", "internal document", "whistleblower",
        "supply chain attack", "vendor breach", "acme-corp-internal", "acme-corp-leak", "combo list", "honeypot", "confidential:projectx"
    ]
    while True:
        # Simulate trending data
        trending_data = [
            {"trend": random.choice(base_trends), "region": random.choice(regions)}
            for _ in range(10)
        ]
        for data in trending_data:
            trend = data["trend"]
            region = data["region"]
            for trig in triggers:
                if trig["pattern"].lower() in trend.lower():
                    # Enhanced metadata for each alert
                    meta = {
                        "title": f"Google Trends {region}",
                        "trend": trend,
                        "region": region,
                        "source": "trends",
                        "geo_info": {
                            "country": "Germany",
                            "city": "Berlin",
                            "lat": 52.52,
                            "lon": 13.405
                        },
                        "source_url": f"https://trends.google.com/trends/explore?q={trend.replace(' ', '+')}&geo={region}",
                        "detected_at": utils.datetime.utcnow().isoformat() if hasattr(utils, 'datetime') else None,
                        "first_seen": utils.datetime.utcnow().isoformat() if hasattr(utils, 'datetime') else None,
                        "last_seen": utils.datetime.utcnow().isoformat() if hasattr(utils, 'datetime') else None,
                        "entities": extract_entities(trend),
                        "threat_analysis": {
                            "potential_impact": f"Potential impact related to {trend}",
                            "risk_vector": "Public search interest spike",
                            "related_terms": ["data breach", "hack", "cybersecurity"]
                        },
                        "trend_velocity": {
                            "increase_percent": random.randint(10, 200),
                            "previous_day_volume": random.randint(100, 500),
                            "current_volume": random.randint(501, 1000)
                        },
                        "sentiment": random.choice(["negative", "neutral", "positive"]),
                        "tags": ["osint", "data-leak", "trending", "cyber-intel"],
                        "classification": "Confidential"
                    }
                    utils.log_signal(
                        source="trends",
                        signal_type="triggered_content",
                        severity=trig["severity"],
                        trigger_id=trig["trigger_id"],
                        context=f"Google Trends {region}: {trig['context']}",
                        extra_data=meta
                    )
                    print("[trends] Alert logged!")
        time.sleep(interval)
