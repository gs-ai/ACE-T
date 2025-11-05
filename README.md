# ⚡️ ACE-T: Advanced Cyber-Enabled Threat Intelligence Platform

<p align="left">
  <img src="https://img.shields.io/badge/Python-3.11-blue.svg" alt="Python 3.11">
  <img src="https://img.shields.io/badge/Platform-macOS%20|%20Linux%20|%20Windows-lightgrey.svg" alt="Platform">
  <img src="https://img.shields.io/badge/License-MIT-green.svg" alt="License">
  <img src="https://img.shields.io/badge/Last_Update-2025--11--05-yellow.svg" alt="Last Update">
  <img src="https://img.shields.io/badge/Framework-FastAPI%20%7C%20Scrapy%20%7C%20PyTorch-orange.svg" alt="Frameworks">
</p>

---

> **Date:** November 5, 2025  
> **Platform:** macOS • Linux • Windows  
> **Languages:** Python 3.11, YAML, JSON, JavaScript  
> **Frameworks:** FastAPI, Scrapy, PyTorch  
> **License:** MIT  
> **Maintainer:** gs-ai / ACE-T Team

## Overview

ACE-T is a next-generation modular Open-Source Intelligence (OSINT) platform for real-time, actionable insights across social, deep, and dark web sources.
It combines AI, NLP, and analytics to deliver automated alerting, global visibility, and rich contextual intelligence for investigators and security teams.

## Features

- Real-time OSINT Monitoring — social media, paste sites, forums, code repos, dark web, and more
- Modular Architecture — independent modules for each data source
- AI/NLP Analytics — entity extraction, sentiment, and trend velocity
- Rich Metadata — geo-info, source URLs, timestamps, and classification
- Automated Alerting — live GUI with map-based visualization
- Role-Based Access Control — secure FastAPI backend
- Extensible Spiders — 15+ Scrapy crawlers for surface, deep, and dark web
- Analyst Review Workflow — medium/high alerts routed to alerts_for_review/

## Quick Start

```bash
conda env create -f environment.yml
conda activate ace-t-env

alembic upgrade head

./start_ace_t.sh
# or
make start
```

GUI auto-opens the live Nodes Map.
API available at: http://127.0.0.1:8000/docs

## Database Management

```bash
alembic upgrade head
alembic revision --autogenerate -m "Describe change"
```

## Core OSINT Modules

pastebin
ghostbin
rentry
reddit
chans
telegram
twitter
archive_org
github
shodan
crtsh
trends

## Web Crawlers

Located in: web_crawlers/ace_t_scraper/ace_t_scraper/spiders/

Example:

```bash
cd web_crawlers/ace_t_scraper
outdir="$(cd ../.. && pwd)/data/alerts/$(date +%Y/%m/%d)"
mkdir -p "$outdir"
scrapy crawl pastebin -O "$outdir/pastebin.jsonl"
```

## Alert Metadata Example

```json
{
  "geo_info": {"country": "Germany", "city": "Berlin"},
  "source_url": "https://trends.google.com/trends/explore?q=database+leak&geo=EU",
  "detected_at": "2025-04-18T23:52:07",
  "entities": {"organizations": ["Google"], "keywords": ["leak","database"]},
  "threat_analysis": {"potential_impact": "Data exposure"},
  "trend_velocity": {"increase_percent": 147},
  "sentiment": "negative",
  "tags": ["osint","data-leak","cyber-intel"],
  "classification": "Confidential"
}
```

## Triggers

Defined in ace_t_osint/triggers/triggers.json

```json
[
  {"pattern": "database leak", "severity": "high", "trigger_id": "db-leak-001"},
  {"pattern": "CVE-2025-", "severity": "medium", "trigger_id": "cve-2025"}
]
```

## Output & Logs

```
output/             → alert logs and exports
alerts_for_review/  → medium/high alerts
data/osint.db       → local SQLite DB
data/alerts/YYYY/MM/DD/alerts.jsonl
```

## Refactored OSINT Monitor

```bash
python -m ace_t_osint run --sources all --once
python -m ace_t_osint validate
python -m ace_t_osint vacuum
python -m ace_t_osint.migrate
```

## Local Tools & Checks

```python
import yaml; c=yaml.safe_load(open('ace_t_osint/config.yml'))
for k,v in c.get('sources',{}).items(): print(k, v.get('urls',[]))
```

```bash
sqlite3 -json data/osint.db "SELECT count(*) AS cnt FROM alerts;"

conda activate ace-t-env
pytest -q
python -m ace_t_osint run --sources all --once
```

## Startup Script

scripts/start_ace_t.sh

```bash
./start_ace_t.sh
```

## Suggested Public Monitoring Sources

https://pastebin.com/archive
https://rentry.org/
https://old.reddit.com/r/netsec/
https://github.com/trending
https://seclists.org/
https://bleepingcomputer.com/forums/
https://www.exploit-db.com/
https://www.cisa.gov/newsroom/alerts

## Wiki

Full documentation: https://github.com/gs-ai/ACE-T/wiki

Publish updates:

```bash
python utilities/publish_wiki.py --remote origin
```

## License

MIT License — see LICENSE file.

ACE-T is engineered for precision OSINT and cyber threat intelligence operations.
