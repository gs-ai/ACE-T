

<p align="left">
  <img src="https://img.shields.io/badge/Python-3.11-blue.svg" alt="Python 3.11">
  <img src="https://img.shields.io/badge/Platform-macOS%20%7C%20Linux%20%7C%20Windows-lightgrey.svg" alt="Platform">
  <img src="https://img.shields.io/badge/License-MIT-green.svg" alt="License">
  <img src="https://img.shields.io/badge/Last_Update-2025--10--30-yellow.svg" alt="Last Update">
</p>

# ACE-T: Advanced Cyber-Enabled Threat Intelligence Platform

---

> **Date:** October 27, 2025  
> **Platform:** macOS, Linux, Windows  
> **License:** MIT  
> **Contact:** Project Maintainer (see LICENSE)

---

## Overview
ACE-T is a next-generation, modular Open-Source Intelligence (OSINT) platform engineered for real-time, actionable insights from a wide range of data sources. It leverages advanced AI, NLP, and analytics to empower analysts and security teams with global visibility, automated alerting, and deep threat context.

---

## Features
- Real-time OSINT Monitoring: Ingests and analyzes data from social media, paste sites, forums, code repositories, dark web, and more.
- Modular Architecture: Each data source is handled by a dedicated module or spider for easy extensibility.
- AI/NLP Analytics: Entity extraction, sentiment analysis, trend velocity, and threat context for every alert.
- Rich Metadata: Alerts include geo-info, source URLs, temporal details, threat analysis, tags, and classification.
- Automated Alerting: Real-time GUI and logs for all detected triggers, with map-based visualization of threats.
- Role-Based Access: Secure backend API with user management.
- Extensible Web Crawlers: 15+ spiders for deep/dark web, forums, leaks, and more.
- Review Workflow: All medium/high alerts are copied to `alerts_for_review/` for analyst triage.

---

## Quick Start

1. Install dependencies
   ```sh
   conda env create -f environment.yml
   conda activate ace-t-env
   ```
2. Initialize the database
   ```sh
   alembic upgrade head
   ```
3. Start the platform
   ```sh
   ./start_ace_t.sh
   ```
   This will clean, initialize, and launch all components (backend, OSINT monitor, log ingester, alert GUI, and all spiders).

4. Access the API
   - Open [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs) for interactive API docs.

---

## Database Setup & Migrations
ACE-T uses Alembic for all database schema management and migrations. Do not use manual scripts for table creation.

- To initialize or upgrade the database, run:
  ```sh
  alembic upgrade head
  ```
- To create a new migration after changing models:
  ```sh
  alembic revision --autogenerate -m "Describe your change"
  ```

See `alembic/README` for more details.

---

## OSINT Modules
Each module runs in parallel and logs alerts with full metadata. All modules use the same trigger system (`ace_t_osint/triggers/triggers.json`).

### Supported Modules
- pastebin: Monitors Pastebin for new/deleted pastes matching triggers.
- ghostbin: Monitors Ghostbin for new/deleted pastes.
- rentry: Monitors Rentry for new/deleted pastes.
- reddit: Monitors Reddit threads for trigger patterns and sentiment shifts.
- chans: Monitors 4chan/Endchan boards for regex-based triggers.
- telegram: Monitors public Telegram channels for triggers and edits/deletes.
- twitter: Monitors Twitter/X for trigger patterns.
- archive_org: Observes Archive.org for disappearance/modification of links.
- github: Monitors GitHub gists and commits for sensitive data or keywords.
- shodan: Monitors Shodan for honeypot/scan patterns and exposed devices.
- crtsh: Monitors crt.sh for new domain registrations matching triggers.
- trends: Monitors Google Trends/pytrends for spikes in search interest.

---

## Web Crawler Spiders
All spiders are located in `web_crawlers/ace_t_scraper/ace_t_scraper/spiders/`:

- pastebin_spider.py: Scrapes Pastebin archive for new pastes.
- pastebin_leak_spider.py: Extracts leaked credentials and dox content from Pastebin.
- reddit_spider.py: Scrapes Reddit for new posts in target subreddits.
- twitter_intel_spider.py: Collects tweets with specific hashtags or accounts (via Nitter).
- telegram_indexer_spider.py: Extracts posts and group movements from public Telegram channels.
- bleepingcomputer_spider.py: Scrapes BleepingComputer news for security articles.
- bleepingcomputer_forum_spider.py: Scrapes BleepingComputer forums for new threads.
- forum_spider.py: Monitors high-activity forums for conversations and exploits.
- financial_fraud_spider.py: Extracts BIN lists, CVV dumps, and fraud complaints.
- geo_intel_spider.py: Tracks military movement and regional flashpoints from OSINT/geopolitical sources.
- news_breach_spider.py: Parses breach announcements and cybercrime reports from news sites.
- threat_intel_report_spider.py: Extracts IoCs and threat intelligence from vendor blogs and reports.
- recruitment_spider.py: Tracks cyberwarfare and hacking group job boards.
- darkweb_listing_spider.py: Scrapes darknet marketplaces and forums for leaked data listings.

---

## Alert Metadata Structure
Every alert includes:
- geo_info: Country, city, latitude, longitude (if available)
- source_url: Direct link to the source
- detected_at, first_seen, last_seen: Timestamps for detection and observation
- entities: Extracted organizations and keywords
- threat_analysis: Potential impact, risk vector, related terms
- trend_velocity: Percent increase, previous/current volume
- sentiment: Sentiment classification
- tags, classification: Tags and data classification

Example:
```json
{
  "geo_info": {"country": "Germany", "city": "Berlin", "lat": 52.52, "lon": 13.405},
  "source_url": "https://trends.google.com/trends/explore?q=database+leak&geo=EU",
  "detected_at": "2025-04-18T23:52:07.395474",
  "first_seen": "2025-04-18T23:48:02.192038",
  "last_seen": "2025-04-18T23:51:42.980113",
  "entities": {"organizations": ["Google", "EU Parliament"], "keywords": ["leak", "dump", "database", "cyberattack"]},
  "threat_analysis": {"potential_impact": "Data exposure of sensitive EU databases", "risk_vector": "Public search interest spike", "related_terms": ["data breach", "hack", "cybersecurity"]},
  "trend_velocity": {"increase_percent": 147, "previous_day_volume": 320, "current_volume": 790},
  "sentiment": "negative",
  "tags": ["osint", "data-leak", "trending", "cyber-intel"],
  "classification": "Confidential"
}
```

---

## Triggers
- Triggers are defined in `ace_t_osint/triggers/triggers.json`.
- Each trigger includes a pattern, severity, and context.
- Example:
```json
[
  {"pattern": "database leak", "severity": "high", "context": "Sensitive database leak detected", "trigger_id": "db-leak-001"},
  {"pattern": "CVE-2025-", "severity": "medium", "context": "Potential new CVE", "trigger_id": "cve-2025"}
]
```

---

## Output & Logs
- All alerts and logs are written to `ace_t_osint/output/`:
  - logs.csv (for GUI)
  - logs.json (for analytics)
  - Individual per-alert JSON files
- All medium and high severity alerts are also copied to `alerts_for_review/` for further review.
- The alert GUI displays new alerts in real time and maps medium/high alerts with geolocation.

---

## GUI & Visualization
- Real-time alert table with severity color-coding.
- Full-screen dark mode interface.
- Interactive map (bottom half) with pins for all medium/high alerts (city/region shown if available).
- Clickable markers show full alert details (time, source, context, region, city, etc).

---

## Backend API
- FastAPI backend for user management, alert ingestion, and analytics.
- Interactive docs at [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs)

---

## Analytics
- Run `python ace_t_osint/analytics/analytics.py` for summary reports and statistics on OSINT activity.

---

## Extending ACE-T
- Add new modules in `ace_t_osint/modules/`.
- Add new spiders in `web_crawlers/ace_t_scraper/ace_t_scraper/spiders/`.
- Use `utils.log_signal()` to log alerts with full metadata.
- Register new modules in `ace_t_osint/monitor/main.py`.

---

## Security & Compliance
- All data is stored locally by default.
- Role-based access and audit logging for backend API.
- Designed for compliance with privacy and security best practices.

---

## License
See LICENSE file for details.

---

## Contact
For support or collaboration, contact the project maintainer.

---

<sub>ACE-T is built for the next generation of cyber threat intelligence. Stay sharp. Stay secure.</sub>

## Refactored OSINT Monitor

The OSINT framework now uses an asynchronous pipeline located in `ace_t_osint/`. Key commands:

```sh
python -m ace_t_osint run --sources all --once
python -m ace_t_osint validate
python -m ace_t_osint vacuum
```

Before running, initialize the local SQLite schema and sample directories (this also creates `data/osint.db` on demand):

```sh
python -m ace_t_osint.migrate
```

Alerts are written to `data/osint.db` and JSONL files under `data/alerts/YYYY/MM/DD/alerts.jsonl`. The SQLite database and runtime artifacts are git-ignored and will be generated locally when commands run. Checkpointed seen sets are stored in `data/checkpoints/`.

### Troubleshooting
- Ensure the `tests/fixtures/<source>/sample.html` files exist when running in offline mode.
- Configure per-source URLs, intervals, and concurrency via `ace_t_osint/config.yml`.
- If you need to resume after interruption, rerun with `python -m ace_t_osint.cli run --from-checkpoint --once`.
- For verbose debugging, edit `ace_t_osint/cli.py` to add console logging or update the JSON log at `logs/osint.log`.

---

## Useful Local Commands

Copyable snippets to inspect configuration, cache, alerts and run tests locally. All commands assume you are in the repository root and (when appropriate) have activated the `ace-t-env` conda environment.

- Show configured source URLs and count them:
```bash
python - <<'PY'
import yaml
c=yaml.safe_load(open('ace_t_osint/config.yml'))
s=c.get('sources',{})
count=sum(len(v.get('urls',[])) for v in s.values())
print('source url count:',count)
for name,conf in s.items():
  print(name, conf.get('urls',[]))
PY
```

- List runtime data files and alerts folder:
```bash
ls -la data
ls -la data/alerts || true
ls -la data/checkpoints || true
```

- Show the most recent alerts.jsonl (first 50 lines):
```bash
latest=$(find data/alerts -name alerts.jsonl -print0 | xargs -0 ls -1 -t | head -n1)
echo "latest alert file: $latest"
[ -n "$latest" ] && head -n 50 "$latest" || echo "no alerts.jsonl found"
```

- Inspect HTTP cache (first few keys):
```bash
python - <<'PY'
import json
p='data/http_cache.json'
try:
  d=json.load(open(p,'r',encoding='utf-8'))
except Exception as e:
  print('no cache or failed to read:',e); raise SystemExit
print('cached url count:', len(d))
for i,u in enumerate(list(d.keys())[:10],1):
  print(i,u)
PY
```

- Quick sqlite checks (counts):
```bash
sqlite3 -json data/osint.db "SELECT count(*) AS cnt FROM alerts;"
sqlite3 -json data/osint.db "SELECT count(*) AS cnt FROM runs;"
sqlite3 -json data/osint.db "SELECT count(*) AS cnt FROM seen;"
```

- Run tests and the monitoring CLI (after activating conda env):
```bash
conda activate ace-t-env
pytest -q
# run a single iteration for all configured sources
python -m ace_t_osint run --sources all --once
```

## Startup script location (note)

The repository startup script was moved to `scripts/start_ace_t.sh` to keep the repository root cleaner.

- You can still run the original entrypoint at the repo root with:

```sh
./start_ace_t.sh
```

This file is a small compatibility shim that forwards to `scripts/start_ace_t.sh`, so existing tooling and CI that call `./start_ace_t.sh` will continue to work.

If you prefer to run the implementation directly, use:

```sh
./scripts/start_ace_t.sh
```

## Suggested Additional Public URLs (examples)
The following list contains 25 public URLs that are safe to add as monitoring targets (they do not require API keys or authentication). These are suggestions only — do not add them automatically. Review each target for suitability and robots/terms before using at scale.

1. https://pastebin.com/archive
2. https://paste.ee/archive
3. https://paste.rs/
4. https://hastebin.com/archive
5. https://rentry.org/
6. https://old.reddit.com/r/netsec/
7. https://old.reddit.com/r/cybersecurity/
8. https://news.ycombinator.com/newest
9. https://github.com/trending
10. https://gist.github.com/discover
11. https://web.archive.org/web/*/https://example.com/
12. https://bleepingcomputer.com/forums/ - forum index
13. https://www.exploit-db.com/ - public exploit DB index
14. https://pastebin.com/u/ - public user listings (example)
15. https://boards.4channel.org/g/catalog
16. https://seclists.org/ - security mailing list archives
17. https://www.reddit.com/r/OSINT/
18. https://nitter.net/search?q=security
19. https://nitter.net/OSINTAlerts
20. https://t.me/s/telegramchannelname  (public Telegram channel index page)
21. https://github.com/search?q=password+leak&type=commits
22. https://www.virustotal.com/gui/home/search
23. https://pastebin.com/raw/ (used with paste IDs to fetch raw bodies)
24. https://www.heise.de/news/ (security news in German)
25. https://www.cert.org/ncas/alerts/ (public CERT advisories)

Note: Replace placeholder channel names (like `telegramchannelname`) with actual public channel slugs if you intend to monitor Telegram. Respect each site's robots.txt and terms of service before scraping at scale.


## Wiki

Comprehensive operator and developer documentation now lives in the project wiki. See the rendered pages at `https://github.com/gs-ai/ACE-T/wiki` (or consult the markdown sources under `wiki/` in this repository when offline).

### Publishing wiki updates

Use the helper script to publish the local `wiki/` directory to the GitHub-hosted wiki. The script clones the wiki repository, synchronises the markdown files, commits, and pushes. Provide credentials via your Git configuration or a `GITHUB_TOKEN`-powered credential helper.

```sh
python utilities/publish_wiki.py --remote origin
```

Override the inferred wiki URL with `--wiki-url` when working from a fork or mirror. Set `WIKI_COMMIT_MESSAGE` to customise the commit message.

