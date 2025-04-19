![Project Architecture](15cc352a-102e-4da7-a48b-05b18394f2e9.png)

# ACE-T: Advanced Cyber-Enabled Threat Intelligence Platform

## Overview
ACE-T is a next-generation, modular Open-Source Intelligence (OSINT) platform engineered for real-time, actionable insights from a wide range of data sources. It leverages advanced AI, NLP, and analytics to empower analysts and security teams with global visibility, automated alerting, and deep threat context.

---

## Features
- **Real-time OSINT Monitoring**: Ingests and analyzes data from social media, paste sites, forums, code repositories, and more.
- **Modular Architecture**: Each data source is handled by a dedicated module for easy extensibility.
- **AI/NLP Analytics**: Entity extraction, sentiment analysis, trend velocity, and threat context for every alert.
- **Rich Metadata**: Alerts include geo-info, source URLs, temporal details, threat analysis, tags, and classification.
- **Automated Alerting**: Real-time GUI and logs for all detected triggers.
- **Role-Based Access**: Secure backend API with user management.

---

## Quick Start

1. **Install dependencies**
   ```sh
   conda env create -f environment.yml
   conda activate ace-t-env
   ```
2. **Initialize the database**
   ```sh
   alembic upgrade head
   ```
3. **Start the platform**
   ```sh
   ./start_ace_t.sh
   ```
   This will clean, initialize, and launch all components (backend, OSINT monitor, log ingester, alert GUI).

4. **Access the API**
   - Open [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs) for interactive API docs.

---

## Database Setup & Migrations

ACE-T uses Alembic for all database schema management and migrations. **Do not use manual scripts for table creation.**

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

## Recent Updates (April 2025)

### Improved Module Logging & Monitoring
- All OSINT modules now print a startup message and log when an alert is triggered. This makes it easy to confirm in the terminal that each module is running and actively monitoring.
- The orchestrator prints a message after launching each major component/module.

### GUI Table Fixes
- The alert GUI now filters out header rows from the logs, preventing column names from appearing in the middle of the alert table.
- Alerts are color-coded by severity and pop to the front on high-severity events.

### crt.sh (crtsh) Module
- **crtsh**: Monitors [crt.sh](https://crt.sh/) for new SSL/TLS certificates matching triggers. Useful for detecting new domain registrations, phishing, or suspicious certificate issuance.

### Troubleshooting
- If a module does not print its startup message or log alerts, check the terminal for errors and ensure all dependencies are installed.
- Logs are written to `ace_t_osint/output/logs.csv` and `logs.json`. The GUI displays alerts in real time from these files.

---

## OSINT Modules
Each module runs in parallel and logs alerts with full metadata. All modules use the same trigger system (`ace_t_osint/triggers/triggers.json`).

### Supported Modules
- **pastebin**: Monitors Pastebin for new/deleted pastes matching triggers.
- **ghostbin**: Monitors Ghostbin for new/deleted pastes.
- **rentry**: Monitors Rentry for new/deleted pastes.
- **reddit**: Monitors Reddit threads for trigger patterns and sentiment shifts.
- **chans**: Monitors 4chan/Endchan boards for regex-based triggers.
- **telegram**: Monitors public Telegram channels for triggers and edits/deletes.
- **twitter**: Monitors Twitter/X for trigger patterns.
- **archive_org**: Observes Archive.org for disappearance/modification of links.
- **github**: Monitors GitHub gists and commits for sensitive data or keywords.
- **shodan**: Monitors Shodan for honeypot/scan patterns and exposed devices.
- **crtsh**: Monitors crt.sh for new domain registrations matching triggers.
- **trends**: Monitors Google Trends/pytrends for spikes in search interest.

---

## Alert Metadata Structure
Every alert includes:
- `geo_info`: Country, city, latitude, longitude (if available)
- `source_url`: Direct link to the source
- `detected_at`, `first_seen`, `last_seen`: Timestamps for detection and observation
- `entities`: Extracted organizations and keywords
- `threat_analysis`: Potential impact, risk vector, related terms
- `trend_velocity`: Percent increase, previous/current volume
- `sentiment`: Sentiment classification
- `tags`, `classification`: Tags and data classification

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
- All alerts and logs are written to `ace_t_osint/output/`.
- Each alert is saved as a per-alert JSON file and appended to `logs.csv` and `logs.json`.
- The alert GUI displays new alerts in real time.

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
