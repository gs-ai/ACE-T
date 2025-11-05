"""
ACE-T Scraper Pipelines

Handles validation, transformation, and post-processing of scraped items.
Includes robust logging and error handling for data quality.
"""
# Define your item pipelines here
#
# Don't forget to add your pipeline to the ITEM_PIPELINES setting
# See: https://docs.scrapy.org/en/latest/topics/item-pipeline.html


# useful for handling different item types with a single interface
from itemadapter import ItemAdapter
import logging
import sys
from pathlib import Path

# Make ACE-T repo root importable so we can log into the unified pipeline
try:
    ROOT = Path(__file__).resolve().parents[3]
    if str(ROOT) not in sys.path:
        sys.path.append(str(ROOT))
    from ace_t_osint.utils import utils as ace_utils
    from ace_t_osint.detectors.iot_config_leak import process_capture as iot_process_capture
except Exception:  # pragma: no cover - be resilient in scraper-only runs
    ace_utils = None
    iot_process_capture = None

class AceTScraperPipeline:
    def process_item(self, item, spider):
        # Validate item fields
        required_fields = ['title', 'url']
        missing = [f for f in required_fields if not item.get(f)]
        if missing:
            logging.warning(f"Missing required fields {missing} in item: {item}")
            item['error'] = f"Missing fields: {missing}"
            # Optionally, yield or store incomplete items for review
            return item

        # Transform data (e.g., strip whitespace)
        for field in ['title', 'url', 'author', 'published_date', 'content', 'source']:
            if item.get(field) and isinstance(item[field], str):
                item[field] = item[field].strip()
        if item.get('tags') and isinstance(item['tags'], list):
            item['tags'] = [t.strip() for t in item['tags'] if isinstance(t, str)]

        # Add timestamp if missing
        if not item.get('crawled_at'):
            from datetime import datetime
            item['crawled_at'] = datetime.utcnow().isoformat()

        logging.info(f"Processed item: {item}")

        # 1) Run IoT leak detector on item content (if available)
        try:
            if iot_process_capture and item.get('content') and item.get('url'):
                content_bytes = (item.get('content') or '').encode('utf-8', errors='ignore')
                metadata = {
                    'scrape_time': item.get('crawled_at'),
                    'user_agent': None,
                    'headers': None,
                    'response_status': None,
                    'capture_file': (item.get('title') or item.get('url') or 'scrapy_item')[:64].replace(' ', '_')
                }
                det = iot_process_capture(item['url'], content_bytes, metadata)
                if det.get('flagged') and ace_utils is not None:
                    for alert in det.get('alerts', []):
                        source = getattr(spider, 'name', 'scrapy')
                        signal_type = 'iot_config_leak'
                        severity = str(alert.get('severity', 'MEDIUM')).lower()
                        trigger_id = alert.get('id')
                        context = alert.get('summary') or (item.get('title') or item.get('url') or '')
                        extra_data = {
                            'source_url': alert.get('source_url') or item.get('url'),
                            'title': item.get('title'),
                            'detectors': alert.get('detectors'),
                            'matches': alert.get('matches'),
                            'sha256': alert.get('sha256'),
                            'evidence_path': alert.get('evidence_path'),
                            'metadata': alert.get('metadata') or {},
                            'source': item.get('source') or source,
                        }
                        ace_utils.log_signal(source, signal_type, severity, trigger_id, context, extra_data=extra_data)
        except Exception as e:
            logging.warning(f"IoT detector failed on item: {e}")

        # 2) Forward into ACE-T unified alert pipeline so results appear in output/logs.csv
        # and medium/high go to alerts_for_review automatically (baseline visibility).
        try:
            if ace_utils is not None:
                source = getattr(spider, 'name', 'scrapy')
                signal_type = 'spider'
                severity = 'medium'  # use medium to ensure visibility in review folder
                trigger_id = item.get('title') or source
                context = item.get('title') or item.get('url') or ''
                extra_data = {
                    'source_url': item.get('url'),
                    'title': item.get('title'),
                    'tags': item.get('tags') or [],
                    'author': item.get('author'),
                    'published_date': item.get('published_date'),
                    'content': item.get('content'),
                    'source': item.get('source') or source,
                }
                ace_utils.log_signal(source, signal_type, severity, trigger_id, context, extra_data=extra_data)
        except Exception as e:
            logging.warning(f"Failed to forward item to ACE-T alerts pipeline: {e}")

        return item
