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
        return item
