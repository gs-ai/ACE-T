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
        if not item.get('title') or not item.get('url'):
            logging.warning(f"Missing required fields in item: {item}")
            return None

        # Transform data (e.g., strip whitespace)
        item['title'] = item['title'].strip()
        item['url'] = item['url'].strip()

        logging.info(f"Processed item: {item}")
        return item
