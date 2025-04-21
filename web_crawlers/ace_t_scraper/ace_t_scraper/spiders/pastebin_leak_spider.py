import scrapy
from ..items import AceTScraperItem
from datetime import datetime

class PastebinLeakSpider(scrapy.Spider):
    """
    PastebinLeakSpider

    Purpose: Extract leaked credentials, dox content, and keywords like “leak”, “dump”, “confidential” from Pastebin.com.
    Enhancement: Adds underground chatter and breach visibility to ACE-T.
    """
    name = "pastebin_leak"
    allowed_domains = ["pastebin.com"]
    start_urls = ["https://pastebin.com/archive"]

    def parse(self, response):
        for row in response.css('table.maintable tr')[1:]:
            title = row.css('td a::text').get()
            if title and any(k in title.lower() for k in ["leak", "dump", "confidential", "dox"]):
                item = AceTScraperItem()
                item['title'] = title
                paste_href = row.css('td a::attr(href)').get()
                if paste_href:
                    item['url'] = response.urljoin(paste_href)
                    item['source'] = response.urljoin(paste_href)
                else:
                    item['url'] = response.url
                    item['source'] = response.url
                item['author'] = row.css('td .i_author::text').get()
                item['published_date'] = row.css('td[align="center"]::text').get()
                item['content'] = None
                item['tags'] = ["leak"]
                item['crawled_at'] = datetime.utcnow().isoformat()
                item['error'] = None
                yield item
