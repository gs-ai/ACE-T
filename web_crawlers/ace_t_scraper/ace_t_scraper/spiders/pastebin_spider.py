import scrapy
from ..items import AceTScraperItem
from datetime import datetime

class PastebinSpider(scrapy.Spider):
    name = "pastebin"
    allowed_domains = ["pastebin.com"]
    start_urls = ["https://pastebin.com/archive"]

    def parse(self, response):
        for row in response.css('table.maintable tr')[1:]:
            item = AceTScraperItem()
            item['title'] = row.css('td a::text').get()
            paste_href = row.css('td a::attr(href)').get()
            if paste_href:
                item['url'] = response.urljoin(paste_href)
                item['source'] = response.urljoin(paste_href)
            else:
                item['url'] = response.url
                item['source'] = response.url
            item['author'] = row.css('td .i_author::text').get()
            item['published_date'] = row.css('td[align="center"]::text').get()
            item['content'] = None  # Content requires a follow request
            item['tags'] = []
            item['crawled_at'] = datetime.utcnow().isoformat()
            item['error'] = None
            yield item
