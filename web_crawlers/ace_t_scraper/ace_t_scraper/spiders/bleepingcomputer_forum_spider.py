import scrapy
from ..items import AceTScraperItem
from datetime import datetime

class BleepingComputerForumSpider(scrapy.Spider):
    name = "bleepingcomputer_forum"
    allowed_domains = ["bleepingcomputer.com"]
    start_urls = ["https://www.bleepingcomputer.com/forums/f/22/security/",]

    def parse(self, response):
        for thread in response.css('div.topic_title'):
            item = AceTScraperItem()
            item['title'] = thread.css('a::text').get()
            thread_href = thread.css('a::attr(href)').get()
            if thread_href:
                item['url'] = response.urljoin(thread_href)
                item['source'] = response.urljoin(thread_href)
            else:
                item['url'] = response.url
                item['source'] = response.url
            item['author'] = thread.css('span.author::text').get()
            item['published_date'] = None
            item['content'] = None
            item['tags'] = []
            item['crawled_at'] = datetime.utcnow().isoformat()
            item['error'] = None
            yield item
