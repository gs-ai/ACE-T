import scrapy
from ..items import AceTScraperItem
from datetime import datetime

class BleepingComputerSpider(scrapy.Spider):
    name = "bleepingcomputer"
    allowed_domains = ["bleepingcomputer.com"]
    start_urls = ["https://www.bleepingcomputer.com/news/security/"]

    def parse(self, response):
        for article in response.css('div.bc_latest_news li'):
            item = AceTScraperItem()
            item['title'] = article.css('a::text').get()
            article_href = article.css('a::attr(href)').get()
            if article_href:
                item['url'] = response.urljoin(article_href)
                item['source'] = response.urljoin(article_href)
            else:
                item['url'] = response.url
                item['source'] = response.url
            item['author'] = None
            item['published_date'] = article.css('span.bc_latest_news_date::text').get()
            item['content'] = None
            item['tags'] = []
            item['crawled_at'] = datetime.utcnow().isoformat()
            item['error'] = None
            yield item
