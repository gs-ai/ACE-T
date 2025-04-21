import scrapy
from ..items import AceTScraperItem
from datetime import datetime

"""
NewsBreachSpider

Purpose: Parse breach announcements, APT group activity, and cybercrime reports from security news sites.
Enhancement: Brings in curated, vetted intel for correlation in ACE-T.
"""

class NewsBreachSpider(scrapy.Spider):
    name = "news_breach"
    allowed_domains = ["krebsonsecurity.com", "databreaches.net", "hackread.com"]
    start_urls = [
        "https://krebsonsecurity.com/",
        "https://www.databreaches.net/",
        "https://www.hackread.com/category/data-breaches/"
    ]

    def parse(self, response):
        for article in response.css('article'):
            item = AceTScraperItem()
            item['title'] = article.css('h2 a::text, h3 a::text').get()
            article_href = article.css('h2 a::attr(href), h3 a::attr(href)').get()
            if article_href:
                item['url'] = response.urljoin(article_href)
                item['source'] = response.urljoin(article_href)
            else:
                item['url'] = response.url
                item['source'] = response.url
            item['author'] = article.css('.author::text').get()
            item['published_date'] = article.css('time::attr(datetime)').get()
            item['content'] = article.css('div.entry-content p::text').get()
            item['tags'] = ["breach", "news"]
            item['crawled_at'] = datetime.utcnow().isoformat()
            item['error'] = None
            yield item
