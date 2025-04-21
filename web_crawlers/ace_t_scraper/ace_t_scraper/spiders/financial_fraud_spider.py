import scrapy
from ..items import AceTScraperItem
from datetime import datetime

"""
FinancialFraudSpider

Purpose: Extract BIN lists, CVV dumps, and fraud complaints from carding shops and scam tracking sites.
Enhancement: Provides a fraud intelligence layer for financial investigations in ACE-T.
"""

class FinancialFraudSpider(scrapy.Spider):
    name = "financial_fraud"
    allowed_domains = ["cardingforum.com", "scamtrackersite.com"]
    start_urls = [
        "https://cardingforum.com/bin-lists",
        "https://scamtrackersite.com/complaints"
    ]

    def parse(self, response):
        for post in response.css('div.post, li.complaint, div.bin'):
            item = AceTScraperItem()
            item['title'] = post.css('a::text').get()
            post_href = post.css('a::attr(href)').get()
            if post_href:
                item['url'] = response.urljoin(post_href)
                item['source'] = response.urljoin(post_href)
            else:
                item['url'] = response.url
                item['source'] = response.url
            item['author'] = post.css('.author::text').get()
            item['published_date'] = post.css('.date::text').get()
            item['content'] = post.css('.content::text').get()
            item['tags'] = ["fraud", "carding"]
            item['crawled_at'] = datetime.utcnow().isoformat()
            item['error'] = None
            yield item
