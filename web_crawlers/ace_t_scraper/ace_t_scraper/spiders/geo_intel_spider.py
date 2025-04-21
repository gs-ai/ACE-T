import scrapy
from ..items import AceTScraperItem
from datetime import datetime

"""
GeoIntelSpider

Purpose: Track military movement, satellite imagery analysis, and regional flashpoints from OSINT/geopolitical sources.
Enhancement: Provides high-fidelity geopolitical forecasting and verification for ACE-T.
"""

class GeoIntelSpider(scrapy.Spider):
    name = "geo_intel"
    allowed_domains = ["liveuamap.com", "janes.com", "bellingcat.com"]
    start_urls = [
        "https://liveuamap.com/",
        "https://www.janes.com/defence-news",
        "https://www.bellingcat.com/category/news/"
    ]

    def parse(self, response):
        for post in response.css('article, div.news-item, li.news'):
            item = AceTScraperItem()
            item['title'] = post.css('a::text, h2::text').get()
            post_href = post.css('a::attr(href)').get()
            if post_href:
                item['url'] = response.urljoin(post_href)
                item['source'] = response.urljoin(post_href)
            else:
                item['url'] = response.url
                item['source'] = response.url
            item['author'] = post.css('.author::text').get()
            item['published_date'] = post.css('time::attr(datetime)').get()
            item['content'] = post.css('p::text').get()
            item['tags'] = ["geo", "intel"]
            item['crawled_at'] = datetime.utcnow().isoformat()
            item['error'] = None
            yield item
