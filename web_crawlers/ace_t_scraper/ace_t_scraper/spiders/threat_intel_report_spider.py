import scrapy
from ..items import AceTScraperItem
from datetime import datetime

"""
ThreatIntelReportSpider

Purpose: Extract IoCs, actor TTPs, and threat intelligence from PDF/HTML reports and vendor blogs.
Enhancement: Provides tactical feeds for signature or alert enrichment in ACE-T.
"""

class ThreatIntelReportSpider(scrapy.Spider):
    name = "threat_intel_report"
    allowed_domains = ["fireeye.com", "crowdstrike.com", "mandiant.com"]
    start_urls = [
        "https://www.fireeye.com/blog/threat-research.html",
        "https://www.crowdstrike.com/blog/category/threat-intel/",
        "https://www.mandiant.com/resources/blog"
    ]

    def parse(self, response):
        for post in response.css('article'):
            item = AceTScraperItem()
            item['title'] = post.css('h2 a::text').get()
            post_href = post.css('h2 a::attr(href)').get()
            if post_href:
                item['url'] = response.urljoin(post_href)
                item['source'] = response.urljoin(post_href)
            else:
                item['url'] = response.url
                item['source'] = response.url
            item['author'] = post.css('.author::text').get()
            item['published_date'] = post.css('time::attr(datetime)').get()
            item['content'] = post.css('div.entry-content p::text').get()
            item['tags'] = ["threatintel", "report"]
            item['crawled_at'] = datetime.utcnow().isoformat()
            item['error'] = None
            yield item
