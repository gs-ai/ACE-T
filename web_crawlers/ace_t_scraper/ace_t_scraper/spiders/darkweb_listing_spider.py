import scrapy
from ..items import AceTScraperItem
from datetime import datetime

"""
DarkWebListingSpider

Purpose: Scrape darknet marketplaces and forums for leaked data listings and zero-day sales (requires Tor proxy).
Enhancement: Adds underground economy insight and breach attribution to ACE-T.
"""

class DarkWebListingSpider(scrapy.Spider):
    name = "darkweb_listing"
    custom_settings = {
        'HTTPPROXY_ENABLED': True,
        'HTTPPROXY_PROXY': 'http://127.0.0.1:8118',  # Example: Privoxy
    }
    allowed_domains = ["onionmarketplace.onion"]
    start_urls = ["http://onionmarketplace.onion/listings"]

    def parse(self, response):
        for listing in response.css('div.listing'):
            item = AceTScraperItem()
            item['title'] = listing.css('h2::text').get()
            listing_href = listing.css('a::attr(href)').get()
            if listing_href:
                item['url'] = response.urljoin(listing_href)
                item['source'] = response.urljoin(listing_href)
            else:
                item['url'] = response.url
                item['source'] = response.url
            item['author'] = listing.css('.vendor::text').get()
            item['published_date'] = listing.css('.date::text').get()
            item['content'] = listing.css('.description::text').get()
            item['tags'] = ["darkweb", "listing"]
            item['crawled_at'] = datetime.utcnow().isoformat()
            item['error'] = None
            yield item
