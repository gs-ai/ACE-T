import scrapy
from ..items import AceTScraperItem
from datetime import datetime

class TwitterIntelSpider(scrapy.Spider):
    """
    TwitterIntelSpider

    Purpose: Collect tweets with specific hashtags or accounts tied to protests, hacks, political instability (via Nitter as a proxy).
    Enhancement: Real-time situational awareness and threat detection for ACE-T.
    """
    name = "twitter_intel"
    allowed_domains = ["twitter.com"]
    start_urls = [
        "https://nitter.net/search?f=tweets&q=%23protest+OR+%23hack+OR+%23cyberattack"
    ]

    def parse(self, response):
        for tweet in response.css('div.timeline-item'):
            item = AceTScraperItem()
            item['title'] = tweet.css('div.tweet-content::text').get()
            tweet_href = tweet.css('a::attr(href)').get()
            if tweet_href:
                item['url'] = response.urljoin(tweet_href)
                item['source'] = response.urljoin(tweet_href)
            else:
                item['url'] = response.url
                item['source'] = response.url
            item['author'] = tweet.css('a.username::text').get()
            item['published_date'] = tweet.css('span.tweet-date a::attr(title)').get()
            item['content'] = tweet.css('div.tweet-content::text').get()
            item['tags'] = ["twitter", "intel"]
            item['crawled_at'] = datetime.utcnow().isoformat()
            item['error'] = None
            yield item
