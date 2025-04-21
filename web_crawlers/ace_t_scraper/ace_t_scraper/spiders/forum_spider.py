import scrapy
from ..items import AceTScraperItem
from datetime import datetime

class ForumSpider(scrapy.Spider):
    """
    ForumSpider

    Purpose: Monitor high-activity forums for conversations, sales, group formations, and exploits.
    Enhancement: Adds chatter-based early warning system to ACE-T.
    """
    name = "forum"
    allowed_domains = ["raidforums.com", "crackingforum.com"]
    start_urls = [
        "https://raidforums.com/Forum-Data-Breaches",
        "https://crackingforum.com/forums/announcements.1/"
    ]

    def parse(self, response):
        for thread in response.css('div.thread, li.thread, div.topic'):
            item = AceTScraperItem()
            item['title'] = thread.css('a::text').get()
            thread_href = thread.css('a::attr(href)').get()
            if thread_href:
                item['url'] = response.urljoin(thread_href)
                item['source'] = response.urljoin(thread_href)
            else:
                item['url'] = response.url
                item['source'] = response.url
            item['author'] = thread.css('.author::text').get()
            item['published_date'] = thread.css('.date::text').get()
            item['content'] = thread.css('.snippet::text').get()
            item['tags'] = ["forum", "chatter"]
            item['crawled_at'] = datetime.utcnow().isoformat()
            item['error'] = None
            yield item
