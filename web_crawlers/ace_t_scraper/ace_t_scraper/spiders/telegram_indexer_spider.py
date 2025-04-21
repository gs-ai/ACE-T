import scrapy
from ..items import AceTScraperItem
from datetime import datetime

"""
TelegramIndexerSpider

Purpose: Extract posts, file drops, propaganda, and group movements from public Telegram channels.
Enhancement: Improves visibility into encrypted chatter and disinformation for ACE-T.
"""

class TelegramIndexerSpider(scrapy.Spider):
    name = "telegram_indexer"
    allowed_domains = ["t.me"]
    start_urls = [
        "https://t.me/s/example_channel"
    ]

    def parse(self, response):
        for post in response.css('div.tgme_widget_message_wrap'):
            item = AceTScraperItem()
            item['title'] = post.css('div.tgme_widget_message_text::text').get()
            post_href = post.css('a.tgme_widget_message_from_author::attr(href)').get()
            if post_href:
                item['url'] = response.urljoin(post_href)
                item['source'] = response.urljoin(post_href)
            else:
                item['url'] = response.url
                item['source'] = response.url
            item['author'] = post.css('a.tgme_widget_message_from_author::text').get()
            item['published_date'] = post.css('time::attr(datetime)').get()
            item['content'] = post.css('div.tgme_widget_message_text::text').get()
            item['tags'] = ["telegram", "index"]
            item['crawled_at'] = datetime.utcnow().isoformat()
            item['error'] = None
            yield item
