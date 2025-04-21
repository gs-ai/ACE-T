import scrapy
from ..items import AceTScraperItem
from datetime import datetime

class RedditSpider(scrapy.Spider):
    name = "reddit"
    allowed_domains = ["reddit.com"]
    start_urls = ["https://www.reddit.com/r/netsec/new/"]

    def parse(self, response):
        for post in response.css('div.Post'):
            item = AceTScraperItem()
            item['title'] = post.css('h3::text').get()
            post_href = post.css('a::attr(href)').get()
            if post_href:
                item['url'] = response.urljoin(post_href)
                item['source'] = response.urljoin(post_href)
            else:
                item['url'] = response.url
                item['source'] = response.url
            item['author'] = post.css('a[data-click-id="user"]::text').get()
            item['published_date'] = post.css('a[data-click-id="timestamp"]::attr(title)').get()
            item['content'] = post.css('div[data-click-id="text"]::text').get()
            item['tags'] = post.css('span[data-testid="flair"]::text').getall()
            item['crawled_at'] = datetime.utcnow().isoformat()
            item['error'] = None
            yield item
