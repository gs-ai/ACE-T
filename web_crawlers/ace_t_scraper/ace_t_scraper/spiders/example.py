import scrapy
from ..items import AceTScraperItem

class ExampleSpider(scrapy.Spider):
    name = "example"
    allowed_domains = ["example.com"]
    start_urls = ["https://example.com"]

    def parse(self, response):
        for article in response.css('div.article'):
            item = AceTScraperItem()
            item['title'] = article.css('h2.title::text').get()
            item['url'] = article.css('a::attr(href)').get()
            yield item

        # Follow pagination links
        next_page = response.css('a.next::attr(href)').get()
        if next_page:
            yield response.follow(next_page, self.parse)
