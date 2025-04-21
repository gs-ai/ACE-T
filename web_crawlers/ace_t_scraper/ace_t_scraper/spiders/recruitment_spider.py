import scrapy
from ..items import AceTScraperItem
from datetime import datetime

class RecruitmentSpider(scrapy.Spider):
    """
    RecruitmentSpider

    Purpose: Track aggressive hiring trends in cyber warfare, HUMINT recruitment, and hacking group job boards.
    Enhancement: Strategic-level forecasting of emerging actors or capabilities for ACE-T.
    """
    name = "recruitment"
    allowed_domains = ["army.mil", "contractor.com", "hackerjobs.com"]
    start_urls = [
        "https://www.army.mil/jobs/",
        "https://www.contractor.com/cyber-jobs/",
        "https://www.hackerjobs.com/"
    ]

    def parse(self, response):
        for job in response.css('div.job-listing, li.job, div.listing'):
            item = AceTScraperItem()
            item['title'] = job.css('a::text').get()
            job_href = job.css('a::attr(href)').get()
            if job_href:
                item['url'] = response.urljoin(job_href)
                item['source'] = response.urljoin(job_href)
            else:
                item['url'] = response.url
                item['source'] = response.url
            item['author'] = job.css('.company::text').get()
            item['published_date'] = job.css('.date::text').get()
            item['content'] = job.css('.description::text').get()
            item['tags'] = ["recruitment", "cyberwarfare"]
            item['crawled_at'] = datetime.utcnow().isoformat()
            item['error'] = None
            yield item
