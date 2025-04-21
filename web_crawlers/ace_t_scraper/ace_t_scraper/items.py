"""
Defines the data models (items) for ACE-T Scrapy spiders.
Each field represents a piece of data to be extracted from crawled sources.
"""
import scrapy
from typing import Optional, List

class AceTScraperItem(scrapy.Item):
    """
    Data container for scraped content.
    Fields are extensible for robust, future-proof scraping.
    """
    title: Optional[str] = scrapy.Field()
    url: Optional[str] = scrapy.Field()
    author: Optional[str] = scrapy.Field()
    published_date: Optional[str] = scrapy.Field()
    content: Optional[str] = scrapy.Field()
    tags: Optional[List[str]] = scrapy.Field()
    source: Optional[str] = scrapy.Field()
    crawled_at: Optional[str] = scrapy.Field()
    error: Optional[str] = scrapy.Field()  # For error reporting or fallback
