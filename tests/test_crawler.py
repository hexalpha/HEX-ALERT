import pytest
from collectors.crawler import CrawlerManager
from collectors.base import validate_public_url


def test_article_extraction_removes_navigation_and_keeps_links():
    page=CrawlerManager._extract("<html><head><title>Advisory</title></head><body><nav>Menus</nav><main><h1>Patch released</h1><article><p>Critical fix.</p><a href='/patch'>Patch notes</a></article></main><footer>Footer</footer></body></html>","https://example.org/advisory",{})
    assert page["title"]=="Patch released"
    assert "Critical fix." in page["summary"]
    assert "Menus" not in page["summary"] and "Footer" not in page["summary"]
    assert page["links"]==["/patch"]


@pytest.mark.parametrize("url",["file:///etc/passwd","ftp://example.org/file","http://127.0.0.1/","http://169.254.169.254/latest/meta-data/","http://[::1]/","http://service.local/"])
def test_crawler_rejects_unsafe_schemes_and_local_addresses(url):
    with pytest.raises(ValueError):validate_public_url(url)
