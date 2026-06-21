from __future__ import annotations

from strix.modules.dorking import DorkingModule


async def test_dorking_builds_search_urls():
    result = await DorkingModule().run("example.com")

    assert result.error is None
    assert len(result.findings) >= 5

    for finding in result.findings:
        assert finding.source == "dorking"
        assert "example.com" in finding.value
        # Primary URL is a Google search; alternates live in metadata.
        assert finding.url and finding.url.startswith("https://www.google.com/search?q=")
        assert "bing" in finding.metadata
        assert "duckduckgo" in finding.metadata

    titles = {f.title for f in result.findings}
    assert "Indexed pages" in titles
