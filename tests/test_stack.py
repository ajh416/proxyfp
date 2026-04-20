import httpx
import pytest
import respx

from proxyfp.detectors import stack


@pytest.mark.asyncio
@respx.mock
async def test_uniub_manifest_match():
    respx.get("https://example.test/manifest.json").respond(
        200, json={"short_name": "UniUB v4", "name": "UniUB v4"}
    )
    async with httpx.AsyncClient() as client:
        result = await stack.probe("https://example.test", client)
    assert result.signal == "uniub_manifest"
    assert result.weight >= 0.9


@pytest.mark.asyncio
@respx.mock
async def test_no_stack_when_nothing_matches():
    # Every path 404s.
    respx.get(url__regex=r"https://example\.test/.*").respond(404)
    async with httpx.AsyncClient() as client:
        result = await stack.probe("https://example.test", client)
    assert result.signal == "no_stack_match"
    assert result.weight == 0.0
