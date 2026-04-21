import httpx
import pytest
import respx

from proxyfp.detectors import service_worker as sw


LANDING_WITH_SW = """
<!doctype html>
<html><head><title>x</title></head>
<body>
<script>
navigator.serviceWorker.register('/worker.js', {scope: '/'})
  .then(function (reg) { console.log('ok'); });
</script>
</body></html>
"""

LANDING_WITHOUT_SW = """
<!doctype html><html><body><h1>hi</h1></body></html>
"""


@pytest.mark.asyncio
@respx.mock
async def test_named_stack_ultraviolet():
    respx.get("https://t.test/").respond(200, text=LANDING_WITH_SW)
    respx.get("https://t.test/worker.js").respond(
        200, text="self.__uv$config = {}; var UVServiceWorker = function(){};"
    )
    async with httpx.AsyncClient() as client:
        result = await sw.probe("https://t.test/", client)
    assert result.signal == "sw_ultraviolet"
    assert result.weight == 0.9


@pytest.mark.asyncio
@respx.mock
async def test_named_stack_scramjet():
    respx.get("https://t.test/").respond(200, text=LANDING_WITH_SW)
    respx.get("https://t.test/worker.js").respond(
        200, text="class ScramjetServiceWorker {}; var __scramjet$config = {};"
    )
    async with httpx.AsyncClient() as client:
        result = await sw.probe("https://t.test/", client)
    assert result.signal == "sw_scramjet"
    assert result.weight == 0.9


@pytest.mark.asyncio
@respx.mock
async def test_generic_fetch_proxy_with_rewrite_hint():
    body = """
    self.addEventListener('fetch', function (event) {
      var u = new URL(atob(event.request.url.split('?')[1]));
      event.respondWith(fetch(u));
    });
    """
    respx.get("https://t.test/").respond(200, text=LANDING_WITH_SW)
    respx.get("https://t.test/worker.js").respond(200, text=body)
    async with httpx.AsyncClient() as client:
        result = await sw.probe("https://t.test/", client)
    assert result.signal == "sw_fetch_proxy_generic"
    assert result.weight == 0.75


@pytest.mark.asyncio
@respx.mock
async def test_plain_pwa_is_not_a_hit():
    body = """
    self.addEventListener('fetch', function (event) {
      event.respondWith(caches.match(event.request).then(r => r || fetch(event.request)));
    });
    """
    respx.get("https://t.test/").respond(200, text=LANDING_WITH_SW)
    respx.get("https://t.test/worker.js").respond(200, text=body)
    async with httpx.AsyncClient() as client:
        result = await sw.probe("https://t.test/", client)
    assert result.signal == "sw_no_proxy_signal"
    assert result.weight == 0.0


@pytest.mark.asyncio
@respx.mock
async def test_no_sw_register():
    respx.get("https://t.test/").respond(200, text=LANDING_WITHOUT_SW)
    async with httpx.AsyncClient() as client:
        result = await sw.probe("https://t.test/", client)
    assert result.signal == "no_sw_register"
    assert result.weight == 0.0
