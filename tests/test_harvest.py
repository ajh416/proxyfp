from proxyfp.harvest import build_matcher, iter_hostnames


def test_matcher_requires_token_and_platform():
    m = build_matcher()
    assert m.match("my-unblocker-site.vercel.app")
    assert m.match("school-proxy-demo.pages.dev")
    assert m.match("ultraviolet-fork.onrender.com")


def test_matcher_rejects_token_only():
    m = build_matcher()
    assert not m.match("unblock.example.com")
    assert not m.match("proxy.someone.dev")


def test_matcher_rejects_platform_only():
    m = build_matcher()
    assert not m.match("my-portfolio.vercel.app")
    assert not m.match("blog.pages.dev")


def test_matcher_is_case_insensitive():
    m = build_matcher()
    assert m.match("MyUnblocker.Vercel.App".lower())


def test_iter_hostnames_extracts_and_normalizes():
    msg = {
        "message_type": "certificate_update",
        "data": {
            "leaf_cert": {
                "all_domains": ["*.proxy-demo.vercel.app", "proxy-demo.vercel.app"]
            }
        },
    }
    hosts = list(iter_hostnames(msg))
    assert hosts == ["proxy-demo.vercel.app", "proxy-demo.vercel.app"]


def test_iter_hostnames_ignores_non_cert_messages():
    assert list(iter_hostnames({"message_type": "heartbeat"})) == []
    assert list(iter_hostnames({})) == []
