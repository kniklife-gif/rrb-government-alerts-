"""Regression tests for RRB discovery, identity checks, and parsing."""
from rrb import Board, CENTRAL_HOST, _headline_like, discover_boards, confirm_board_identity, parse_generic_html_notices

HOME = f"https://{CENTRAL_HOST}/"


def _home_html(hrefs):
    links = "".join(f'<a href="{href}">{text}</a>' for href, text in hrefs)
    return f"<html><body><div class='grid'><table><tr><td>{links}</td></tr></table></div></body></html>"


def _board():
    return Board("ahmedabad", "Ahmedabad", f"https://{CENTRAL_HOST}/ahmedabad", "/ahmedabad", "Ahmedabad", "unified_portal_url_subdirectory")


def test_headline_like_accepts_short_city_names():
    for name in ("Ahmedabad", "Ajmer", "Secunderabad", "Thiruvananthapuram", "Mumbai"):
        assert _headline_like(name) is False


def test_headline_like_rejects_headlines():
    assert _headline_like("CEN 05/2025 Result declared") is True
    assert _headline_like("one two three four five six seven") is True


def test_discover_city_name_only_anchor_text():
    html = _home_html([(f"/{name.lower()}", name) for name in ("Ahmedabad", "Ajmer", "Secunderabad", "Mumbai")])
    boards, diag = discover_boards(html, HOME)
    assert f"https://{CENTRAL_HOST}/ahmedabad" in {b.url for b in boards}
    assert any(c["method"] == "unified_portal_url_subdirectory" for c in diag["candidates"])


def test_discover_excludes_non_board_slugs():
    html = _home_html([(f"/{name}", name.title()) for name in ("about", "contact", "login", "ahmedabad", "ajmer", "mumbai")])
    boards, _ = discover_boards(html, HOME)
    urls = {b.url for b in boards}
    assert all(f"https://{CENTRAL_HOST}/{slug}" not in urls for slug in ("about", "contact", "login"))


def test_discover_ignores_assets_and_documents():
    html = _home_html([("/static/app.js", "app.js"), ("/files/notice.pdf", "notice.pdf"), ("/ahmedabad", "Ahmedabad"), ("/ajmer", "Ajmer"), ("/mumbai", "Mumbai")])
    boards, _ = discover_boards(html, HOME)
    assert not any(url.endswith((".js", ".pdf")) for url in (b.url for b in boards))


def test_identity_confirmed_when_rrb_phrase_and_city_in_title():
    html = "<html><head><title>Ahmedabad | Railway Recruitment Board</title></head><body><h1>Ahmedabad</h1></body></html>"
    assert confirm_board_identity(html, _board())["status"] == "confirmed"


def test_identity_unconfirmed_without_rrb_phrase():
    html = "<html><head><title>Ahmedabad</title></head><body><h1>Ahmedabad</h1></body></html>"
    assert confirm_board_identity(html, _board())["status"].startswith("unconfirmed")


def test_parser_finds_pdf_notice_links():
    html = "<html><body><div class='notice-board'><ul><li><a href='/docs/cen-05-2025-notice.pdf'>CEN 05/2025 - Notice</a> 01/09/2025</li><li><a href='/docs/admit-card.pdf'>Admit Card Download</a> 15/09/2025</li></ul></div></body></html>"
    out = parse_generic_html_notices(html, _board().url, _board())
    assert out.ok
    assert len(out.notices) >= 2


def test_parser_finds_html_notice_links_in_fallback():
    html = "<html><body><table><tr><td><a href='/notice/cen-05-2025'>CEN 05/2025 Detailed Notice</a></td><td>01/09/2025</td></tr><tr><td><a href='/result/cen-04-2025'>CEN 04/2025 Result</a></td><td>20/09/2025</td></tr></table></body></html>"
    out = parse_generic_html_notices(html, _board().url, _board())
    assert out.ok, out.status
    urls = {n.notice_url for n in out.notices}
    assert any("/notice/" in url for url in urls)
    assert any("/result/" in url for url in urls)


def test_parser_does_not_pick_chrome_links():
    html = "<html><body><nav><a href='/notice/nav-should-be-skipped'>Nav</a></nav><div class='notice-board'><a href='/notice/real-notice'>Real Notice</a> 01/09/2025</div></body></html>"
    out = parse_generic_html_notices(html, _board().url, _board())
    urls = {n.notice_url for n in out.notices}
    assert any("real-notice" in url for url in urls)
    assert not any("nav-should-be-skipped" in url for url in urls)


# ---- offline resilience / safety regression tests (no network) ----
import json
import socket
import ssl
from pathlib import Path
import tempfile

import requests

import rrb
from rrb import Fetcher, classify_exception, collect, load_boards_file, main


class _Resp:
    def __init__(self, url, status=200, body=b"", headers=None):
        self.url, self.status_code, self._body = url, status, body
        self.headers = {"Content-Type": "text/html; charset=utf-8", **(headers or {})}
        self.encoding = "utf-8"

    def iter_content(self, n):
        yield self._body

    def close(self):
        pass


class _Session:
    """Scripted session: maps url -> Response or Exception. Records calls; never touches the network."""
    def __init__(self, script):
        self.script, self.calls, self.headers = script, [], {}

    def get(self, url, **kw):
        self.calls.append((url, kw))
        item = self.script[url]
        if isinstance(item, list):
            item = item.pop(0)
        if isinstance(item, BaseException):
            raise item
        return item


def _fetcher(script, **kw):
    return Fetcher(session=_Session(script), delay=0, sleep=lambda s: None, respect_robots=False, **kw)


def _wrapped(outer, inner):
    """Mimic requests/urllib3 chaining: the low-level error is the __cause__ of the requests exception."""
    outer.__cause__ = inner
    return outer


def _dns_error():
    return _wrapped(requests.exceptions.ConnectionError("Failed to resolve host"), socket.gaierror(-2, "Name or service not known"))


def _raises_kind(exc, kind):
    return classify_exception(exc) == kind


def test_classify_exception_kinds():
    assert _raises_kind(_dns_error(), "dns_failure")
    assert _raises_kind(_wrapped(requests.exceptions.SSLError("tls"), ssl.SSLCertVerificationError("bad cert")), "tls_error")
    assert _raises_kind(requests.exceptions.ConnectTimeout("t"), "connect_timeout")
    assert _raises_kind(requests.exceptions.ReadTimeout("t"), "read_timeout")
    assert _raises_kind(requests.exceptions.TooManyRedirects("r"), "too_many_redirects")
    assert _raises_kind(_wrapped(requests.exceptions.ConnectionError("refused"), ConnectionRefusedError()), "connection_refused")


def test_fetch_tls_error_is_reported_and_retried_not_swallowed():
    sess_err = _wrapped(requests.exceptions.SSLError("tls"), ssl.SSLCertVerificationError("certificate verify failed"))
    f = _fetcher({HOME: [sess_err, sess_err]})
    r = f.get(HOME)
    assert r.error_kind == "tls_error" and r.access_status == "exception" and r.attempts == 2 and r.text == ""


def test_fetch_never_disables_tls_verification():
    f = _fetcher({HOME: _Resp(HOME, body=b"<html>ok</html>")})
    f.get(HOME)
    assert all(kw.get("verify", True) is True for _, kw in f.session.calls)
    assert "verify=False" not in Path(rrb.__file__).read_text(encoding="utf-8").replace(" ", "")


def test_fetch_http_errors_and_5xx_retry():
    f = _fetcher({HOME: _Resp(HOME, 404, b"nf")})
    r = f.get(HOME)
    assert r.access_status == "http_error" and r.status == 404 and r.attempts == 1
    f = _fetcher({HOME: [_Resp(HOME, 503, b"x"), _Resp(HOME, 200, b"<html>ok</html>")]})
    r = f.get(HOME)
    assert r.access_status == "ok" and r.attempts == 2


def test_fetch_follows_official_redirect_and_records_chain():
    dest = f"https://{CENTRAL_HOST}/home"
    f = _fetcher({HOME: _Resp(HOME, 301, headers={"Location": "/home"}), dest: _Resp(dest, 200, b"<html>hi</html>")})
    r = f.get(HOME)
    assert r.access_status == "ok" and r.final_url == dest and r.redirect_chain[0]["status"] == 301


def test_fetch_blocks_off_domain_and_downgrade_redirects():
    f = _fetcher({HOME: _Resp(HOME, 302, headers={"Location": "https://evil.example.com/x"})})
    r = f.get(HOME)
    assert r.error_kind == "redirect_blocked" and r.access_status == "exception" and r.attempts == 1
    f = _fetcher({HOME: _Resp(HOME, 302, headers={"Location": f"http://{CENTRAL_HOST}/x"})})
    assert f.get(HOME).error_kind == "redirect_blocked"


def test_fetch_redirect_loop_is_bounded():
    f = _fetcher({HOME: _Resp(HOME, 302, headers={"Location": HOME})})
    assert f.get(HOME).error_kind == "too_many_redirects"


def test_empty_body_and_challenge_page_are_not_ok():
    assert _fetcher({HOME: _Resp(HOME, 200, b"")}).get(HOME).access_status == "empty_body"
    assert _fetcher({HOME: _Resp(HOME, 200, b"<html>Access Denied</html>")}).get(HOME).access_status == "challenge_or_denied_page"


def test_collect_on_dns_failure_emits_no_notices():
    dns = _dns_error()
    rep = collect(_fetcher({HOME: [dns, dns]}))
    assert rep["overall_status"] == "TOTAL_FAILURE" and rep["homepage"]["error_kind"] == "dns_failure"
    assert rep["notices"] == [] and rep["summary"]["notices_total"] == 0 and rep["production_ready"] is False


def test_collect_homepage_redirect_off_gov_in_is_not_crawled():
    f = _fetcher({HOME: _Resp(HOME, 302, headers={"Location": "https://example.com/"})})
    rep = collect(f)
    assert rep["overall_status"] == "TOTAL_FAILURE" and rep["boards"] == [] and rep["notices"] == []


def test_collect_board_fetch_failure_yields_no_notices():
    html = _home_html([(f"/{n}", n.title()) for n in ("ahmedabad", "ajmer", "mumbai")])
    dns = _dns_error()
    script = {HOME: _Resp(HOME, 200, html.encode())}
    for n in ("ahmedabad", "ajmer", "mumbai"):
        script[f"https://{CENTRAL_HOST}/{n}"] = [dns, dns]
    rep = collect(_fetcher(script))
    assert rep["boards"] and all(b["notice_count"] == 0 and b["parse_status"] == "not_run_access_failed" for b in rep["boards"])
    assert rep["notices"] == [] and rep["overall_status"] == "TOTAL_FAILURE"


def test_main_writes_json_report_and_exit_code_2_on_network_failure():
    dns = _dns_error()
    orig = rrb.Fetcher._new_session
    rrb.Fetcher._new_session = staticmethod(lambda: _Session({HOME: [dns, dns], f"https://{CENTRAL_HOST}/robots.txt": dns}))
    orig_sleep = rrb.time.sleep
    rrb.time.sleep = lambda s: None
    try:
        with tempfile.TemporaryDirectory() as d:
            out = Path(d) / "r.json"
            assert main(["--out", str(out)]) == 2
            data = json.loads(out.read_text(encoding="utf-8"))
    finally:
        rrb.Fetcher._new_session = orig
        rrb.time.sleep = orig_sleep
    assert data["overall_status"] == "TOTAL_FAILURE" and data["homepage"]["error_kind"] == "dns_failure" and data["notices"] == []


def test_boards_file_rejects_non_official_or_unevidenced_urls():
    def load(items):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "b.json"
            p.write_text(json.dumps(items), encoding="utf-8")
            try:
                return load_boards_file(str(p))
            except ValueError as e:
                return e
    ok = {"url": "https://rrbahmedabad.gov.in/", "name": "Ahmedabad", "evidence": "linked from homepage"}
    assert isinstance(load([ok]), list)
    assert isinstance(load([{**ok, "url": "https://rrbahmedabad.com/"}]), ValueError)
    assert isinstance(load([{**ok, "url": "http://rrbahmedabad.gov.in/"}]), ValueError)
    assert isinstance(load([{**ok, "url": "https://gov.in.evil.com/"}]), ValueError)
    assert isinstance(load([{**ok, "evidence": ""}]), ValueError)
    assert isinstance(load({"not": "a list"}), ValueError)


def test_discover_ignores_off_host_links():
    html = _home_html([("https://evil.example.com/ahmedabad", "Ahmedabad"), ("/ajmer", "Ajmer"), ("/mumbai", "Mumbai"), ("/pune", "Pune")])
    boards, _ = discover_boards(html, HOME)
    assert all(urlparse_host(b.url) == CENTRAL_HOST for b in boards)


def urlparse_host(u):
    from urllib.parse import urlparse
    return urlparse(u).hostname


def test_parser_handles_malformed_and_empty_html_without_crashing():
    for html in ("", "<html><body><div class='notice-board'><a href='/docs/x.pdf'>Unclosed <b>tag", "<<<>>>", "\x00\x01 binary-ish"):
        out = parse_generic_html_notices(html, _board().url, _board())
        assert out.notices == [] or all(n.title and n.notice_url for n in out.notices)


def test_parser_missing_date_still_has_title_and_official_url_and_no_fake_date():
    html = "<html><body><div class='notice-board'><a href='/docs/cen-05-2025-notice.pdf'>CEN 05/2025 Notice</a></div></body></html>"
    out = parse_generic_html_notices(html, _board().url, _board())
    assert out.notices
    n = out.notices[0]
    assert n.title and n.notice_url.startswith(f"https://{CENTRAL_HOST}/")
    assert not getattr(n, "published_date", None), "date must stay empty when the page shows none"


def test_parser_dedupes_duplicate_notice_links():
    a = "<li><a href='/docs/cen-05-2025-notice.pdf'>CEN 05/2025 - Notice</a> 01/09/2025</li>"
    html = f"<html><body><div class='notice-board'><ul>{a}{a}</ul></div></body></html>"
    out = parse_generic_html_notices(html, _board().url, _board())
    urls = [n.notice_url for n in out.notices]
    assert len(urls) == len(set(urls)) == 1
