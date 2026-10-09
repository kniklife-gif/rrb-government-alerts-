"""Read-only collector for Railway Recruitment Board notice pages.

The discovery heuristics and generic parser are intentionally marked unverified
until checked against live official portal responses. No notices are fabricated.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import socket
import ssl
import time
import unicodedata
from dataclasses import asdict, dataclass, field
from datetime import date, datetime, timezone
from pathlib import Path
from urllib import robotparser
from urllib.parse import quote, urldefrag, urljoin, urlparse

import requests
from bs4 import BeautifulSoup

MODULE_VERSION = "0.7-unverified"
HOME_URL = "https://rrb.indianrailways.gov.in/"
CENTRAL_HOST = "rrb.indianrailways.gov.in"
USER_AGENT = "rrb-notice-collector/0.1 (read-only; respects robots.txt)"
TIMEOUT = (10, 25)
MAX_BODY = 2 * 1024 * 1024
DELAY_SECONDS = 1.5
MAX_BOARDS = 40
MAX_REDIRECTS = 5
REDIRECT_CODES = (301, 302, 303, 307, 308)
DOC_EXT = (".pdf", ".doc", ".docx", ".xls", ".xlsx", ".zip", ".rar", ".ppt", ".pptx")
STATIC_EXT = (".css", ".js", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".woff", ".woff2")
DENIED_MARKERS = ("access denied", "request blocked", "captcha", "are you a robot", "unusual traffic", "403 forbidden", "attention required", "you have been blocked")
NON_BOARD_SLUGS = {"about", "about-us", "contact", "contact-us", "login", "register", "home", "index", "sitemap", "help", "faq", "privacy", "terms", "disclaimer", "downloads", "download", "notices", "results", "admit-card", "answer-key", "gallery", "media", "news", "press", "tenders", "rti", "acts", "rules", "policies", "recruitment", "central", "cen", "rrb", "en", "hi", "english", "hindi", "css", "js", "images", "img", "assets", "static", "uploads"}
BOARD_LABEL = re.compile(r"\b(rrb|railway\s+recruitment\s+board)\b", re.I)
BOARD_CONTEXT = re.compile(r"region|zone|board|rrb", re.I)
NOTICE_CLASS = re.compile(r"notice|notif|news|recruit|circular|announce|result|ticker|marquee|latest|(?:^|[\s_\-.#])cen(?:$|[\s_\-.#])", re.I)
CHROME_CLASS = re.compile(r"navbar|nav-|menu|breadcrumb|footer|header|social|sidebar-menu", re.I)
GENERIC_LABELS = {"click here", "download", "view", "pdf", "read more", "more", "details", "here", "link"}
PAG_TEXT = re.compile(r"^(next|prev|previous|first|last|»|«|›|‹|>>|<<|>|<|\d{1,3})$", re.I)
EMPTY_PHRASES = ("no record", "no data", "no notice", "nothing to display", "no result found")
JS_MARKERS = ("ng-app", "ng-version", 'id="root"', 'id="app"', "__NEXT_DATA__", "data-reactroot", "enable javascript", "requires javascript")
CATEGORY_HINTS = [("cen", re.compile(r"\bcen\b|centrali[sz]ed employment", re.I)), ("corrigendum", re.compile(r"corrigend|amendment|addendum", re.I)), ("admit_card", re.compile(r"admit card|e-?call letter|call letter", re.I)), ("answer_key", re.compile(r"answer key|response sheet", re.I)), ("result", re.compile(r"\bresults?\b|scorecard|merit list", re.I)), ("exam_schedule", re.compile(r"exam (date|schedule|city)|city intimation|schedule", re.I)), ("document_verification", re.compile(r"document verification|\bdv\b", re.I)), ("application", re.compile(r"apply|application|registration", re.I))]
MONTHS = {**{m[:3]: i for i, m in enumerate(("january", "february", "march", "april", "may", "june", "july", "august", "september", "october", "november", "december"), 1)}, **{m: i for i, m in enumerate(("january", "february", "march", "april", "may", "june", "july", "august", "september", "october", "november", "december"), 1)}, "sept": 9}
BOARD_PARSER: dict[str, str] = {}
VERIFIED_ADAPTERS: set[str] = set()
NOTICE_PATH_HINT = re.compile(r"/(notice|notification|circular|announcement|cen|result|admit|answer|corrigendum|tender)(/|$|\?|#)", re.I)


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


@dataclass
class Notice:
    board_id: str
    board_name: str
    source_url: str
    title: str
    notice_url: str
    pdf_url: str | None = None
    published_date: str | None = None
    notice_id: str | None = None
    first_seen_at: str | None = None
    content_hash: str = ""
    shared_hash: str = ""
    category_hint: str | None = None
    retrieval_status: str = "unknown"
    parsing_notes: list = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class Board:
    board_id: str
    name: str
    url: str
    href: str
    link_text: str
    discovery_method: str
    duplicate_hrefs: list = field(default_factory=list)
    notes: list = field(default_factory=list)
    cluster: int | None = None
    discovery_status: str = "candidate_unverified"


@dataclass
class FetchResult:
    requested_url: str
    final_url: str | None = None
    status: int | None = None
    content_type: str | None = None
    text: str = ""
    size_bytes: int = 0
    elapsed_s: float | None = None
    exception: str | None = None
    redirect_chain: list = field(default_factory=list)
    truncated: bool = False
    attempts: int = 0
    access_status: str = "not_tested"
    method: str = "http_get"
    error_kind: str | None = None
    headers: dict = field(default_factory=dict)


def has_ext(url: str, exts: tuple) -> bool:
    p = urlparse(url)
    return p.path.lower().endswith(exts) or any(re.search(re.escape(e) + r"(?:$|[&#;])", p.query.lower()) for e in exts)


def encode_url(url: str) -> str:
    return quote(url, safe="%/:?&=#+,;@!$'()*[]~-._")


def document_base(soup, page_url: str) -> str:
    tag = soup.find("base", href=True)
    return urljoin(page_url, tag["href"].strip()) if tag else page_url


def norm_url(url: str) -> str:
    p = urlparse(urldefrag(encode_url(url.strip()))[0])
    path = p.path.rstrip("/") or ""
    return f"{p.scheme.lower()}://{(p.netloc or '').lower()}{path}" + (f"?{p.query}" if p.query else "")


def norm_title(title: str) -> str:
    return " ".join(unicodedata.normalize("NFKC", title).casefold().split())


def sha(*parts: str) -> str:
    return hashlib.sha256("\n".join(parts).encode("utf-8")).hexdigest()


def describe(el) -> str:
    cls = el.get("class") or []
    if isinstance(cls, str):
        cls = cls.split()
    return (el.name or "") + (f"#{el['id']}" if el.get("id") else "") + ("." + ".".join(cls) if cls else "")


def clean(s: str) -> str:
    return " ".join((s or "").split())


def slugify(s: str) -> str:
    ascii_s = unicodedata.normalize("NFKD", s).encode("ascii", "ignore").decode().lower()
    return re.sub(r"[^a-z0-9]+", "-", ascii_s).strip("-")


def parse_date(text: str) -> tuple[str | None, str | None]:
    m = re.search(r"\b(\d{4})-(\d{2})-(\d{2})\b", text)
    if m:
        try: return date(*map(int, m.groups())).isoformat(), None
        except ValueError: return None, f"ISO date {m.group(0)!r} invalid"
    m = re.search(r"\b(\d{1,2})[./-](\d{1,2})[./-](\d{4})\b", text)
    if m:
        d, mo, y = map(int, m.groups())
        try: return date(y, mo, d).isoformat(), "numeric date read day-first (assumption)" if d <= 12 else None
        except ValueError: return None, f"numeric date {m.group(0)!r} invalid under day-first reading"
    m = re.search(r"\b(\d{1,2})(?:st|nd|rd|th)?[\s-]+([A-Za-z]{3,9})\.?,?[\s-]+(\d{4})\b", text)
    if m and m.group(2).lower() in MONTHS:
        try: return date(int(m.group(3)), MONTHS[m.group(2).lower()], int(m.group(1))).isoformat(), None
        except ValueError: return None, f"date {m.group(0)!r} invalid"
    m = re.search(r"\b([A-Za-z]{3,9})\.?\s+(\d{1,2})(?:st|nd|rd|th)?,?\s+(\d{4})\b", text)
    if m and m.group(1).lower() in MONTHS:
        try: return date(int(m.group(3)), MONTHS[m.group(1).lower()], int(m.group(2))).isoformat(), None
        except ValueError: return None, f"date {m.group(0)!r} invalid"
    return None, None


def classify_exception(exc: BaseException) -> str:
    chain, seen = [], set()
    stack = [exc]
    while stack and len(chain) < 12:
        e = stack.pop(0)
        if e is None or id(e) in seen: continue
        seen.add(id(e)); chain.append(e)
        stack += [e.__cause__, e.__context__, getattr(e, "reason", None)]
    has = lambda *types: any(isinstance(e, types) for e in chain)
    names = {type(e).__name__ for e in chain}
    if has(socket.gaierror): return "dns_failure"
    if has(requests.exceptions.SSLError, ssl.SSLError, ssl.CertificateError): return "tls_error"
    if has(requests.exceptions.ConnectTimeout) or "ConnectTimeoutError" in names: return "connect_timeout"
    if has(requests.exceptions.ReadTimeout) or "ReadTimeoutError" in names: return "read_timeout"
    if has(requests.exceptions.TooManyRedirects): return "too_many_redirects"
    if has(ConnectionRefusedError): return "connection_refused"
    if has(ConnectionResetError, ConnectionAbortedError, BrokenPipeError) or names & {"RemoteDisconnected", "ProtocolError"}: return "connection_reset_or_closed"
    if has(requests.exceptions.ConnectionError): return "connection_error_other"
    if has(requests.exceptions.Timeout, socket.timeout, TimeoutError): return "timeout_other"
    return "other"


def classify_access(r: FetchResult) -> str:
    if r.exception or r.status is None: return "exception"
    if not 200 <= r.status < 300: return "http_error"
    if r.size_bytes == 0: return "empty_body"
    if r.size_bytes < 30000 and any(m in r.text.lower() for m in DENIED_MARKERS): return "challenge_or_denied_page"
    return "ok"


class Fetcher:
    """Sequential HTTP fetcher with robots.txt checks, bounded bodies and safe redirects."""
    def __init__(self, session=None, delay: float = DELAY_SECONDS, retries: int = 1, respect_robots: bool = True, sleep=time.sleep, timeout=TIMEOUT, restrict_redirects: bool = True):
        self.session = session or self._new_session()
        self.delay, self.retries, self.respect_robots, self.sleep = delay, retries, respect_robots, sleep
        self.timeout, self.restrict_redirects = timeout, restrict_redirects
        self._robots, self.robots_info = {}, {}
        self._requested_before = False

    @staticmethod
    def _new_session():
        s = requests.Session()
        s.headers.update({"User-Agent": USER_AGENT, "Accept": "text/html,application/xhtml+xml,*/*;q=0.8"})
        return s

    def allowed(self, url: str) -> bool:
        if not self.respect_robots: return True
        p = urlparse(url); origin = f"{p.scheme}://{p.netloc}"
        if origin not in self._robots:
            rp = None
            info = {"url": origin + "/robots.txt", "http_status": None, "error_kind": None, "exception": None}
            t0 = time.monotonic()
            try:
                r = self.session.get(origin + "/robots.txt", timeout=self.timeout, allow_redirects=True)
                info["http_status"] = r.status_code
                if r.status_code >= 500: rp = False
                elif r.status_code == 200 and r.text:
                    rp = robotparser.RobotFileParser(); rp.parse(r.text.splitlines())
            except Exception as exc:
                info["error_kind"] = classify_exception(exc); info["exception"] = f"{type(exc).__name__}: {exc}"[:300]
            info["elapsed_s"] = round(time.monotonic() - t0, 3)
            info["effect"] = "unreachable_5xx_assumed_disallow_all" if rp is False else "rules_loaded" if rp else "treated_as_allow_all"
            self.robots_info[origin], self._robots[origin] = info, rp
        rp = self._robots[origin]
        if rp is False: return False
        return True if rp is None else rp.can_fetch(USER_AGENT, url)

    def _redirect_violation(self, cur: str, nxt: str) -> str | None:
        a, b = urlparse(cur), urlparse(nxt)
        if b.scheme not in ("http", "https"): return f"non-http(s) scheme {b.scheme!r}"
        if a.scheme == "https" and b.scheme == "http": return "https -> http downgrade"
        if self.restrict_redirects and not (b.hostname or "").lower().endswith(".gov.in"):
            return f"target {b.hostname!r} is outside the official *.gov.in domain"
        if not self.allowed(nxt): return "robots.txt of the redirect target disallows it"
        return None

    def _open(self, url: str, res: FetchResult):
        cur, chain = url, []
        for hop in range(MAX_REDIRECTS + 1):
            resp = self.session.get(cur, timeout=self.timeout, allow_redirects=False, stream=True)
            loc = resp.headers.get("Location")
            if not (resp.status_code in REDIRECT_CODES and loc):
                res.redirect_chain = chain
                return resp
            nxt = urljoin(cur, loc); chain.append({"status": resp.status_code, "url": cur, "location": nxt})
            status = resp.status_code; resp.close()
            if hop == MAX_REDIRECTS: raise requests.exceptions.TooManyRedirects(f"more than {MAX_REDIRECTS} redirects")
            why = self._redirect_violation(cur, nxt)
            if why:
                res.status, res.final_url, res.redirect_chain = status, cur, chain
                res.error_kind, res.exception = "redirect_blocked", f"RedirectBlocked: {why}"
                return None
            cur = nxt
        return None

    def _once(self, url: str) -> FetchResult:
        res = FetchResult(url); chunks, got, resp = [], 0, None; t0 = time.monotonic()
        try:
            resp = self._open(url, res)
            if resp is not None:
                res.status, res.final_url = resp.status_code, resp.url
                res.content_type = resp.headers.get("Content-Type")
                res.headers = {k: ("[redacted]" if k.lower() in ("set-cookie", "authorization") else v) for k, v in dict(resp.headers).items()}
                for chunk in resp.iter_content(65536):
                    if not chunk: continue
                    room = MAX_BODY - got
                    if len(chunk) > room:
                        chunks.append(chunk[:room]); got += room; res.truncated = True; break
                    chunks.append(chunk); got += len(chunk)
        except Exception as exc:
            res.exception = f"{type(exc).__name__}: {exc}"[:300]; res.error_kind = classify_exception(exc)
        finally:
            if resp is not None:
                try: resp.close()
                except Exception: pass
        body = b"".join(chunks); res.size_bytes = len(body); res.elapsed_s = round(time.monotonic() - t0, 3)
        enc = None
        if res.content_type:
            m = re.search(r"charset=([\w\-]+)", res.content_type, re.I); enc = m.group(1) if m else None
        try: res.text = body.decode(enc or getattr(resp, "encoding", None) or "utf-8", errors="replace")
        except LookupError: res.text = body.decode("utf-8", errors="replace")
        return res

    def get(self, url: str) -> FetchResult:
        if not self.allowed(url):
            info = self.robots_info.get(f"{urlparse(url).scheme}://{urlparse(url).netloc}", {})
            status = "robots_txt_unreachable_5xx" if info.get("effect", "").startswith("unreachable_5xx") else "blocked_by_robots_txt"
            return FetchResult(url, status=info.get("http_status"), access_status=status)
        result = FetchResult(url)
        for attempt in range(self.retries + 1):
            if self._requested_before or attempt: self.sleep(2.0 if attempt else self.delay)
            self._requested_before = True
            result = self._once(url); result.attempts = attempt + 1
            transient = (result.exception is not None and result.error_kind != "redirect_blocked") or (result.status is not None and (result.status == 429 or result.status >= 500))
            if not transient: break
        result.access_status = classify_access(result)
        return result


def _is_page_link(abs_url: str, host: str) -> bool:
    p = urlparse(abs_url)
    return p.scheme in ("http", "https") and (p.hostname or "").lower() == host and not has_ext(abs_url, DOC_EXT + STATIC_EXT)


def _container_signature(a) -> str:
    parts = []
    for p in list(a.parents)[:4]:
        if getattr(p, "name", None) in (None, "[document]"): break
        cls = p.get("class") or []; parts.append(p.name + ("." + ".".join(sorted(cls)) if cls else ""))
    return " < ".join(parts)


def _headline_like(name: str) -> bool:
    words = name.split()
    return bool(re.search(r"\d", name)) or len(words) > 6


def _in_chrome(el) -> bool:
    for p in [el] + list(el.parents):
        if getattr(p, "name", None) in ("nav", "header", "footer"): return True
        if not hasattr(p, "get") or getattr(p, "name", None) == "[document]": continue
        if p.get("role") in ("navigation", "banner", "contentinfo") or CHROME_CLASS.search(describe(p)): return True
    return False


def discover_boards(html: str, page_url: str, board_url_regex: str | None = None, max_boards: int = MAX_BOARDS, select_clusters: list | None = None):
    """Discover regional-board candidates. Returns (boards, diagnostics)."""
    soup = BeautifulSoup(html or "", "html.parser"); host = (urlparse(page_url).hostname or "").lower(); home_norm = norm_url(page_url)
    pattern = re.compile(board_url_regex) if board_url_regex else None; base = document_base(soup, page_url)
    cands, first_by_url = [], {}
    for a in soup.find_all("a", href=True):
        href = a["href"].strip()
        if not href or href.lower().startswith(("javascript:", "mailto:", "tel:", "#")): continue
        absu = encode_url(urljoin(base, href)); text = clean(a.get_text(" ", strip=True))
        alts = [im.get("alt", "") for im in a.find_all("img") if im.get("alt")]
        label = clean(" ".join([text] + alts + [a.get("title", "")]))
        method = "label_mentions_rrb" if BOARD_LABEL.search(label) else None
        if method is None:
            anc = " ".join(describe(p) for p in list(a.parents)[:4] if p.name not in ("body", "html", "[document]"))
            h = a.find_previous(re.compile(r"^h[1-6]$"))
            if h is not None and h.parent in list(a.parents): anc += " " + clean(h.get_text(" ", strip=True))
            if BOARD_CONTEXT.search(anc): method = "container_or_scoped_heading_mentions_region_zone_board"
        if method is None:
            pp = urlparse(absu); segs = [s for s in pp.path.split("/") if s]
            if ( (pp.hostname or "").lower() == CENTRAL_HOST and len(segs) == 1 and segs[0].lower() not in NON_BOARD_SLUGS and not has_ext(absu, DOC_EXT + STATIC_EXT)):
                method = "unified_portal_url_subdirectory"
        if method is None: continue
        name = clean(" ".join([text] + alts)) or clean(a.get("title", "")) or norm_url(absu).rsplit("/", 1)[-1]
        c = {"index": len(cands), "href": href, "url": absu, "text": text, "name": name, "method": method, "in_chrome": _in_chrome(a), "signature": _container_signature(a), "cluster": None, "classification": None, "reason": None}
        key = norm_url(absu)
        if not _is_page_link(absu, host): c.update(classification="excluded", reason="not_same_host_page_link")
        elif key == home_norm: c.update(classification="excluded", reason="same_as_homepage")
        elif pattern and not pattern.search(absu): c.update(classification="excluded", reason="board_url_regex_mismatch")
        elif _headline_like(name): c.update(classification="excluded", reason="headline_like_text_contains_digits_or_is_long")
        elif key in first_by_url:
            first_by_url[key]["duplicate_hrefs"].append(href); c.update(classification="duplicate", reason=f"same_normalized_url_as_candidate_{first_by_url[key]['index']}")
        else:
            c["duplicate_hrefs"] = []; first_by_url[key] = c
        cands.append(c)
    live = [c for c in cands if c["classification"] is None]; groups = {}
    for c in live: groups.setdefault(c["signature"], []).append(c)
    ordered = sorted(groups.items(), key=lambda kv: (-len(kv[1]), kv[1][0]["index"])); clusters = []
    for i, (sig, members) in enumerate(ordered, 1):
        for m in members: m["cluster"] = i
        depths = sorted({len([x for x in urlparse(m["url"]).path.split("/") if x]) for m in members})
        clusters.append({"cluster": i, "size": len(members), "signature": sig, "path_depths": depths, "chrome_links": sum(m["in_chrome"] for m in members), "sample_names": [m["name"] for m in members[:8]], "sample_urls": [m["url"] for m in members[:3]]})
    diag = {"candidates_total_matched": len(cands), "candidates_after_exclusions": len(live), "clusters": clusters, "warnings": [], "ambiguous": False, "ambiguity_reason": None, "selection_method": None, "candidates": cands}
    chosen = []
    if select_clusters:
        chosen = [i for i in select_clusters if 1 <= i <= len(clusters)]; diag["selection_method"] = "operator_selected_clusters"
        if len(chosen) != len(set(select_clusters)): diag["warnings"].append(f"some requested clusters do not exist (have {len(clusters)})")
    elif pattern and clusters:
        chosen = [c["cluster"] for c in clusters]; diag["selection_method"] = "operator_board_url_regex"
    elif clusters:
        top = clusters[0]; second = clusters[1]["size"] if len(clusters) > 1 else 0
        if top["size"] >= 3 and top["size"] >= 1.5 * second: chosen = [1]; diag["selection_method"] = "dominant_cluster"
        else: diag["ambiguous"] = True; diag["ambiguity_reason"] = f"no dominant cluster (largest={top['size']}, next={second}); inspect clusters, then use select_clusters or board_url_regex"
    elif cands:
        diag["ambiguous"] = True; diag["ambiguity_reason"] = "every matched link was excluded; see candidate reasons"
    selected = [c for c in live if c["cluster"] in chosen]
    for c in live:
        if c["cluster"] in chosen: c["classification"], c["reason"] = "selected", f"member of cluster {c['cluster']} ({diag['selection_method']})"
        else: c["classification"], c["reason"] = "uncertain", "plausible link but not in a selected cluster"
    if len(selected) > max_boards:
        diag["ambiguous"] = True; diag["ambiguity_reason"] = f"selected cluster(s) hold {len(selected)} links, over max_boards={max_boards}"; selected = []
    out, used = [], set()
    for c in selected:
        bd = Board("", c["name"], c["url"], c["href"], c["text"], c["method"], list(c["duplicate_hrefs"]), ["link sits inside nav/header/footer/menu markup"] if c["in_chrome"] else [], c["cluster"])
        base_slug = slugify(urlparse(bd.url).path.strip("/").split("/")[-1]) or slugify(bd.name) or "board"; bid, n = base_slug, 2
        while bid in used: bid, n = f"{base_slug}-{n}", n + 1; bd.notes.append("board_id collision resolved with numeric suffix; URLs are distinct")
        used.add(bid); bd.board_id = bid; out.append(bd)
    diag["candidate_boards"], diag["selected_count"] = len(out), len(out)
    return out, diag


def load_boards_file(path: str) -> list[Board]:
    items = json.loads(Path(path).read_text(encoding="utf-8")); boards, used = [], set()
    if not isinstance(items, list): raise ValueError("boards file must contain a JSON list")
    for i, it in enumerate(items):
        url, name, ev = (it.get("url") or "").strip(), (it.get("name") or "").strip(), (it.get("evidence") or "").strip()
        p = urlparse(url)
        if p.scheme != "https" or not (p.hostname or "").lower().endswith(".gov.in"): raise ValueError(f"entry {i}: url must be https on *.gov.in, got {url!r}")
        if not name or not ev: raise ValueError(f"entry {i}: 'name' and 'evidence' (where you verified this URL) are required")
        base_slug = slugify(p.path.strip("/").split("/")[-1]) or slugify(name) or "board"; bid, n = base_slug, 2
        while bid in used: bid, n = f"{base_slug}-{n}", n + 1
        used.add(bid); boards.append(Board(bid, name, url, url, name, "operator_supplied", notes=[f"operator evidence: {ev}"], discovery_status="operator_supplied_unverified_until_identity_confirmed"))
    return boards


def confirm_board_identity(html: str, board: Board) -> dict:
    soup = BeautifulSoup(html or "", "html.parser"); title = clean(soup.title.get_text(" ", strip=True)) if soup.title else ""
    h1s = [clean(h.get_text(" ", strip=True)) for h in soup.find_all("h1")][:3]; h2s = [clean(h.get_text(" ", strip=True)) for h in soup.find_all("h2")][:5]
    body = clean(soup.get_text(" ", strip=True))[:5000]; strong = " ".join([title] + h1s + h2s).casefold()
    stripped = BOARD_LABEL.sub(" ", board.name); tokens = [t.casefold() for t in re.findall(r"[^\W\d_]{3,}", stripped) if t.casefold() not in ("railway", "recruitment", "board", "boards", "rrb")]
    if not tokens: tokens = re.findall(r"[a-z]{3,}", (urlparse(board.url).path or "").lower())
    word = lambda t, text: re.search(r"(?<!\w)" + re.escape(t) + r"(?!\w)", text) is not None
    in_head = [t for t in tokens if word(t, strong)]; in_body = [t for t in tokens if word(t, body.casefold())]
    rrb_phrase = bool(BOARD_LABEL.search(" ".join([title] + h1s + h2s) + " " + body))
    if rrb_phrase and in_head: status = "confirmed"
    elif rrb_phrase:
        board_slug = slugify(board.name); path_slug = urlparse(board.url).path.strip("/").lower()
        if board_slug and board_slug in path_slug: status = "confirmed_via_url_path_and_body_rrb_phrase"
        elif in_body: status = "unconfirmed_name_only_in_body_text"
        else: status = "unconfirmed_board_name_not_found_in_page"
    else: status = "unconfirmed_no_rrb_phrase_in_page"
    return {"status": status, "title": title[:200], "h1": h1s, "h2": h2s, "name_tokens": tokens, "name_tokens_found": in_head, "name_tokens_found_only_in_body": [t for t in in_body if t not in in_head], "rrb_phrase_found": rrb_phrase}


@dataclass
class ParseOutcome:
    notices: list
    status: str
    ok: bool
    strategy: str
    notes: list = field(default_factory=list)
    excluded: list = field(default_factory=list)
    pagination_links_seen: int = 0
    js_markers: list = field(default_factory=list)


def _row_of(a):
    for p in a.parents:
        if p.name in ("tr", "li", "article"): return p
    for p in a.parents:
        if p.name in ("p", "td", "div"): return p
    return a.parent


def make_notice(board: Board, source_url: str, title: str, notice_url: str, published: str | None, notes: list, retrieval_status: str) -> Notice:
    is_pdf = has_ext(notice_url, (".pdf",)); cat = next((name for name, rx in CATEGORY_HINTS if rx.search(title)), None)
    return Notice(board.board_id, board.name, source_url, title, notice_url, notice_url if is_pdf else None, published, None, None, sha(board.board_id, norm_url(notice_url), norm_title(title)), sha(norm_url(notice_url)), cat, retrieval_status, list(notes))


def parse_generic_html_notices(html: str, page_url: str, board: Board, retrieval_status: str = "http_ok") -> ParseOutcome:
    """Best-effort generic parser; results are not production-verified."""
    soup = BeautifulSoup(html or "", "html.parser"); base = document_base(soup, page_url); low = (html or "").lower()
    js = [m for m in JS_MARKERS if m.lower() in low]
    pag = sum(1 for a in soup.find_all("a", href=True) if re.search(r"[?&](page|pageno|pg)=", a["href"], re.I))
    containers = [el for el in soup.find_all(["div", "section", "ul", "ol", "table", "article", "tbody", "marquee"]) if (el.name == "marquee" or NOTICE_CLASS.search(describe(el))) and el.find("a", href=True) and not _in_chrome(el)]
    ids = {id(c) for c in containers}; containers = [c for c in containers if not any(id(p) in ids for p in c.parents)]
    if containers: strategy = "notice_containers"; anchors = [a for c in containers for a in c.find_all("a", href=True)]
    else:
        strategy = "document_links_fallback"; anchors = [a for a in soup.find_all("a", href=True) if (has_ext(a["href"], DOC_EXT) or NOTICE_PATH_HINT.search(a["href"])) and not _in_chrome(a)]
    notices, excluded, seen, pending = [], [], set(), []
    for a in anchors:
        href = a["href"].strip(); text = clean(a.get_text(" ", strip=True)); why = None
        if not href or href.lower().startswith(("javascript:", "mailto:", "tel:", "#")): why = "non_navigational_href"
        elif _in_chrome(a): why = "inside_page_chrome"
        elif PAG_TEXT.match(text) and "pag" in " ".join(describe(p) for p in list(a.parents)[:4]).lower(): why = "pagination_link"
        absu = encode_url(urljoin(base, href)) if not why else href
        if not why and norm_url(absu) in (norm_url(page_url), norm_url(board.url)): why = "links_to_the_page_itself"
        if why: excluded.append({"href": href, "text": text[:80], "reason": why}); continue
        row = _row_of(a); row_text = clean(row.get_text(" ", strip=True)) if row is not None else text; rest = clean(row_text.replace(text, "")) if text else row_text
        notes, title = [], text
        if not title or title.lower() in GENERIC_LABELS: title = rest[:300]; notes.append("anchor text empty/generic; title taken from surrounding row text")
        if not title: excluded.append({"href": href, "text": "", "reason": "no_title_available"}); continue
        published, dnote = parse_date(rest)
        if published is None and parse_date(text)[0]: notes.append("date-like text only inside the title; published_date left null")
        if dnote: notes.append(dnote)
        if has_ext(absu, DOC_EXT) and not has_ext(absu, (".pdf",)): notes.append("non-PDF document link")
        key = (norm_url(absu), norm_title(title))
        if key in seen: excluded.append({"href": href, "text": text[:80], "reason": "duplicate_in_page"}); continue
        seen.add(key); notice = make_notice(board, page_url, title, absu, published, notes, retrieval_status)
        if not text or text.lower() in GENERIC_LABELS: pending.append((notice, href, text))
        else: notices.append(notice)
    titled_urls = {norm_url(n.notice_url) for n in notices}
    for n, href, text in pending:
        if norm_url(n.notice_url) in titled_urls: excluded.append({"href": href, "text": text[:80], "reason": "generic_link_duplicates_titled_notice"})
        else: notices.append(n)
    pnotes = ["UNVERIFIED generic parser; selectors are not backed by a real official response"]
    if notices: return ParseOutcome(notices, "parsed_generic_unverified" if strategy == "notice_containers" else "parsed_generic_fallback_unverified", True, strategy, pnotes, excluded, pag, js)
    scoped = " ".join(el.get_text(" ", strip=True) for el in soup.find_all(["div", "section", "ul", "ol", "table", "article", "tbody", "marquee", "p"]) if NOTICE_CLASS.search(describe(el)) or el.name == "marquee").lower()
    if any(p in scoped for p in EMPTY_PHRASES): return ParseOutcome([], "empty_section_indicated_by_page_text", True, strategy, pnotes, excluded, pag, js)
    status = "unrecognized_structure_possible_client_rendering" if js or not soup.find("a", href=True) else "unrecognized_structure_no_notice_elements"
    return ParseOutcome([], status, False, strategy, pnotes, excluded, pag, js)


ADAPTERS = {"generic_html_v0": parse_generic_html_notices}


def choose_parser(board: Board) -> str:
    return BOARD_PARSER.get(board.board_id, "generic_html_v0")


def process_board(board: Board, fetcher: Fetcher) -> dict:
    parser_name = choose_parser(board); verified = parser_name in VERIFIED_ADAPTERS
    rec = {"board_id": board.board_id, "board_name": board.name, "board_url": board.url, "official_homepage_link": {"href": board.href, "text": board.link_text, "method": board.discovery_method, "cluster": board.cluster, "duplicate_hrefs": board.duplicate_hrefs}, "parser": parser_name, "verified": verified, "verification_status": "verified_against_real_responses" if verified else "unverified_no_real_response_evidence", "retrieval_method": None, "access_status": "not_tested", "http_status": None, "final_url": None, "content_type": None, "error_kind": None, "identity_status": "not_tested", "identity_evidence": {}, "parse_status": "not_run", "parse_ok": False, "notice_count": 0, "notices": [], "errors": [], "evidence": {}, "stages": {"url_discovered": True, "response_received": False, "identity_confirmed": False, "page_parsed": False, "notices_extracted": False}}
    try:
        fr = fetcher.get(board.url); rec.update(retrieval_method=fr.method, access_status=fr.access_status, http_status=fr.status, final_url=fr.final_url, content_type=fr.content_type, error_kind=fr.error_kind)
        rec["evidence"].update(size_bytes=fr.size_bytes, elapsed_s=fr.elapsed_s, attempts=fr.attempts, truncated=fr.truncated, redirect_chain=fr.redirect_chain)
        if fr.exception: rec["errors"].append(fr.exception)
        if fr.access_status != "ok": rec["parse_status"] = "not_run_access_failed"; return rec
        rec["stages"]["response_received"] = True; final_host = (urlparse(fr.final_url or board.url).hostname or "").lower()
        if final_host != (urlparse(board.url).hostname or "").lower(): rec["identity_status"] = "unconfirmed_redirected_off_host"; rec["errors"].append(f"redirected to a different host: {final_host}"); rec["parse_status"] = "not_run_identity_unconfirmed"; return rec
        if "json" in (fr.content_type or "").lower() or fr.text.lstrip()[:1] in ("{", "["): rec["parse_status"] = "unsupported_json_response_no_adapter"; rec["errors"].append("JSON response received but no evidence-based JSON adapter exists"); return rec
        ident = confirm_board_identity(fr.text, board); rec["identity_status"], rec["identity_evidence"] = ident["status"], ident
        if ident["status"] not in ("confirmed", "confirmed_via_url_path_and_body_rrb_phrase"): rec["parse_status"] = "not_run_identity_unconfirmed"; return rec
        rec["stages"]["identity_confirmed"] = True; board.discovery_status = "identity_confirmed_from_own_page"
        out = ADAPTERS[parser_name](fr.text, fr.final_url or board.url, board, "http_ok")
        rec.update(parse_status=out.status, parse_ok=out.ok, notice_count=len(out.notices), notices=[n.to_dict() for n in out.notices]); rec["stages"]["page_parsed"] = out.ok; rec["stages"]["notices_extracted"] = len(out.notices) > 0
        rec["evidence"].update(strategy=out.strategy, parser_notes=out.notes, excluded_count=len(out.excluded), excluded_samples=out.excluded[:20], pagination_links_seen=out.pagination_links_seen, pagination_followed=False, js_markers=out.js_markers)
    except Exception as exc:
        rec["parse_status"] = "parser_exception"; rec["errors"].append(f"{type(exc).__name__}: {exc}"[:300])
    return rec


def _finalize(report: dict, status: str, reason: str | None) -> dict:
    bs = report["boards"]; disc = report.get("discovery", {}); candidates = disc.get("candidates", [])
    count = lambda k: sum(c.get("classification") == k for c in candidates)
    report["overall_status"] = status
    report["summary"] = {"reason": reason, "candidates_matched": disc.get("candidates_total_matched", 0), "candidates_excluded": count("excluded"), "candidates_duplicate": count("duplicate"), "candidates_uncertain": count("uncertain"), "candidates_selected": count("selected"), "clusters_found": len(disc.get("clusters", [])), "boards_selected_for_fetch": len(bs), "response_received": sum(b["stages"]["response_received"] for b in bs), "identity_confirmed": sum(b["stages"]["identity_confirmed"] for b in bs), "identity_unconfirmed": sum(b["stages"]["response_received"] and not b["stages"]["identity_confirmed"] for b in bs), "pages_parsed_ok": sum(b["stages"]["page_parsed"] for b in bs), "pages_with_notices": sum(b["stages"]["notices_extracted"] for b in bs), "access_failed": sum(b["access_status"] not in ("ok", "not_tested") for b in bs), "boards_verified": sum(b["verified"] for b in bs), "notices_total": sum(b["notice_count"] for b in bs)}
    report["notices"] = [n for b in bs for n in b["notices"]]; report["finished_utc"] = now_iso(); return report


def collect(fetcher: Fetcher | None = None, home_url: str = HOME_URL, board_url_regex: str | None = None, max_boards: int = MAX_BOARDS, select_clusters: list | None = None, discovery_only: bool = False, boards_override: list[Board] | None = None) -> dict:
    fetcher = fetcher or Fetcher(); report = {"module_version": MODULE_VERSION, "started_utc": now_iso(), "home_url": home_url, "homepage": {}, "discovery": {}, "boards": [], "summary": {}, "overall_status": None, "production_ready": False}
    if boards_override is not None:
        report["homepage"] = {"access_status": "not_requested_operator_board_list"}; report["discovery"] = {"selection_method": "operator_boards_file", "candidates": [], "clusters": [], "candidates_total_matched": 0, "boards": [asdict(b) for b in boards_override]}
        report["boards"] = [process_board(b, fetcher) for b in boards_override]; report["robots"] = getattr(fetcher, "robots_info", {}); ok = [b for b in report["boards"] if b["parse_ok"]]
        return _finalize(report, "TOTAL_FAILURE" if not ok else "COMPLETE_UNVERIFIED" if len(ok) == len(boards_override) else "PARTIAL", None)
    hp = fetcher.get(home_url); report["homepage"] = {"requested_url": hp.requested_url, "final_url": hp.final_url, "http_status": hp.status, "content_type": hp.content_type, "access_status": hp.access_status, "retrieval_method": hp.method, "size_bytes": hp.size_bytes, "exception": hp.exception, "error_kind": hp.error_kind, "attempts": hp.attempts, "elapsed_s": hp.elapsed_s, "response_headers": hp.headers}; report["robots"] = getattr(fetcher, "robots_info", {})
    if hp.access_status != "ok": return _finalize(report, "TOTAL_FAILURE", f"homepage not usable: {hp.access_status}")
    fhost = (urlparse(hp.final_url or home_url).hostname or "").lower()
    if not fhost.endswith(".gov.in"): return _finalize(report, "TOTAL_FAILURE", f"homepage redirected off the official *.gov.in domain to {fhost!r}; not crawled")
    try: boards, diag = discover_boards(hp.text, hp.final_url or home_url, board_url_regex, max_boards, select_clusters)
    except Exception as exc: return _finalize(report, "TOTAL_FAILURE", f"discovery crashed: {type(exc).__name__}: {exc}")
    report["discovery"] = {**diag, "boards": [asdict(b) for b in boards]}
    if not boards: return _finalize(report, "TOTAL_FAILURE", diag.get("ambiguity_reason") or "no regional boards discovered (not proof that none exist)")
    if discovery_only: return _finalize(report, "DISCOVERY_ONLY", "board pages not requested (--discovery-only)")
    report["boards"] = [process_board(b, fetcher) for b in boards]; ok = [b for b in report["boards"] if b["parse_ok"]]
    return _finalize(report, "TOTAL_FAILURE" if not ok else "COMPLETE_UNVERIFIED" if len(ok) == len(boards) else "PARTIAL", None)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Read-only RRB notice collector")
    ap.add_argument("--out", default="rrb_report.json"); ap.add_argument("--board-url-regex"); ap.add_argument("--select-clusters", help="comma-separated cluster numbers, e.g. 1,2"); ap.add_argument("--max-boards", type=int, default=MAX_BOARDS); ap.add_argument("--connect-timeout", type=float, default=TIMEOUT[0]); ap.add_argument("--read-timeout", type=float, default=TIMEOUT[1]); ap.add_argument("--boards-file"); ap.add_argument("--discovery-only", action="store_true")
    args = ap.parse_args(argv); timeout = (min(max(args.connect_timeout, 1), 60), min(max(args.read_timeout, 1), 120)); fetcher = Fetcher(timeout=timeout)
    sel = [int(x) for x in args.select_clusters.split(",") if x.strip()] if args.select_clusters else None
    rep = collect(fetcher, board_url_regex=args.board_url_regex, max_boards=args.max_boards, select_clusters=sel, discovery_only=args.discovery_only, boards_override=load_boards_file(args.boards_file) if args.boards_file else None)
    Path(args.out).write_text(json.dumps(rep, indent=2, ensure_ascii=False), encoding="utf-8"); print(json.dumps({"overall_status": rep["overall_status"], **rep["summary"]}, indent=2, ensure_ascii=False)); print(f"\nfull report: {Path(args.out).resolve()}")
    return 2 if rep["overall_status"] == "TOTAL_FAILURE" else 0


if __name__ == "__main__":
    raise SystemExit(main())
