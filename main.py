#!/usr/bin/env python3
"""RRB recruitment alert orchestrator."""
from __future__ import annotations

import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

import requests
from rrb import collect, Fetcher, load_boards_file

STATE_PATH = Path("state/seen.json")
TELEGRAM_TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN", "").strip()
TELEGRAM_CHAT = os.environ.get("TELEGRAM_CHAT_ID", "").strip()


def load_state() -> dict:
    if STATE_PATH.exists():
        try:
            data = json.loads(STATE_PATH.read_text(encoding="utf-8"))
            if isinstance(data, dict) and isinstance(data.get("seen"), dict):
                return data
        except (OSError, json.JSONDecodeError):
            pass
    return {"seen": {}}


def save_state(state: dict) -> None:
    STATE_PATH.parent.mkdir(parents=True, exist_ok=True)
    temp = STATE_PATH.with_suffix(".json.tmp")
    temp.write_text(json.dumps(state, indent=2, ensure_ascii=False), encoding="utf-8")
    temp.replace(STATE_PATH)


def esc(s: str) -> str:
    return (s or "").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def format_notice(n: dict) -> str:
    parts = [f"<b>{esc(n.get('board_name', 'Unknown board'))}</b>"]
    if n.get("category_hint"):
        parts.append(f"[{esc(n['category_hint'])}]")
    parts.append(esc(n.get("title", "Untitled notice")))
    if n.get("published_date"):
        parts.append(f"Date: {esc(n['published_date'])}")
    parts.append(esc(n.get("notice_url", "")))
    return "\n".join(parts)


def send_telegram(text: str) -> bool:
    if not TELEGRAM_TOKEN or not TELEGRAM_CHAT:
        print("Telegram is not configured; skipping send", file=sys.stderr)
        return False
    url = f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage"
    try:
        response = requests.post(url, json={
            "chat_id": TELEGRAM_CHAT,
            "text": text,
            "parse_mode": "HTML",
            "disable_web_page_preview": False,
        }, timeout=20)
        if not response.ok:
            print(f"Telegram returned HTTP {response.status_code}: {response.text[:200]}", file=sys.stderr)
        return response.ok and response.json().get("ok", False)
    except (requests.RequestException, ValueError) as exc:
        print(f"Telegram send failed: {type(exc).__name__}: {exc}", file=sys.stderr)
        return False


def main() -> int:
    boards_file = os.environ.get("RRB_BOARDS_FILE", "").strip()
    fetcher = Fetcher()
    report = collect(fetcher=fetcher, boards_override=load_boards_file(boards_file) if boards_file else None)
    state = load_state()
    seen = state.setdefault("seen", {})
    new_notices = []
    for notice in report.get("notices", []):
        content_hash = notice.get("content_hash")
        if not content_hash or content_hash in seen:
            continue
        new_notices.append(notice)
    sent_hashes = []
    for notice in new_notices:
        if send_telegram(format_notice(notice)):
            sent_hashes.append(notice["content_hash"])
            seen[notice["content_hash"]] = {
                "first_seen": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                "board_id": notice.get("board_id", ""),
                "title": notice.get("title", "")[:200],
                "url": notice.get("notice_url", ""),
            }
    save_state(state)
    print(json.dumps({
        "overall_status": report.get("overall_status"),
        "boards_selected": report.get("summary", {}).get("boards_selected_for_fetch", 0),
        "notices_total": report.get("summary", {}).get("notices_total", 0),
        "new_notices": len(new_notices),
        "notified": len(sent_hashes),
    }, indent=2))
    return 2 if report.get("overall_status") == "TOTAL_FAILURE" else 0


if __name__ == "__main__":
    raise SystemExit(main())
