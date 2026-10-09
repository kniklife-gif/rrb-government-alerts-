# RRB Government Alerts

Automated monitoring of Railway Recruitment Board notices from https://rrb.indianrailways.gov.in/.

## Files

- `rrb.py` — discovery, identity checks, and generic notice parsing.
- `main.py` — orchestration, Telegram notifications, and persistent seen-state.
- `state/seen.json` — persistent set of previously-seen notice hashes.
- `.github/workflows/rrb_alerts.yml` — scheduled execution.
- `test_rrb.py` — regression tests.

## Required GitHub Secrets

- `TELEGRAM_BOT_TOKEN`
- `TELEGRAM_CHAT_ID`

Optional environment variable: `RRB_BOARDS_FILE`, pointing to a JSON list of objects with `name`, `url`, and `evidence` keys.

## Local run

```bash
pip install -r requirements.txt
python rrb.py --discovery-only --out disc.json
python rrb.py --out rrb_report.json
python main.py
```

## Tests

```bash
python -m py_compile rrb.py main.py
python -m pytest test_rrb.py -v
```

## Status

Discovery and parsing rules are unverified against live official responses. No board count or notice count is claimed. Inspect the generated JSON report before relying on alerts.
