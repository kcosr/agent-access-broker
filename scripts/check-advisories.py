#!/usr/bin/env python3
"""Enforce dated exceptions before running the repository's dependency audit."""
import argparse
from datetime import date, datetime, timezone
from pathlib import Path
import re
import subprocess
import sys
import tomllib

ROOT = Path(__file__).resolve().parent.parent


def check_exception_dates(text, today):
    ignored = tomllib.loads(text).get("advisories", {}).get("ignore", [])
    if len(ignored) != len(set(ignored)):
        raise ValueError("duplicate advisory exceptions")
    records = re.findall(
        r'^\s*"(RUSTSEC-\d{4}-\d{4})",?\s*# review-by: (\d{4}-\d{2}-\d{2})\s*$',
        text, re.MULTILINE,
    )
    if len(records) != len(ignored) or {item[0] for item in records} != set(ignored):
        raise ValueError('each ignored advisory needs an inline "# review-by: YYYY-MM-DD"')
    for advisory, deadline in records:
        if today > date.fromisoformat(deadline):
            raise ValueError(f"{advisory} exception review expired after {deadline}; review or remove it")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cargo", default="cargo")
    args = parser.parse_args()
    try:
        check_exception_dates(
            (ROOT / ".cargo/audit.toml").read_text(), datetime.now(timezone.utc).date()
        )
    except (OSError, ValueError) as error:
        print(f"Dependency advisory check failed: {error}", file=sys.stderr)
        return 1
    return subprocess.call([args.cargo, "audit", "--deny", "warnings"], cwd=ROOT)


if __name__ == "__main__":
    sys.exit(main())
