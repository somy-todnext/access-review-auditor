"""Flag common access review findings in an account inventory."""
import argparse
import csv
from datetime import date
import json
import sys

COLUMNS = ("account", "role", "enabled", "mfa", "last_login")


def yes_no(value):
    if value not in ("yes", "no"):
        raise ValueError("enabled and mfa must be yes or no")
    return value == "yes"


def audit(source, as_of, days):
    reader = csv.DictReader(source, strict=True)
    if reader.fieldnames != list(COLUMNS):
        raise ValueError("Expected columns " + ",".join(COLUMNS))
    findings = []
    seen = set()
    for row in reader:
        try:
            if None in row or any(value is None for value in row.values()):
                raise ValueError("wrong number of fields")
            account, role, enabled, mfa, login = (row[key].strip() for key in COLUMNS)
            if not account or not role or account.casefold() in seen:
                raise ValueError("account and role must be present and accounts must be unique")
            seen.add(account.casefold())
            enabled, mfa = yes_no(enabled.lower()), yes_no(mfa.lower())
            last_login = date.fromisoformat(login) if login else None
            if last_login and last_login > as_of:
                raise ValueError("last login occurs after the review date")
        except ValueError as error:
            raise ValueError(f"Line {reader.line_num}: {error}") from error
        reasons = []
        if enabled:
            if role.casefold() == "admin" and not mfa:
                reasons.append("admin_without_mfa")
            if last_login is None:
                reasons.append("missing_login_history")
            elif (as_of - last_login).days >= days:
                reasons.append("inactive_account")
        if reasons:
            findings.append({"account": account, "reasons": reasons})
    return findings


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input")
    parser.add_argument("--as-of", type=date.fromisoformat, default=date.today())
    parser.add_argument("--days", type=int, default=90)
    args = parser.parse_args()
    if args.days < 1:
        parser.error("--days must be positive")
    try:
        with open(args.input, encoding="utf-8-sig", newline="") as source:
            findings = audit(source, args.as_of, args.days)
        print(json.dumps(findings, indent=2))
    except (OSError, ValueError, csv.Error) as error:
        print(f"Error: {error}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
