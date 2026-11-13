# Access Review Auditor

Review an account inventory for enabled admins with MFA disabled, enabled accounts with old sign-ins, and enabled accounts with missing sign-in dates. Findings are review leads. The tool runs offline and makes no account changes.

```cmd
py audit.py sample.csv --as-of 2026-11-14
```

Use Python 3.10 or later. Use `python` if your system uses that command. The synthetic example flags demo-admin, demo-stale, and demo-new. Disabled accounts generate no findings. Exit code 0 means the review finished and 2 indicates an error.

The CSV uses the sample header. Provide one row per account, `yes` or `no` for enabled and MFA, `admin` for privileged accounts, and ISO dates for last sign-ins. Map your exported roles to that convention before running. An account is inactive when its last sign-in is at least 90 days before the review date. Use `--days` to change this threshold. Missing sign-in dates get a separate finding.

Created with AI assistance as a cybersecurity portfolio project.
