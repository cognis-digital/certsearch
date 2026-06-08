# Demo 01 — Basic CT-export triage for `example.com`

## Scenario

You own `example.com`. You pulled a Certificate-Transparency export from a
crt.sh-style source (`ct_export.json`) and want to:

1. Enumerate every subdomain that has ever had a certificate logged.
2. Surface **rogue / suspicious issuance** — certs that don't fit your
   expected CA posture, sensitive subdomains, expired leftovers, and
   **lookalike phishing domains** that embed your brand.

The export is intentionally seeded with realistic findings:

| Entry | What CERTSEARCH should catch |
|-------|------------------------------|
| `vpn.example.com` from `Acme Internal Root CA` | **HIGH** — unrecognized CA issued a cert for an owned name (possible rogue issuance) |
| `login.example.com` from Let's Encrypt | **MEDIUM** — sensitive subdomain from a free CA; confirm it's yours |
| `secure-example-login.com` | **CRITICAL** — external lookalike embeds the `example` brand (phishing infra) |
| `staging.example.com` / `dev.example.com` (expired 2026-01-15) | **LOW** — expired cert still in logs |
| `*.example.com` | **INFO** — apex wildcard present |

## Run it

```bash
# Human-readable triage table
python -m certsearch analyze demos/01-basic/ct_export.json -d example.com

# Machine-readable for pipelines (jq, SIEM ingest, etc.)
python -m certsearch analyze demos/01-basic/ct_export.json -d example.com --format json

# Self-contained shareable HTML report (the tool's UI)
python -m certsearch analyze demos/01-basic/ct_export.json \
    -d example.com --format html -o report.html
```

## Exit codes

- `0` — no actionable findings (only `info` or none)
- `1` — at least one `low`/`medium`/`high`/`critical` finding (use in CI)
- `2` — input/usage error

In this demo the tool exits **1** because actionable findings are present.
