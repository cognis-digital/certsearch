"""Command-line interface for CERTSEARCH."""
from __future__ import annotations

import argparse
import json
import sys
from html import escape

from . import TOOL_NAME, TOOL_VERSION
from .core import AnalysisResult, CertsearchError, analyze, parse_export

_SEV_COLOR = {
    "critical": "#b00020",
    "high": "#d84315",
    "medium": "#f9a825",
    "low": "#1565c0",
    "info": "#546e7a",
}


def _read(path: str) -> str:
    if path == "-":
        return sys.stdin.read()
    with open(path, "r", encoding="utf-8") as fh:
        return fh.read()


def _render_table(res: AnalysisResult) -> str:
    lines: list[str] = []
    lines.append(f"CERTSEARCH report for {res.base_domain}")
    lines.append("=" * 56)
    lines.append(f"Certificates analyzed : {res.total_certs}")
    lines.append(f"Subdomains discovered : {len(res.subdomains)}")
    lines.append(f"Wildcards             : {len(res.wildcards)}")
    counts = res.counts()
    sev_line = ", ".join(
        f"{k}={counts[k]}" for k in ("critical", "high", "medium", "low", "info")
        if counts.get(k)
    ) or "none"
    lines.append(f"Findings              : {len(res.findings)} ({sev_line})")
    lines.append("")

    if res.subdomains:
        lines.append("Subdomains:")
        for s in res.subdomains:
            lines.append(f"  - {s}")
        lines.append("")

    if res.findings:
        lines.append("Findings:")
        for f in res.findings:
            lines.append(f"  [{f.severity.upper():8}] {f.kind:20} {f.name}")
            lines.append(f"             {f.detail}")
    else:
        lines.append("No findings.")
    return "\n".join(lines)


def _render_html(res: AnalysisResult) -> str:
    counts = res.counts()
    summary_rows = "".join(
        f'<tr><td><span class="dot" style="background:{_SEV_COLOR[k]}"></span>'
        f'{k}</td><td>{counts.get(k, 0)}</td></tr>'
        for k in ("critical", "high", "medium", "low", "info")
    )
    finding_rows = "".join(
        f'<tr class="sev-{f.severity}">'
        f'<td><span class="badge" style="background:{_SEV_COLOR[f.severity]}">'
        f'{escape(f.severity.upper())}</span></td>'
        f'<td>{escape(f.kind)}</td>'
        f'<td class="mono">{escape(f.name)}</td>'
        f'<td>{escape(f.detail)}</td></tr>'
        for f in res.findings
    ) or '<tr><td colspan="4" class="empty">No findings.</td></tr>'
    sub_items = "".join(
        f'<li class="mono">{escape(s)}</li>' for s in res.subdomains
    ) or "<li><em>none</em></li>"

    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>CERTSEARCH — {escape(res.base_domain)}</title>
<style>
  :root {{ font-family: -apple-system, Segoe UI, Roboto, sans-serif; }}
  body {{ margin:0; background:#f4f5f7; color:#1a1a1a; }}
  header {{ background:#11151c; color:#fff; padding:20px 28px; }}
  header h1 {{ margin:0; font-size:20px; letter-spacing:.5px; }}
  header .sub {{ color:#9aa4b2; font-size:13px; margin-top:4px; }}
  main {{ max-width:1000px; margin:24px auto; padding:0 16px; }}
  .cards {{ display:flex; gap:16px; flex-wrap:wrap; margin-bottom:20px; }}
  .card {{ background:#fff; border-radius:10px; padding:16px 20px;
           box-shadow:0 1px 3px rgba(0,0,0,.1); flex:1; min-width:150px; }}
  .card .n {{ font-size:28px; font-weight:700; }}
  .card .l {{ color:#667; font-size:12px; text-transform:uppercase; }}
  table {{ width:100%; border-collapse:collapse; background:#fff;
           border-radius:10px; overflow:hidden; box-shadow:0 1px 3px rgba(0,0,0,.1); }}
  th, td {{ text-align:left; padding:10px 14px; border-bottom:1px solid #eee;
            font-size:14px; vertical-align:top; }}
  th {{ background:#fafbfc; font-size:12px; text-transform:uppercase; color:#667; }}
  .badge {{ color:#fff; padding:2px 8px; border-radius:12px; font-size:11px;
            font-weight:700; }}
  .dot {{ display:inline-block; width:10px; height:10px; border-radius:50%;
          margin-right:8px; vertical-align:middle; }}
  .mono {{ font-family:ui-monospace, Menlo, Consolas, monospace; font-size:13px; }}
  .empty {{ text-align:center; color:#888; }}
  h2 {{ font-size:15px; margin:24px 0 10px; }}
  ul {{ columns:2; background:#fff; border-radius:10px; padding:16px 16px 16px 36px;
        box-shadow:0 1px 3px rgba(0,0,0,.1); }}
  .max {{ font-weight:700; }}
</style></head>
<body>
<header>
  <h1>CERTSEARCH report</h1>
  <div class="sub">{escape(res.base_domain)} &middot; {res.total_certs} certificates
    &middot; highest severity:
    <span class="max" style="color:{_SEV_COLOR[res.max_severity]}">
    {escape(res.max_severity.upper())}</span></div>
</header>
<main>
  <div class="cards">
    <div class="card"><div class="n">{res.total_certs}</div>
      <div class="l">Certificates</div></div>
    <div class="card"><div class="n">{len(res.subdomains)}</div>
      <div class="l">Subdomains</div></div>
    <div class="card"><div class="n">{len(res.wildcards)}</div>
      <div class="l">Wildcards</div></div>
    <div class="card"><div class="n">{len(res.findings)}</div>
      <div class="l">Findings</div></div>
  </div>

  <h2>Severity summary</h2>
  <table><thead><tr><th>Severity</th><th>Count</th></tr></thead>
  <tbody>{summary_rows}</tbody></table>

  <h2>Findings</h2>
  <table><thead><tr><th>Severity</th><th>Kind</th><th>Name</th><th>Detail</th></tr>
  </thead><tbody>{finding_rows}</tbody></table>

  <h2>Discovered subdomains</h2>
  <ul>{sub_items}</ul>
</main>
</body></html>"""


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog=TOOL_NAME,
        description="Analyze Certificate-Transparency exports for subdomains "
                    "and rogue issuance (defensive recon on domains you own).",
    )
    p.add_argument("--version", action="version",
                   version=f"{TOOL_NAME} {TOOL_VERSION}")
    sub = p.add_subparsers(dest="command", required=True)

    a = sub.add_parser("analyze", help="analyze a CT export for one base domain")
    a.add_argument(
        "export",
        help="path to CT export (JSON/JSONL/CSV), or '-' for stdin",
    )
    a.add_argument(
        "-d", "--domain",
        required=True,
        help="base domain you own, e.g. example.com",
    )
    a.add_argument("--format", choices=("table", "json", "html"), default="table",
                   help="output format (html writes a self-contained report)")
    a.add_argument("-o", "--output", help="write report to this file instead of stdout")
    return p


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    if args.command == "analyze":
        if not args.domain or not args.domain.strip():
            print("error: --domain must not be empty", file=sys.stderr)
            return 2
        try:
            text = _read(args.export)
        except OSError as exc:
            print(f"error: cannot read export: {exc}", file=sys.stderr)
            return 2
        try:
            certs = parse_export(text)
            res = analyze(certs, args.domain)
        except CertsearchError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2
        except Exception as exc:  # noqa: BLE001
            print(f"error: unexpected failure during analysis: {exc}", file=sys.stderr)
            return 2

        if args.format == "json":
            out = json.dumps(res.to_dict(), indent=2)
        elif args.format == "html":
            out = _render_html(res)
        else:
            out = _render_table(res)

        if args.output:
            try:
                with open(args.output, "w", encoding="utf-8") as fh:
                    fh.write(out)
            except OSError as exc:
                print(f"error: cannot write output: {exc}", file=sys.stderr)
                return 2
            print(f"wrote {args.format} report to {args.output}", file=sys.stderr)
        else:
            print(out)

        # Non-zero exit if any actionable (non-info) findings exist.
        actionable = [f for f in res.findings if f.severity != "info"]
        return 1 if actionable else 0

    return 2


if __name__ == "__main__":
    sys.exit(main())
