"""CERTSEARCH MCP server — exposes analyze() as an MCP tool for Cognis.Studio."""
from __future__ import annotations

import json

from certsearch.core import analyze, parse_export


def serve() -> int:
    """Start an MCP stdio server. Requires the optional 'mcp' extra:
        pip install "cognis-certsearch[mcp]"
    """
    try:
        from mcp.server.fastmcp import FastMCP
    except Exception:
        print("Install the MCP extra: pip install 'cognis-certsearch[mcp]'")
        return 1
    app = FastMCP("certsearch")

    @app.tool()
    def certsearch_scan(export_text: str, base_domain: str) -> str:
        """Analyze a CT export for subdomains & rogue issuance.

        Args:
            export_text: Raw CT export content (JSON array, JSONL, or CSV).
            base_domain: The base domain you own, e.g. ``example.com``.

        Returns:
            JSON string of findings.
        """
        certs = parse_export(export_text)
        result = analyze(certs, base_domain)
        return json.dumps(result.to_dict(), indent=2)

    app.run()
    return 0
