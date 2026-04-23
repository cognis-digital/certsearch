"""CERTSEARCH MCP server — exposes scan() as an MCP tool for Cognis.Studio."""
from __future__ import annotations
from certsearch.core import scan, to_json

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
    def certsearch_scan(target: str) -> str:
        """Analyze Certificate-Transparency exports for subdomains & rogue issuance. Returns JSON findings."""
        return to_json(scan(target))

    app.run()
    return 0
