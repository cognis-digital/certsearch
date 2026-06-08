"""CERTSEARCH — Certificate-Transparency export analyzer.

Analyze CT log exports (crt.sh-style JSON/CSV) for subdomain enumeration
and rogue / suspicious certificate issuance against domains you own.
Defensive/forensics only: operates on artifacts you already possess.
"""
from .core import (
    Certificate,
    Finding,
    AnalysisResult,
    parse_export,
    analyze,
    SEVERITY_ORDER,
)

TOOL_NAME = "certsearch"
TOOL_VERSION = "1.0.0"

__all__ = [
    "Certificate",
    "Finding",
    "AnalysisResult",
    "parse_export",
    "analyze",
    "SEVERITY_ORDER",
    "TOOL_NAME",
    "TOOL_VERSION",
]
