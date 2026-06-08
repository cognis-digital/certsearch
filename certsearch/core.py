"""Core engine for CERTSEARCH.

Parses Certificate-Transparency exports (crt.sh JSON, generic JSON arrays,
or CSV) and performs defensive analysis: subdomain enumeration plus
detection of suspicious / rogue issuance against an owned base domain.

All logic is real and standard-library only.
"""
from __future__ import annotations

import csv
import io
import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Iterable

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

# Issuers commonly trusted by orgs. A cert for your domain from anything
# outside your expected set is worth a human look.
_COMMON_CA_HINTS = (
    "let's encrypt", "lets encrypt", "digicert", "sectigo", "globalsign",
    "google trust services", "amazon", "comodo", "godaddy", "entrust",
    "buypass", "zerossl", "cloudflare",
)

# Free / automated CAs frequently abused for lookalike phishing certs.
_FREE_CA_HINTS = ("let's encrypt", "lets encrypt", "zerossl", "buypass", "cloudflare")

_LABEL_RE = re.compile(r"^[a-z0-9_*]([a-z0-9_\-]*[a-z0-9_])?$", re.IGNORECASE)

# Tokens that, when prepended to an owned brand, suggest credential phishing.
_PHISH_TOKENS = (
    "login", "secure", "account", "verify", "signin", "sign-in", "auth",
    "mail", "webmail", "vpn", "portal", "update", "billing", "pay", "support",
    "admin", "sso", "confirm", "security", "wallet",
)


@dataclass
class Certificate:
    """One logged certificate / CT entry."""
    names: list[str]
    issuer: str = ""
    not_before: datetime | None = None
    not_after: datetime | None = None
    serial: str = ""
    log_id: str = ""
    raw_id: str = ""

    @property
    def primary(self) -> str:
        return self.names[0] if self.names else ""


@dataclass
class Finding:
    severity: str
    kind: str
    name: str
    detail: str
    certificate: Certificate | None = None

    def to_dict(self) -> dict:
        d = {
            "severity": self.severity,
            "kind": self.kind,
            "name": self.name,
            "detail": self.detail,
        }
        if self.certificate is not None:
            d["issuer"] = self.certificate.issuer
            d["not_after"] = (
                self.certificate.not_after.isoformat()
                if self.certificate.not_after else None
            )
            d["serial"] = self.certificate.serial
        return d


@dataclass
class AnalysisResult:
    base_domain: str
    total_certs: int = 0
    subdomains: list[str] = field(default_factory=list)
    wildcards: list[str] = field(default_factory=list)
    issuers: dict[str, int] = field(default_factory=dict)
    findings: list[Finding] = field(default_factory=list)

    @property
    def max_severity(self) -> str:
        if not self.findings:
            return "info"
        return min(self.findings, key=lambda f: SEVERITY_ORDER[f.severity]).severity

    def counts(self) -> dict[str, int]:
        out: dict[str, int] = {}
        for f in self.findings:
            out[f.severity] = out.get(f.severity, 0) + 1
        return out

    def to_dict(self) -> dict:
        return {
            "base_domain": self.base_domain,
            "total_certs": self.total_certs,
            "subdomains": self.subdomains,
            "wildcards": self.wildcards,
            "issuers": self.issuers,
            "severity_counts": self.counts(),
            "max_severity": self.max_severity,
            "findings": [f.to_dict() for f in self.findings],
        }


# --------------------------------------------------------------------------
# Parsing
# --------------------------------------------------------------------------

def _parse_dt(value) -> datetime | None:
    if value in (None, "", 0):
        return None
    if isinstance(value, (int, float)):
        try:
            return datetime.fromtimestamp(float(value), tz=timezone.utc)
        except (OverflowError, OSError, ValueError):
            return None
    s = str(value).strip()
    # crt.sh uses "YYYY-MM-DDTHH:MM:SS" (no tz); also accept date-only / Z.
    for fmt in ("%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S", "%Y-%m-%d"):
        try:
            return datetime.strptime(s, fmt).replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    try:
        return datetime.fromisoformat(s.replace("Z", "+00:00"))
    except ValueError:
        return None


def _split_names(*fields: str) -> list[str]:
    seen: dict[str, None] = {}
    for fld in fields:
        if not fld:
            continue
        # crt.sh packs SANs newline-separated in name_value
        for part in re.split(r"[\n,;]+", str(fld)):
            n = part.strip().lower().rstrip(".")
            if n and n not in seen:
                seen[n] = None
    return list(seen.keys())


def _cert_from_obj(obj: dict) -> Certificate:
    names = _split_names(
        obj.get("name_value", ""),
        obj.get("common_name", ""),
        obj.get("dns_names", ""),
        obj.get("subject", ""),
    )
    if isinstance(obj.get("dns_names"), list):
        names = _split_names("\n".join(obj["dns_names"]), *names)
    issuer = str(
        obj.get("issuer_name")
        or obj.get("issuer_ca_id")
        and obj.get("issuer", "")
        or obj.get("issuer", "")
    ).strip()
    return Certificate(
        names=names,
        issuer=issuer,
        not_before=_parse_dt(obj.get("not_before") or obj.get("notBefore")),
        not_after=_parse_dt(obj.get("not_after") or obj.get("notAfter")),
        serial=str(obj.get("serial_number") or obj.get("serial") or ""),
        log_id=str(obj.get("log_id") or ""),
        raw_id=str(obj.get("id") or obj.get("min_cert_id") or ""),
    )


def parse_export(text: str) -> list[Certificate]:
    """Parse a CT export string (JSON array, JSONL, or CSV) into Certificates."""
    text = text.strip()
    if not text:
        return []

    # Try JSON (array or single object) first.
    if text[0] in "[{":
        try:
            data = json.loads(text)
            if isinstance(data, dict):
                data = [data]
            return [_cert_from_obj(o) for o in data if isinstance(o, dict)]
        except json.JSONDecodeError:
            pass

    # Try JSON Lines.
    lines = [ln for ln in text.splitlines() if ln.strip()]
    if lines and lines[0].lstrip().startswith("{"):
        certs: list[Certificate] = []
        ok = True
        for ln in lines:
            try:
                certs.append(_cert_from_obj(json.loads(ln)))
            except json.JSONDecodeError:
                ok = False
                break
        if ok:
            return certs

    # Fall back to CSV.
    reader = csv.DictReader(io.StringIO(text))
    return [_cert_from_obj(row) for row in reader]


# --------------------------------------------------------------------------
# Analysis
# --------------------------------------------------------------------------

def _is_under(name: str, base: str) -> bool:
    name = name.lstrip("*.").rstrip(".")
    return name == base or name.endswith("." + base)


def _valid_hostname(name: str) -> bool:
    host = name.lstrip("*.").rstrip(".")
    if not host or len(host) > 253:
        return False
    return all(_LABEL_RE.match(lbl) for lbl in host.split("."))


def _looks_like_phish(name: str, base: str) -> str | None:
    """Detect lookalike domains that embed the owned brand but are NOT under it."""
    host = name.lstrip("*.").rstrip(".")
    if _is_under(host, base):
        return None
    brand = base.split(".")[0]
    if len(brand) < 4:
        return None
    if brand in host.replace("-", "").replace(".", ""):
        return f"external hostname embeds brand '{brand}' but is not under {base}"
    return None


def analyze(certs: Iterable[Certificate], base_domain: str) -> AnalysisResult:
    base = base_domain.strip().lower().lstrip("*.").rstrip(".")
    res = AnalysisResult(base_domain=base)
    certs = list(certs)
    res.total_certs = len(certs)

    subs: dict[str, None] = {}
    wilds: dict[str, None] = {}
    now = datetime.now(timezone.utc)

    for cert in certs:
        if cert.issuer:
            res.issuers[cert.issuer] = res.issuers.get(cert.issuer, 0) + 1

        owned_here = [n for n in cert.names if _is_under(n, base)]

        for name in cert.names:
            if _is_under(name, base):
                if name.startswith("*."):
                    wilds.setdefault(name, None)
                else:
                    subs.setdefault(name, None)

            # Lookalike / brand-abuse detection (external names).
            phish = _looks_like_phish(name, base)
            if phish:
                res.findings.append(Finding(
                    "critical", "lookalike", name, phish, cert))

        if not owned_here:
            continue  # cert unrelated to our base domain

        # --- per-cert checks on owned names ---

        # Unknown / unexpected issuer for an owned cert -> possible rogue issuance.
        iss_l = cert.issuer.lower()
        if cert.issuer and not any(h in iss_l for h in _COMMON_CA_HINTS):
            res.findings.append(Finding(
                "high", "unknown_issuer", owned_here[0],
                f"certificate for owned name issued by unrecognized CA "
                f"'{cert.issuer}'", cert))

        # Expired or not-yet-valid certs still appearing in logs.
        if cert.not_after and cert.not_after < now:
            res.findings.append(Finding(
                "low", "expired", owned_here[0],
                f"certificate expired on {cert.not_after.date()}", cert))

        # Suspiciously short validity from a free CA on a sensitive sub.
        for name in owned_here:
            label = name.lstrip("*.").split(".")[0].lower()
            if label in _PHISH_TOKENS and any(h in iss_l for h in _FREE_CA_HINTS):
                res.findings.append(Finding(
                    "medium", "sensitive_subdomain", name,
                    f"sensitive subdomain '{label}' certificate from free CA "
                    f"'{cert.issuer}' — confirm this is yours", cert))

        # Malformed hostnames in an owned cert -> possible mis-issuance.
        for name in owned_here:
            if not _valid_hostname(name):
                res.findings.append(Finding(
                    "medium", "malformed_name", name,
                    "malformed hostname present in certificate", cert))

    res.subdomains = sorted(subs)
    res.wildcards = sorted(wilds)

    # Newly-seen wildcard for the apex is worth flagging as info.
    if ("*." + base) in wilds:
        res.findings.append(Finding(
            "info", "apex_wildcard", "*." + base,
            "apex wildcard certificate present — verify it is intentional"))

    res.findings.sort(key=lambda f: (SEVERITY_ORDER[f.severity], f.name))
    return res
