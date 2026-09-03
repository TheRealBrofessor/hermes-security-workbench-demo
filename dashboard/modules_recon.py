"""Hermes Security Workbench — recon modules.

Each module is a self-contained entry in MODULES matching the registry contract
in plugin_api.py (name, category, description, risk_level, ... runner). Runners
are async functions `(target, params) -> list[findings]`. All passive / DNS-based.
"""
from __future__ import annotations

from typing import Any, Dict, List

import dns.exception
import dns.reversename
import dns.resolver

_DEFAULT_SUBDOMAINS = [
    "www", "mail", "ftp", "admin", "api", "blog", "dev", "test",
    "staging", "vpn", "remote", "mx", "ns1", "ns2", "pop",
]

_resolver = dns.resolver.Resolver()
_resolver.lifetime = 5.0
_resolver.timeout = 5.0


def _ok(rtype: str, target: str, value: str, extra: Dict[str, Any] | None = None) -> Dict[str, Any]:
    return {
        "finding_type": rtype,
        "value": value,
        "confidence": 0.85,
        "severity": "info",
        "source": "dnspython",
        "evidence": {"type": rtype, "target": target, **(extra or {})},
        "raw": {},
    }


async def _run_dns_lookup(target: str, params: Dict[str, Any]) -> List[Dict[str, Any]]:
    rtypes = params.get("types", "A,AAAA,MX,NS,TXT,CNAME")
    out: List[Dict[str, Any]] = []
    for rtype in (r.strip().upper() for r in str(rtypes).split(",")):
        if not rtype:
            continue
        try:
            answers = _resolver.resolve(target, rtype)
            for ans in answers:
                out.append(_ok(f"dns_{rtype}", target, str(ans)))
        except dns.resolver.NoAnswer:
            continue
        except (dns.exception.DNSException, Exception):  # noqa: BLE001
            out.append(_ok("dns_error", target, f"{rtype}: query failed", {"rtype": rtype}))
    return out


async def _run_subdomain_enum(target: str, params: Dict[str, Any]) -> List[Dict[str, Any]]:
    words = params.get("wordlist") or _DEFAULT_SUBDOMAINS
    out: List[Dict[str, Any]] = []
    for word in words:
        host = f"{word}.{target}"
        try:
            answers = _resolver.resolve(host, "A")
            ips = [str(a) for a in answers]
            out.append(_ok("subdomain", host, host, {"ip": ips}))
        except (dns.exception.DNSException, Exception):  # noqa: BLE001
            continue
    return out


async def _run_reverse_dns(target: str, params: Dict[str, Any]) -> List[Dict[str, Any]]:
    try:
        rev = dns.reversename.from_address(target)
        answers = _resolver.resolve(rev, "PTR")
        return [_ok("ptr", target, str(a), {"ip": target}) for a in answers]
    except (dns.exception.DNSException, Exception):  # noqa: BLE001
        return [_ok("ptr_error", target, "reverse lookup failed", {"ip": target})]


async def _run_whois_lookup(target: str, params: Dict[str, Any]) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    for rtype in ("SOA", "NS"):
        try:
            answers = _resolver.resolve(target, rtype)
            for ans in answers:
                out.append(_ok(rtype.lower(), target, str(ans)))
        except (dns.exception.DNSException, Exception):  # noqa: BLE001
            out.append(_ok("dns_error", target, f"{rtype}: query failed", {"rtype": rtype}))
    return out


MODULES: List[Dict[str, Any]] = [
    {
        "name": "dns_lookup",
        "category": "recon",
        "description": "Resolve A, AAAA, MX, NS, TXT, CNAME records for a domain.",
        "risk_level": "PASSIVE",
        "network_activity": True,
        "input_types": ["domain"],
        "output_types": ["finding"],
        "runner": _run_dns_lookup,
    },
    {
        "name": "subdomain_enum",
        "category": "recon",
        "description": "Enumerate subdomains from a built-in wordlist via DNS A lookups.",
        "risk_level": "PASSIVE",
        "network_activity": True,
        "input_types": ["domain"],
        "output_types": ["finding"],
        "runner": _run_subdomain_enum,
    },
    {
        "name": "reverse_dns",
        "category": "recon",
        "description": "PTR reverse-DNS lookup for an IP.",
        "risk_level": "PASSIVE",
        "network_activity": True,
        "input_types": ["ip"],
        "output_types": ["finding"],
        "runner": _run_reverse_dns,
    },
    {
        "name": "whois_lookup",
        "category": "recon",
        "description": "Minimal passive WHOIS-style domain info via SOA/NS records (no external binary).",
        "risk_level": "PASSIVE",
        "network_activity": True,
        "input_types": ["domain"],
        "output_types": ["finding"],
        "runner": _run_whois_lookup,
    },
]
