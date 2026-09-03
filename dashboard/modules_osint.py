"""Hermes Security Workbench — OSINT modules.

Passive, stdlib-only public lookups. Runners are async `(target, params) ->
list[findings]` matching the registry contract. No external binaries, no API
keys, no aggressive scanning. All network calls bounded by short timeouts.
"""
from __future__ import annotations

import json
import urllib.error
import urllib.request
from typing import Any, Dict, List

_USER_AGENT = "HermesSecurityWorkbench/0.1 (+local research)"


def _get_json(url: str, timeout: float = 5.0) -> Any:
    req = urllib.request.Request(url, headers={"User-Agent": _USER_AGENT})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8", "replace"))


def _err(t: str, msg: str, source: str) -> Dict[str, Any]:
    return {
        "finding_type": f"{t}_error",
        "value": msg,
        "confidence": 0.1,
        "severity": "info",
        "source": source,
        "evidence": {},
        "raw": {},
    }


async def _run_ip_geolocation(target: str, params: Dict[str, Any]) -> List[Dict[str, Any]]:
    url = f"http://ip-api.com/json/{target}?fields=status,country,regionName,city,isp,org,as,lat,lon,timezone"
    try:
        data = _get_json(url, timeout=params.get("timeout", 5.0))
    except (urllib.error.URLError, urllib.error.HTTPError, Exception) as exc:  # noqa: BLE001
        return [_err("geo", f"request failed: {exc}", "ip-api.com")]
    if not isinstance(data, dict) or data.get("status") != "success":
        return [_err("geo", "lookup did not return success", "ip-api.com")]
    city = data.get("city", "")
    region = data.get("regionName", "")
    country = data.get("country", "")
    loc = ", ".join(x for x in (city, region, country) if x)
    return [{
        "finding_type": "geo_location",
        "value": loc,
        "confidence": 0.9,
        "severity": "info",
        "source": "ip-api.com",
        "evidence": {
            "ip": target, "country": country, "regionName": region, "city": city,
            "isp": data.get("isp"), "org": data.get("org"), "as": data.get("as"),
            "lat": data.get("lat"), "lon": data.get("lon"), "timezone": data.get("timezone"),
        },
        "raw": data,
    }]


async def _run_domain_whois(target: str, params: Dict[str, Any]) -> List[Dict[str, Any]]:
    url = f"https://rdap.org/domain/{target}"
    try:
        data = _get_json(url, timeout=params.get("timeout", 5.0))
    except (urllib.error.URLError, urllib.error.HTTPError, Exception) as exc:  # noqa: BLE001
        return [_err("whois", f"request failed: {exc}", "rdap.org")]
    if not isinstance(data, dict):
        return [_err("whois", "invalid RDAP response", "rdap.org")]
    out: List[Dict[str, Any]] = []

    def _entity_role(role: str):
        for e in data.get("entities", []):
            roles = [r.lower() for r in e.get("roles", [])]
            vcard = e.get("vcardArray", [])
            if role in roles and isinstance(vcard, list) and len(vcard) > 1:
                for item in vcard[1]:
                    if item and item[0] == "fn" and len(item) >= 3:
                        return str(item[3])
        return None

    registrar = _entity_role("registrar")
    if registrar:
        out.append({
            "finding_type": "whois_registrar", "value": registrar, "confidence": 0.85,
            "severity": "info", "source": "rdap.org",
            "evidence": {"registrar": registrar}, "raw": data,
        })

    created = (data.get("events") or [{}])
    for ev in created:
        if ev.get("eventAction") == "registration":
            out.append({
                "finding_type": "whois_created", "value": ev.get("eventDate", ""),
                "confidence": 0.85, "severity": "info", "source": "rdap.org",
                "evidence": {"created": ev.get("eventDate", "")}, "raw": data,
            })
            break

    ns = [n.get("ldhName") for n in data.get("nameservers", []) if n.get("ldhName")]
    if ns:
        out.append({
            "finding_type": "whois_nameservers", "value": ", ".join(ns),
            "confidence": 0.85, "severity": "info", "source": "rdap.org",
            "evidence": {"nameservers": ns}, "raw": data,
        })
    return out


MODULES: List[Dict[str, Any]] = [
    {
        "name": "ip_geolocation",
        "category": "osint",
        "description": "Public IP geolocation metadata from a passive JSON endpoint (ip-api.com).",
        "risk_level": "PASSIVE",
        "network_activity": True,
        "input_types": ["ip"],
        "output_types": ["finding"],
        "runner": _run_ip_geolocation,
    },
    {
        "name": "domain_whois",
        "category": "osint",
        "description": "Passive WHOIS-style domain registration info via a public RDAP endpoint.",
        "risk_level": "PASSIVE",
        "network_activity": True,
        "input_types": ["domain"],
        "output_types": ["finding"],
        "runner": _run_domain_whois,
    },
]
