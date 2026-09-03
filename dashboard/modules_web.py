"""Hermes Security Workbench — web analysis modules.

Passive / safe-active HTTP analysis: headers, technology fingerprinting, and
link extraction. All network calls bounded, no external binaries, no
credentials. Matches the MODULES registry contract in plugin_api.py.
"""
from __future__ import annotations

import re
import ssl
import urllib.error
import urllib.request
from typing import Any, Dict, List

_USER_AGENT = "HermesSecurityWorkbench/0.1 (+local research)"
_TIMEOUT = 8.0

# Technology fingerprint: header patterns.
_HEADER_SIGNS: Dict[str, List[tuple]] = {
    "nginx": [("server", "nginx")],
    "apache": [("server", "apache")],
    "iis": [("server", "microsoft-iis"), ("server", "iis")],
    "cloudflare": [("server", "cloudflare")],
    "wordpress": [("x-powered-by", "php"), ("link", "wp-json")],
    "drupal": [("x-generator", "drupal")],
    "jquery": [("x-powered-by", "jquery")],
}

_BODY_TECH_RE = {
    "wordpress": re.compile(r"wp-content|wp-includes", re.I),
    "drupal": re.compile(r"/sites/default/files|drupal\.settings", re.I),
    "react": re.compile(r"__NEXT_DATA__|_reactroot|data-reactroot", re.I),
    "next.js": re.compile(r"__NEXT_DATA__", re.I),
    "bootstrap": re.compile(r"bootstrap(?:\.min)?\.css|bootstrap(?:\.min)?\.js", re.I),
}

_LINK_RE = re.compile(r'href\s*=\s*["\']([^"\']+)["\']', re.I)


def _open(url: str, timeout: float = _TIMEOUT):
    req = urllib.request.Request(url, headers={"User-Agent": _USER_AGENT})
    return urllib.request.urlopen(req, timeout=timeout)


def _normalize_url(target: str) -> str:
    if not target.startswith(("http://", "https://")):
        return "https://" + target
    return target


def _err(t: str, msg: str, source: str = "web") -> Dict[str, Any]:
    return {
        "finding_type": f"{t}_error",
        "value": msg,
        "confidence": 0.1,
        "severity": "info",
        "source": source,
        "evidence": {},
        "raw": {},
    }


async def _run_http_headers(target: str, params: Dict[str, Any]) -> List[Dict[str, Any]]:
    url = _normalize_url(target)
    try:
        resp = _open(url, timeout=params.get("timeout", _TIMEOUT))
    except (urllib.error.URLError, urllib.error.HTTPError, Exception) as exc:  # noqa: BLE001
        return [_err("http", f"request failed: {exc}")]
    headers = dict(resp.headers.items())
    out: List[Dict[str, Any]] = [{
        "finding_type": "http_status",
        "value": str(resp.status),
        "confidence": 1.0,
        "severity": "info",
        "source": "urllib",
        "evidence": {"status": resp.status, "url": url},
        "raw": headers,
    }]
    server = headers.get("Server") or headers.get("server")
    if server:
        out.append({
            "finding_type": "server_banner",
            "value": server,
            "confidence": 0.9,
            "severity": "info",
            "source": "urllib",
            "evidence": {"header": "Server", "url": url},
            "raw": headers,
        })
    for k in ("X-Powered-By", "X-AspNet-Version", "Via", "X-Generator"):
        v = headers.get(k)
        if v:
            out.append({
                "finding_type": "http_header",
                "value": v,
                "confidence": 0.9,
                "severity": "info",
                "source": "urllib",
                "evidence": {"header": k, "url": url},
                "raw": headers,
            })
    cookies = resp.headers.get_all("Set-Cookie") or []
    for c in cookies:
        out.append({
            "finding_type": "cookie",
            "value": c.split(";")[0],
            "confidence": 0.9,
            "severity": "low",
            "source": "urllib",
            "evidence": {"url": url, "set_cookie": c},
            "raw": headers,
        })
    resp.close()
    return out


async def _run_tech_detect(target: str, params: Dict[str, Any]) -> List[Dict[str, Any]]:
    url = _normalize_url(target)
    resp = None
    try:
        resp = _open(url, timeout=params.get("timeout", _TIMEOUT))
        headers = dict(resp.headers.items())
        body = resp.read(300_000).decode("utf-8", "replace")
    except (urllib.error.URLError, urllib.error.HTTPError, Exception) as exc:  # noqa: BLE001
        return [_err("tech", f"request failed: {exc}")]
    finally:
        if resp is not None:
            try:
                resp.close()
            except Exception:  # noqa: BLE001
                pass

    out: List[Dict[str, Any]] = []
    low = {k.lower(): v for k, v in headers.items()}

    def _add(name: str, evidence: str):
        out.append({
            "finding_type": "tech",
            "value": name,
            "confidence": 0.75,
            "severity": "info",
            "source": "fingerprint",
            "evidence": {"url": url, "matched": evidence},
            "raw": {},
        })

    for tech, sigs in _HEADER_SIGNS.items():
        for header, pattern in sigs:
            hv = low.get(header, "")
            if hv and pattern.lower() in hv.lower():
                _add(tech, f"header {header}={hv}")
                break
    for tech, rx in _BODY_TECH_RE.items():
        if rx.search(body):
            _add(tech, "body pattern")
    return out


async def _run_link_extractor(target: str, params: Dict[str, Any]) -> List[Dict[str, Any]]:
    url = _normalize_url(target)
    resp = None
    try:
        resp = _open(url, timeout=params.get("timeout", _TIMEOUT))
        body = resp.read(500_000).decode("utf-8", "replace")
    except (urllib.error.URLError, urllib.error.HTTPError, Exception) as exc:  # noqa: BLE001
        return [_err("link", f"request failed: {exc}")]
    finally:
        if resp is not None:
            try:
                resp.close()
            except Exception:  # noqa: BLE001
                pass

    from urllib.parse import urljoin
    out: List[Dict[str, Any]] = []
    seen = set()
    for m in _LINK_RE.finditer(body):
        href = m.group(1)
        if href.startswith(("#", "javascript:", "mailto:")):
            continue
        full = urljoin(url, href)
        if full in seen:
            continue
        seen.add(full)
        out.append({
            "finding_type": "link",
            "value": full,
            "confidence": 0.9,
            "severity": "info",
            "source": "urllib",
            "evidence": {"url": url, "href": href},
            "raw": {},
        })
        if len(out) >= 200:
            break
    return out


MODULES: List[Dict[str, Any]] = [
    {
        "name": "http_headers",
        "category": "web",
        "description": "Fetch HTTP response metadata: status, server banner, key headers, cookies.",
        "risk_level": "SAFE ACTIVE",
        "network_activity": True,
        "input_types": ["url", "domain"],
        "output_types": ["finding"],
        "runner": _run_http_headers,
    },
    {
        "name": "tech_detect",
        "category": "web",
        "description": "Passive technology fingerprinting from HTTP headers and page body.",
        "risk_level": "SAFE ACTIVE",
        "network_activity": True,
        "input_types": ["url", "domain"],
        "output_types": ["finding"],
        "runner": _run_tech_detect,
    },
    {
        "name": "link_extractor",
        "category": "web",
        "description": "Extract hyperlinks from a web page.",
        "risk_level": "SAFE ACTIVE",
        "network_activity": True,
        "input_types": ["url", "domain"],
        "output_types": ["finding"],
        "runner": _run_link_extractor,
    },
]
