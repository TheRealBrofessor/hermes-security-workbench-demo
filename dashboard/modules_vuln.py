"""Hermes Security Workbench — vulnerability scanning modules.

Active vulnerability detection modules. These require scope authorization
(SAFE ACTIVE or AUTHORIZED ACTIVE risk levels). All runners are async
`(target, params) -> list[findings]` matching the registry contract.
"""
from __future__ import annotations

import asyncio
import re
import ssl
import uuid
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Dict, List, Optional

try:
    from bs4 import BeautifulSoup
    HAS_BS4 = True
except ImportError:
    HAS_BS4 = False

_USER_AGENT = "HermesSecurityWorkbench/1.0 (+local research)"
_TIMEOUT = 10.0
_MAX_REDIRECTS = 3
_RATE_LIMIT_DELAY = 0.5  # 2 req/sec default

# --- XSS Hunter Implementation ---

_PROBE_PREFIX = "KKM_PROBE_"
_HTML_TEST_PAYLOAD = "<kkm-test>probe</kkm-test>"

ESCALATION_PAYLOADS = [
    # onerror - auto-execution, high confidence
    ('<img src=x onerror=alert(1)>', 'onerror'),
    ('<svg onerror=alert(1)>', 'onerror'),
    # onload - auto-execution, high confidence
    ('<img src=x onload=alert(1)>', 'onload'),
    ('<svg onload=alert(1)>', 'onload'),
    ('<iframe src=x onload=alert(1)>', 'onload'),
    # onfocus - autofocus triggers immediately
    ('<input onfocus=alert(1) autofocus>', 'onfocus'),
    ('<svg onfocus=alert(1) autofocus>', 'onfocus'),
    # onmouseover - requires interaction
    ('<div onmouseover=alert(1)>hover</div>', 'onmouseover'),
    ('<img src=x onmouseover=alert(1)>', 'onmouseover'),
]

_PARAM_PATTERNS = [
    'q', 'query', 'search', 's', 'keyword', 'term',
    'id', 'item', 'product', 'page', 'view',
    'url', 'link', 'redirect', 'next', 'return',
    'file', 'path', 'doc', 'download',
    'name', 'email', 'message', 'comment', 'feedback',
    'callback', 'jsonp', 'data', 'input', 'value',
]

_HTML_FORM_INPUT_TYPES = {'text', 'search', 'email', 'url', 'textarea', 'password', 'hidden'}


def _normalize_url(target: str) -> str:
    if not target.startswith(('http://', 'https://')):
        return 'https://' + target
    return target


def _make_request(url: str, method: str = 'GET', data: bytes = None, headers: Dict = None, timeout: float = _TIMEOUT) -> Optional[urllib.request.urlopen]:
    req_headers = {'User-Agent': _USER_AGENT}
    if headers:
        req_headers.update(headers)
    req = urllib.request.Request(url, data=data, headers=req_headers, method=method)
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    try:
        return urllib.request.urlopen(req, timeout=timeout, context=context)
    except Exception:
        return None


async def _http_get(url: str, timeout: float = _TIMEOUT) -> Optional[Dict]:
    """Async wrapper for GET request. Returns {url, status, headers, body} or None."""
    loop = asyncio.get_event_loop()
    resp = await loop.run_in_executor(None, _make_request, url, 'GET', None, None, timeout)
    if resp is None:
        return None
    try:
        body = resp.read(500_000).decode('utf-8', 'replace')
        headers = dict(resp.headers.items())
        status = resp.status
        final_url = str(resp.geturl())
        resp.close()
        return {'url': final_url, 'status': status, 'headers': headers, 'body': body}
    except Exception:
        return None


async def _http_post(url: str, data: Dict, timeout: float = _TIMEOUT) -> Optional[Dict]:
    """Async wrapper for POST request."""
    encoded = urllib.parse.urlencode(data).encode('utf-8')
    headers = {'Content-Type': 'application/x-www-form-urlencoded'}
    loop = asyncio.get_event_loop()
    resp = await loop.run_in_executor(None, _make_request, url, 'POST', encoded, headers, timeout)
    if resp is None:
        return None
    try:
        body = resp.read(500_000).decode('utf-8', 'replace')
        headers = dict(resp.headers.items())
        status = resp.status
        final_url = str(resp.geturl())
        resp.close()
        return {'url': final_url, 'status': status, 'headers': headers, 'body': body}
    except Exception:
        return None


def _extract_url_params(url: str) -> List[str]:
    parsed = urllib.parse.urlparse(url)
    return list(urllib.parse.parse_qs(parsed.query).keys())


def _extract_forms(html: str, base_url: str) -> List[Dict]:
    if not HAS_BS4:
        return []
    soup = BeautifulSoup(html, 'html.parser')
    forms = []
    for form in soup.find_all('form'):
        action = form.get('action', base_url)
        if not action.startswith(('http://', 'https://')):
            action = urllib.parse.urljoin(base_url, action)
        method = form.get('method', 'GET').upper()
        enctype = form.get('enctype', 'application/x-www-form-urlencoded')
        inputs = []
        for inp in form.find_all(['input', 'textarea', 'select']):
            name = inp.get('name')
            itype = inp.get('type', 'text')
            if name and itype not in ('submit', 'button', 'image', 'reset', 'hidden'):
                inputs.append({'name': name, 'type': itype})
        if inputs:
            forms.append({'action': action, 'method': method, 'enctype': enctype, 'inputs': inputs})
    return forms


def _find_reflection_context(body: str, probe: str) -> str:
    """Determine where the probe appears in the response."""
    idx = body.find(probe)
    if idx == -1:
        return 'none'
    window = body[max(0, idx - 200):idx + 200]
    # Inside attribute value
    if re.search(r'=\s*[\'"][^\'"]*$', window):
        return 'html_attribute'
    # Inside script tag
    before = body[:idx]
    after = body[idx:]
    if '<script' in before.split('<script')[-1] and '</script>' not in after.split('</script>')[0]:
        return 'javascript'
    # Inside HTML text
    return 'html_text'


def _generate_probe() -> str:
    return _PROBE_PREFIX + uuid.uuid4().hex[:12]


async def _test_parameter(target: str, param: str, payload: str, method: str = 'GET', form_data: Dict = None) -> Optional[Dict]:
    """Test a single parameter with a payload. Returns reflection info or None."""
    if method == 'GET':
        parsed = urllib.parse.urlparse(target)
        query = urllib.parse.parse_qs(parsed.query)
        query[param] = [payload]
        new_query = urllib.parse.urlencode(query, doseq=True)
        test_url = urllib.parse.urlunparse(parsed._replace(query=new_query))
        resp = await _http_get(test_url)
    else:
        data = form_data.copy() if form_data else {}
        data[param] = payload
        resp = await _http_post(target, data)
    
    if resp and payload in resp['body']:
        context = _find_reflection_context(resp['body'], payload)
        return {
            'reflected': True,
            'context': context,
            'response': resp,
            'payload': payload
        }
    return None


async def _run_xss_hunter(target: str, params: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    XSS Hunter module runner.
    
    Params:
    - timeout: request timeout (default 10)
    - max_params: max parameters to test (default 20)
    - rate_limit: requests per second (default 2)
    - test_headers: also test header reflection (default false)
    """
    timeout = float(params.get('timeout', _TIMEOUT))
    max_params = int(params.get('max_params', 20))
    rate_limit = float(params.get('rate_limit', 2.0))
    test_headers = bool(params.get('test_headers', False))
    
    delay = 1.0 / max(rate_limit, 0.1)
    findings = []
    target = _normalize_url(target)
    
    # Phase 1: Fetch and check content-type
    initial = await _http_get(target, timeout)
    if not initial:
        return [{
            'finding_type': 'xss_error',
            'value': 'Failed to fetch target',
            'confidence': 0.1,
            'severity': 'info',
            'source': 'xss-hunter',
            'evidence': {'target': target},
            'raw': {}
        }]
    
    content_type = initial['headers'].get('Content-Type', initial['headers'].get('content-type', '')).lower()
    if 'text/html' not in content_type:
        return [{
            'finding_type': 'lead_non_html_endpoint',
            'value': f'Non-HTML content-type: {content_type}',
            'confidence': 0.5,
            'severity': 'info',
            'source': 'xss-hunter',
            'evidence': {'target': target, 'content_type': content_type, 'status': initial['status']},
            'raw': {'headers': initial['headers']}
        }]
    
    # Phase 2: Discover injection points
    test_params = []
    
    # URL parameters
    url_params = _extract_url_params(target)
    for p in url_params[:max_params]:
        test_params.append({'param': p, 'method': 'GET', 'source': 'url'})
    
    # Form inputs
    forms = _extract_forms(initial['body'], target)
    for form in forms:
        for inp in form['inputs']:
            if len(test_params) >= max_params:
                break
            test_params.append({
                'param': inp['name'],
                'method': form['method'],
                'source': 'form',
                'form_action': form['action'],
                'form_enctype': form['enctype'],
                'form_data': {i['name']: '' for i in form['inputs']}
            })
        if len(test_params) >= max_params:
            break
    
    # Common parameter names (if no params found)
    if not test_params:
        for p in _PARAM_PATTERNS[:max_params]:
            test_params.append({'param': p, 'method': 'GET', 'source': 'common'})
    
    # Phase 3: Reflection test with benign probe
    reflected_params = []
    for tp in test_params:
        probe = _generate_probe()
        method = tp['method']
        form_data = tp.get('form_data')
        test_target = tp.get('form_action', target)
        
        result = await _test_parameter(test_target, tp['param'], probe, method, form_data)
        if result and result['reflected']:
            reflected_params.append({
                **tp,
                'probe': probe,
                'context': result['context'],
                'response': result['response']
            })
        
        await asyncio.sleep(delay)
    
    if not reflected_params:
        return [{
            'finding_type': 'lead_no_reflection',
            'value': 'No parameters reflected benign probe',
            'confidence': 0.3,
            'severity': 'info',
            'source': 'xss-hunter',
            'evidence': {'target': target, 'tested_params': len(test_params)},
            'raw': {}
        }]
    
    # Phase 4: HTML injection confirmation
    html_injection_points = []
    for rp in reflected_params:
        method = rp['method']
        form_data = rp.get('form_data')
        test_target = rp.get('form_action', target)
        
        result = await _test_parameter(test_target, rp['param'], _HTML_TEST_PAYLOAD, method, form_data)
        if result and result['reflected'] and '<kkm-test>' in result['response']['body']:
            # Verify it's unencoded
            if '<kkm-test>' in result['response']['body']:
                html_injection_points.append({
                    **rp,
                    'html_payload': _HTML_TEST_PAYLOAD,
                    'html_response': result['response']
                })
        
        await asyncio.sleep(delay)
    
    if not html_injection_points:
        return [{
            'finding_type': 'lead_reflection_encoded',
            'value': f'Reflection found but HTML encoded ({len(reflected_params)} params)',
            'confidence': 0.4,
            'severity': 'info',
            'source': 'xss-hunter',
            'evidence': {
                'target': target,
                'reflected_params': [{'param': r['param'], 'context': r['context']} for r in reflected_params]
            },
            'raw': {}
        }]
    
    # Phase 5: Escalation via event handlers
    for hip in html_injection_points:
        method = hip['method']
        form_data = hip.get('form_data')
        test_target = hip.get('form_action', target)
        param = hip['param']
        
        for payload, handler in ESCALATION_PAYLOADS:
            result = await _test_parameter(test_target, param, payload, method, form_data)
            if result and result['reflected']:
                # Determine confidence based on handler
                confidence = 0.9 if handler in ('onerror', 'onload') else 0.75
                if handler in ('onmouseover', 'onfocus'):
                    confidence = 0.7  # requires interaction
                
                findings.append({
                    'finding_type': 'xss_reflected',
                    'value': f'{param} parameter - {handler} handler',
                    'confidence': confidence,
                    'severity': 'high' if confidence >= 0.85 else 'medium',
                    'source': 'xss-hunter',
                    'evidence': {
                        'url': test_target,
                        'parameter': param,
                        'method': method,
                        'content_type': content_type,
                        'reflection_context': hip['context'],
                        'probe_token': hip['probe'],
                        'html_injection_payload': _HTML_TEST_PAYLOAD,
                        'xss_payload': payload,
                        'working_handler': handler,
                        'escalation_confidence': confidence,
                    },
                    'raw': {
                        'probe_response': hip['response']['body'][:5000],
                        'xss_response': result['response']['body'][:5000],
                    }
                })
                break  # First working handler wins
            
            await asyncio.sleep(delay)
    
    if not findings:
        return [{
            'finding_type': 'lead_html_injection_no_xss',
            'value': f'HTML injection confirmed but no executable handler ({len(html_injection_points)} points)',
            'confidence': 0.5,
            'severity': 'info',
            'source': 'xss-hunter',
            'evidence': {
                'target': target,
                'injection_points': [
                    {'param': h['param'], 'context': h['context']} for h in html_injection_points
                ]
            },
            'raw': {}
        }]
    
    return findings


MODULES: List[Dict[str, Any]] = [
    {
        'name': 'xss_hunter',
        'category': 'vuln_scan',
        'description': 'Content-type gated XSS hunting: reflection probe -> HTML injection -> event handler escalation. Implements methodology from video.',
        'risk_level': 'SAFE ACTIVE',
        'network_activity': True,
        'requires_root': False,
        'dependencies': ['bs4'],
        'input_types': ['url', 'domain'],
        'output_types': ['finding'],
        'supports_cancel': True,
        'enabled_by_default': True,
        'runner': _run_xss_hunter,
    },
]