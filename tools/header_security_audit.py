import time

import requests

try:
    from latest_user_agents import get_random_user_agent

    UA = get_random_user_agent()
    if not isinstance(UA, str):
        UA = "Mozilla/5.0"
except (ImportError, Exception):
    UA = "Mozilla/5.0"


RECOMMENDATIONS = {
    "strict-transport-security": "Enable HSTS with long max-age and includeSubDomains.",
    "content-security-policy": "Implement a strict Content-Security-Policy.",
    "x-frame-options": "Set X-Frame-Options to DENY or SAMEORIGIN.",
    "x-content-type-options": "Set X-Content-Type-Options to nosniff.",
    "referrer-policy": "Use a strict Referrer-Policy.",
    "permissions-policy": "Restrict browser feature usage via Permissions-Policy.",
}

REQUIRED_HEADERS = {
    "strict-transport-security": "Missing HSTS header",
    "content-security-policy": "Missing CSP header",
    "x-frame-options": "Missing clickjacking protection",
    "x-content-type-options": "Missing MIME sniffing protection",
    "referrer-policy": "Missing referrer policy",
    "permissions-policy": "Missing permissions policy",
}

def add_finding(findings, severity, ftype, issue, header=None, evidence=None, recommendation=None):
    findings.append({
        "severity": severity,
        "type": ftype,
        "header": header,
        "issue": issue,
        "evidence": evidence,
        "recommendation": recommendation,
    })

def analyze_required_headers(headers, findings):
    for header, issue in REQUIRED_HEADERS.items():
        if header not in headers:
            add_finding(
                findings,
                "medium",
                "missing_header",
                issue,
                header=header,
                recommendation=RECOMMENDATIONS.get(header),
            )

def analyze_hsts(headers, findings):
    hsts = headers.get("strict-transport-security")
    if not hsts:
        return
    low = hsts.lower()
    if "max-age=0" in low:
        add_finding(
            findings,
            "high",
            "weak_hsts",
            "HSTS disabled (max-age=0)",
            header="strict-transport-security",
            evidence=hsts,
            recommendation="Use a positive max-age (e.g. >= 31536000).",
        )
    if "includesubdomains" not in low:
        add_finding(
            findings,
            "low",
            "weak_hsts",
            "HSTS missing includeSubDomains",
            header="strict-transport-security",
            evidence=hsts,
            recommendation="Add includeSubDomains directive.",
        )

def analyze_csp(headers, findings):
    csp = headers.get("content-security-policy")
    if not csp:
        return
    low = csp.lower()
    issues = [
        ("unsafe-inline", "unsafe-inline enabled"),
        ("unsafe-eval", "unsafe-eval enabled"),
        ("data:", "data: scheme allowed"),
        ("*", "Wildcard policy detected"),
    ]
    for token, msg in issues:
        if token in low:
            add_finding(
                findings,
                "high",
                "weak_csp",
                msg,
                header="content-security-policy",
                evidence=csp,
                recommendation="Harden CSP directives.",
            )

def analyze_cookies(response, findings):
    cookies = response.cookies
    for cookie in cookies:
        if not cookie.secure:
            add_finding(
                findings,
                "medium",
                "insecure_cookie",
                f"Cookie '{cookie.name}' missing Secure flag",
                header="set-cookie",
                evidence=str(cookie),
                recommendation="Add Secure flag.",
            )
        if cookie._rest.get("HttpOnly") is None:
            add_finding(
                findings,
                "high",
                "insecure_cookie",
                f"Cookie '{cookie.name}' missing HttpOnly flag",
                header="set-cookie",
                evidence=str(cookie),
                recommendation="Add HttpOnly flag.",
            )

def analyze_cors(headers, findings):
    origin = headers.get("access-control-allow-origin")
    creds = headers.get("access-control-allow-credentials")
    if origin == "*" and creds == "true":
        add_finding(
            findings,
            "high",
            "dangerous_cors",
            "Wildcard CORS with credentials enabled",
            header="access-control-allow-origin",
            evidence=f"{origin} + credentials=true",
            recommendation="Restrict allowed origins.",
        )

def analyze_disclosure(headers, findings):
    if "server" in headers:
        add_finding(
            findings,
            "low",
            "server_disclosure",
            "Server header exposed",
            header="server",
            evidence=headers["server"],
            recommendation="Hide server header.",
        )
    if "x-powered-by" in headers:
        add_finding(
            findings,
            "low",
            "tech_disclosure",
            "X-Powered-By header exposed",
            header="x-powered-by",
            evidence=headers["x-powered-by"],
            recommendation="Remove X-Powered-By header.",
        )

def analyze_header_values(headers, findings):
    xcto = headers.get("x-content-type-options")
    if xcto and xcto.lower() != "nosniff":
        add_finding(
            findings,
            "medium",
            "invalid_header_value",
            "X-Content-Type-Options should be 'nosniff'",
            header="x-content-type-options",
            evidence=xcto,
        )
    xfo = headers.get("x-frame-options")
    if xfo and xfo.lower() not in ["deny", "sameorigin"]:
        add_finding(
            findings,
            "medium",
            "invalid_header_value",
            "Invalid X-Frame-Options value",
            header="x-frame-options",
            evidence=xfo,
        )

def analyze_https(response, findings):
    final_url = str(response.url).lower()
    if not final_url.startswith("https://"):
        add_finding(
            findings,
            "high",
            "no_https",
            "Final destination is not HTTPS",
            recommendation="Enforce HTTPS redirection.",
        )

def header_security_audit(url: str, method: str = "GET") -> dict:
    start = time.time()
    findings = []
    try:
        response = requests.request(
            method=method.upper(),
            url=url,
            timeout=10,
            allow_redirects=True,
            headers={"User-Agent": UA},
        )
        headers = {k.lower(): v for k, v in response.headers.items()}
        analyze_https(response, findings)
        analyze_required_headers(headers, findings)
        analyze_hsts(headers, findings)
        analyze_csp(headers, findings)
        analyze_cookies(response, findings)
        analyze_cors(headers, findings)
        analyze_disclosure(headers, findings)
        analyze_header_values(headers, findings)
        redirect_chain = [r.url for r in response.history] + [response.url]
        return {
            "url": url,
            "final_url": response.url,
            "status_code": response.status_code,
            "headers": headers,
            "findings": findings,
            "redirect_chain": redirect_chain,
            "redirect_count": len(response.history),
            "response_time_seconds": round(time.time() - start, 4),
            "summary": {
                "total": len(findings),
                "high": len([f for f in findings if f["severity"] == "high"]),
                "medium": len([f for f in findings if f["severity"] == "medium"]),
                "low": len([f for f in findings if f["severity"] == "low"]),
            },
        }
    except Exception as e:
        return {
            "url": url,
            "error": str(e),
        }
