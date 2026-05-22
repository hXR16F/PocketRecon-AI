import re
from typing import Optional, List, Dict, Any

import requests

try:
    from latest_user_agents import get_random_user_agent

    UA = get_random_user_agent()
    if not isinstance(UA, str):
        UA = "Mozilla/5.0"
except (ImportError, Exception):
    UA = "Mozilla/5.0"


def _extract_domain(url: str) -> str:
    if "://" in url:
        url = url.split("://", 1)[1]
    domain = url.split("/")[0]
    return domain

def _extract_title(html: str) -> str:
    match = re.search(r"<title[^>]*>(.*?)</title>", html, re.IGNORECASE | re.DOTALL)
    return match.group(1).strip() if match else ""

def _extract_headings(html: str) -> Dict[str, List[str]]:
    def find(tag):
        return re.findall(fr"<{tag}[^>]*>(.*?)</{tag}>", html, re.IGNORECASE | re.DOTALL)

    return {
        "h1": [x.strip() for x in find("h1")],
        "h2": [x.strip() for x in find("h2")],
        "h3": [x.strip() for x in find("h3")]
    }

def _extract_links(html: str, base_url: str, limit: int = 50) -> List[str]:
    links = []

    for match in re.findall(r'<a[^>]+href="([^"]+)"', html, re.IGNORECASE):
        url = match.strip()

        if url.startswith("/"):
            url = requests.compat.urljoin(base_url, url)

        if url.startswith("http"):
            links.append(url)

        if len(links) >= limit:
            break

    return list(dict.fromkeys(links))

def _clean_text(html: str, limit: int = 3000) -> str:
    html = re.sub(r"<script.*?>.*?</script>", "", html, flags=re.DOTALL | re.IGNORECASE)
    html = re.sub(r"<style.*?>.*?</style>", "", html, flags=re.DOTALL | re.IGNORECASE)

    text = re.sub(r"<[^>]+>", " ", html)

    text = re.sub(r"\s+", " ", text).strip()

    return text[:limit]

def visit_website(
    url: str,
    max_links: int = 50,
    content_limit: int = 3000,
    timeout: int = 10,
) -> dict:
    url = url.strip()

    if url.startswith(("http://", "https://")):
        urls_to_try = [url]
    else:
        urls_to_try = [f"https://{url}", f"http://{url}"]

    last_exception = None

    for target_url in urls_to_try:
        try:
            domain = _extract_domain(target_url)

            headers = {
                "User-Agent": UA,
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "Accept-Language": "en-US,en;q=0.9",
                "Referer": f"https://{domain}/",
                "Origin": f"https://{domain}",
                "Connection": "keep-alive",
                "Upgrade-Insecure-Requests": "1",
                "Sec-Fetch-Dest": "document",
                "Sec-Fetch-Mode": "navigate",
                "Sec-Fetch-Site": "none",
                "Sec-Fetch-User": "?1",
                "Cache-Control": "max-age=0"
            }

            resp = requests.get(
                target_url,
                headers=headers,
                timeout=timeout,
                allow_redirects=True,
            )

            try:
                html = resp.text
            except Exception:
                encoding = resp.encoding or resp.apparent_encoding or "utf-8"
                html = resp.content.decode(encoding, errors="ignore")

            return {
                "url": url,
                "final_url": resp.url,
                "status_code": resp.status_code,
                "title": _extract_title(html),
                "headings": _extract_headings(html),
                "links": _extract_links(html, resp.url, max_links),
                "content": _clean_text(html, content_limit),
            }

        except Exception as e:
            last_exception = e
            continue

    return {
        "url": url,
        "error": str(last_exception),
    }
