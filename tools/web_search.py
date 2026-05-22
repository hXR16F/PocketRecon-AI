import re
import requests
from urllib.parse import quote_plus
from typing import Dict, List

try:
    from latest_user_agents import get_random_user_agent
    UA = get_random_user_agent()
    if not isinstance(UA, str):
        UA = "Mozilla/5.0"
except Exception:
    UA = "Mozilla/5.0"


DUCKDUCKGO_URL = "https://duckduckgo.com/html/?q="


def _decode(resp: requests.Response) -> str:
    resp.raise_for_status()
    return resp.content.decode(resp.encoding or "utf-8", errors="replace")

def web_search(query: str, limit: int = 10) -> Dict:
    query = query.strip()
    url = DUCKDUCKGO_URL + quote_plus(query)

    headers = {
        "User-Agent": UA,
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
		"Connection": "keep-alive",
		"Referer": "https://duckduckgo.com/",
		"Origin": "https://duckduckgo.com",
		"Upgrade-Insecure-Requests": "1",
		"Sec-Fetch-Dest": "document",
		"Sec-Fetch-Mode": "navigate",
		"Sec-Fetch-Site": "same-origin",
		"Sec-Fetch-User": "?1",
		"Cache-Control": "max-age=0"
    }

    try:
        resp = requests.get(url, headers=headers, timeout=10)
        content_type = resp.headers.get("Content-Type", "")

        raw = resp.content
        print(raw)

        encoding = resp.encoding or resp.apparent_encoding or "utf-8"

        html = raw.decode(encoding, errors="ignore")

        titles = re.findall(r'class="result__a"[^>]*>(.*?)</a>', html, re.S)
        links = re.findall(r'class="result__a"[^>]*href="(.*?)"', html, re.S)
        snippets = re.findall(r'class="result__snippet">(.*?)</', html, re.S)

        results = []

        for i in range(min(limit, len(links), len(titles))):
            results.append({
                "title": re.sub("<.*?>", "", titles[i]).strip(),
                "url": links[i].strip(),
                "snippet": re.sub("<.*?>", "", snippets[i]).strip() if i < len(snippets) else "",
            })

        return {
            "query": query,
            "count": len(results),
            "results": results
        }

    except Exception as e:
        return {
            "query": query,
            "error": str(e),
            "results": []
        }
