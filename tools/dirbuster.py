import random
import string
from pathlib import Path
from typing import List, Dict
from urllib.parse import urljoin
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests

try:
    from latest_user_agents import get_random_user_agent

    UA = get_random_user_agent()
    if not isinstance(UA, str):
        UA = "Mozilla/5.0"
except (ImportError, Exception):
    UA = "Mozilla/5.0"


MAX_THREADS = 10
TIMEOUT = 5
SCHEME_CHECK_TIMEOUT = TIMEOUT

DEFAULT_WORDLIST = Path(__file__).resolve().parent / "wordlists" / "dirb_common.txt"
DEFAULT_STATUS_FILTER = {200, 204, 301, 302, 307, 401, 403}


def test_url_reachable(url: str, timeout: float = SCHEME_CHECK_TIMEOUT) -> bool:
    try:
        resp = requests.get(url, timeout=timeout, allow_redirects=True, stream=True)
        resp.close()
        return True
    except (requests.RequestException, requests.Timeout):
        return False

def normalize_target(target: str) -> str:
    target = target.strip()

    if target.startswith(("http://", "https://")):
        return target.rstrip("/")

    https_url = f"https://{target}"
    if test_url_reachable(https_url):
        return https_url.rstrip("/")

    http_url = f"http://{target}"
    if test_url_reachable(http_url):
        return http_url.rstrip("/")

    return https_url.rstrip("/")

def load_wordlist(path: Path) -> List[str]:
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        return [line.strip() for line in f if line.strip() and not line.startswith("#")]

def random_probe_path() -> str:
    alphabet = string.ascii_lowercase + string.digits
    token = "".join(random.choice(alphabet) for _ in range(24))
    return f"__probe_{token}__"

def is_soft_404(content: str, baseline_size: int) -> bool:
    size = len(content)
    return bool(baseline_size and abs(size - baseline_size) < 50)

def get_baseline_404(session: requests.Session, base_url: str) -> int:
    test_url = urljoin(base_url + "/", random_probe_path())
    try:
        resp = session.get(test_url, timeout=TIMEOUT, allow_redirects=False)
        return len(resp.text)
    except Exception:
        return 0

def probe_path(session, base_url, path, timeout, baseline_size):
    url = urljoin(base_url + "/", path.lstrip("/"))
    try:
        resp = session.get(url, timeout=timeout, allow_redirects=False)
        content = resp.text
        if resp.status_code == 200 and is_soft_404(content, baseline_size):
            return None
        return {
            "url": url,
            "status": resp.status_code,
            "size": len(content),
        }
    except requests.RequestException:
        return None

def dirbuster_scan(target: str) -> Dict:
    target = normalize_target(target)
    words = load_wordlist(DEFAULT_WORDLIST)

    session = requests.Session()
    session.headers.update({
        "User-Agent": UA,
        "Accept": "*/*",
        "Connection": "keep-alive",
    })

    results = []
    baseline_size = get_baseline_404(session, target)

    with ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
        futures = [
            executor.submit(probe_path, session, target, word, TIMEOUT, baseline_size)
            for word in words
        ]

        for future in as_completed(futures):
            result = future.result()
            if not result:
                continue
            if result["status"] in DEFAULT_STATUS_FILTER:
                results.append(result)

    return {
        "target": target,
        "found": len(results),
        "baseline_size": baseline_size,
        "results": results
    }
