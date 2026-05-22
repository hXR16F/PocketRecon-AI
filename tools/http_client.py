import time
from urllib.parse import urlparse

import requests


DEFAULT_TIMEOUT = 8
MAX_RESPONSE_SIZE = 2_000_000  # 2MB
MAX_REDIRECTS = 6


class HttpClient:
    def __init__(
        self,
        allow_private_networks: bool = False,
        max_response_size: int = MAX_RESPONSE_SIZE,
    ):
        self.allow_private_networks = allow_private_networks
        self.max_response_size = max_response_size

    def _validate_url(self, url: str):
        parsed = urlparse(url)

        if parsed.scheme not in ("http", "https"):
            raise ValueError(f"Blocked scheme: {parsed.scheme}")

        host = (parsed.hostname or "").lower()

        if not self.allow_private_networks:
            blocked_prefixes = (
                "localhost",
                "127.",
                "0.0.0.0",
                "::1",
            )

            if any(host.startswith(p) for p in blocked_prefixes):
                raise ValueError(f"Blocked internal host: {host}")

        return True

    def _read_response(self, resp: requests.Response):
        raw = resp.content[: self.max_response_size]

        try:
            text = raw.decode("utf-8", errors="ignore")
        except Exception:
            text = str(raw)

        return {
            "status_code": resp.status_code,
            "headers": dict(resp.headers),
            "body": text,
            "truncated": len(resp.content) > self.max_response_size,
        }

    def _trace_redirects(
        self,
        session: requests.Session,
        method: str,
        url: str,
        kwargs: dict,
        max_redirects: int = MAX_REDIRECTS,
    ):
        chain = []
        current_url = url

        for _ in range(max_redirects):
            resp = session.request(
                method=method,
                url=current_url,
                allow_redirects=False,
                **kwargs,
            )

            entry = {
                "url": current_url,
                "status_code": resp.status_code,
                "headers": dict(resp.headers),
            }

            chain.append(entry)

            if resp.is_redirect or resp.is_permanent_redirect:
                location = resp.headers.get("Location")

                if not location:
                    break

                current_url = requests.compat.urljoin(current_url, location)
                continue

            return resp, chain

        return resp, chain

    def request(
        self,
        method: str,
        url: str,
        headers: dict | None = None,
        params: dict | None = None,
        data: dict | None = None,
        json: dict | None = None,
        follow_redirects: bool = True,
        max_redirects: int = MAX_REDIRECTS,
    ) -> dict:
        self._validate_url(url)

        session = requests.Session()

        start = time.time()

        try:
            if follow_redirects:
                resp, chain = self._trace_redirects(
                    session=session,
                    method=method,
                    url=url,
                    kwargs={
                        "headers": headers,
                        "params": params,
                        "data": data,
                        "json": json,
                        "timeout": DEFAULT_TIMEOUT,
                    },
                    max_redirects=max_redirects,
                )
            else:
                resp = session.request(
                    method=method,
                    url=url,
                    headers=headers,
                    params=params,
                    data=data,
                    json=json,
                    timeout=DEFAULT_TIMEOUT,
                    allow_redirects=False,
                )
                chain = []

            duration = round(time.time() - start, 4)

            return {
                "request": {
                    "method": method,
                    "url": url,
                    "timeout": DEFAULT_TIMEOUT,
                },
                "final_url": resp.url,
                "redirect_chain": chain,
                "response": self._read_response(resp),
                "timing": {
                    "seconds": duration,
                },
            }

        except Exception as e:
            return {
                "request": {
                    "method": method,
                    "url": url,
                },
                "error": str(e),
            }

    def get(self, url: str, **kwargs):
        return self.request("GET", url, **kwargs)

    def post(self, url: str, **kwargs):
        return self.request("POST", url, **kwargs)

    def put(self, url: str, **kwargs):
        return self.request("PUT", url, **kwargs)

    def delete(self, url: str, **kwargs):
        return self.request("DELETE", url, **kwargs)
