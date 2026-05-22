import re
import time

import requests

try:
    from latest_user_agents import get_random_user_agent

    UA = get_random_user_agent()
    if not isinstance(UA, str):
        UA = "Mozilla/5.0"
except (ImportError, Exception):
    UA = "Mozilla/5.0"


BLOCKLIST_URL = (
    "https://raw.githubusercontent.com/borestad/blocklist-abuseipdb/refs/heads/main/abuseipdb-s100-60d.ipv4"
)


class AbuseIPDBChecker:
    def __init__(self):
        self.cache = {}
        self.last_update = 0

    def _download(self):
        """Download and parse blocklist into structured dict."""

        try:
            resp = requests.get(
                BLOCKLIST_URL,
                timeout=20,
                headers={"User-Agent": UA},
            )

            if resp.status_code != 200:
                raise RuntimeError(f"HTTP {resp.status_code}")

            if not resp.text:
                raise RuntimeError("Empty response from blocklist source")

            parsed = {}
            corrupted = 0

            for line in resp.text.splitlines():
                line = line.strip()

                if not line or line.startswith("#"):
                    continue

                try:
                    parts = line.split("#")

                    ip = parts[0].strip()
                    if not ip:
                        continue

                    meta = parts[1].strip() if len(parts) > 1 else ""

                    match = re.match(r"([A-Z]{2})\s+AS(\d+)\s+(.*)", meta)

                    if match:
                        country = match.group(1)
                        asn = f"AS{match.group(2)}"
                        isp = match.group(3).strip()
                    else:
                        country = None
                        asn = None
                        isp = meta or None

                    parsed[ip] = {
                        "country": country,
                        "asn": asn,
                        "isp": isp,
                    }

                except Exception:
                    corrupted += 1
                    continue

            if not parsed:
                raise RuntimeError("Parsed blocklist is empty (format may have changed)")

            self.cache = parsed
            self.last_update = time.time()

            return {
                "loaded": True,
                "entries": len(parsed),
                "corrupted_lines": corrupted,
            }

        except requests.exceptions.Timeout:
            raise RuntimeError("Blocklist download timed out")

        except requests.exceptions.ConnectionError:
            raise RuntimeError("Network error while downloading blocklist")

        except Exception as e:
            raise RuntimeError(f"Blocklist download failed: {str(e)}")


    def _ensure_cache(self, max_age=43200):
        if not self.cache or (time.time() - self.last_update) > max_age:
            self._download()


    def check_ip(self, ip: str) -> dict:
        self._ensure_cache()

        entry = self.cache.get(ip)

        if entry:
            return {
                "ip": ip,
                "found": True,
                "country": entry["country"],
                "asn": entry["asn"],
                "isp": entry["isp"],
            }

        return {
            "ip": ip,
            "found": False,
        }


    def check_ips(self, ips: list[str]) -> dict:
        return {
            "results": [self.check_ip(ip) for ip in ips],
            "total": len(ips),
        }


_checker = AbuseIPDBChecker()


def abuseipdb_check(ip: str) -> dict:
    return _checker.check_ip(ip)


def abuseipdb_check_many(ips: list[str]) -> dict:
    return _checker.check_ips(ips)
