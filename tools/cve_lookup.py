import re

import requests


NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"

def _extract_version(text: str) -> str | None:
    """Try to extract version-like strings."""
    match = re.search(r"\d+\.\d+(\.\d+)?", text)
    return match.group(0) if match else None


def cve_lookup(
    product: str,
    version: str | None = None,
    limit: int = 10,
) -> dict:
    version = version or _extract_version(product)

    query = product
    if version:
        query += f" {version}"

    try:
        resp = requests.get(
            NVD_API,
            params={"keywordSearch": query, "resultsPerPage": limit},
            timeout=10,
        )

        data = resp.json()

        vulnerabilities = []

        for item in data.get("vulnerabilities", []):
            cve = item.get("cve", {})

            metrics = cve.get("metrics", {})
            cvss = None

            for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                if key in metrics:
                    cvss = metrics[key][0]["cvssData"]["baseScore"]
                    break

            vulnerabilities.append({
                "id": cve.get("id"),
                "description": (
                    cve.get("descriptions", [{}])[0].get("value")
                    if cve.get("descriptions") else None
                ),
                "cvss": cvss,
                "published": cve.get("published"),
                "last_modified": cve.get("lastModified"),
            })

        high_risk = sum(1 for v in vulnerabilities if (v["cvss"] or 0) >= 7.0)

        return {
            "query": query,
            "product": product,
            "version": version,
            "vulnerabilities": vulnerabilities,
            "risk_score": min(high_risk * 20, 100),
            "summary": f"Found {len(vulnerabilities)} potential CVEs",
        }

    except Exception as e:
        return {
            "error": str(e),
            "query": query,
        }
