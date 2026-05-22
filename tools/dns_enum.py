import socket
import dns.resolver


COMMON_SUBDOMAINS = [
    "www",
    "mail",
    "ftp",
    "api",
    "dev",
    "test",
    "staging",
    "admin",
    "portal",
    "vpn",
]


def dns_lookup(domain: str) -> dict:
    result = {"domain": domain, "a": [], "aaaa": [], "mx": [], "ns": []}

    try:
        for rdata in dns.resolver.resolve(domain, "A"):
            result["a"].append(str(rdata))
    except Exception:
        pass

    try:
        for rdata in dns.resolver.resolve(domain, "AAAA"):
            result["aaaa"].append(str(rdata))
    except Exception:
        pass

    try:
        for rdata in dns.resolver.resolve(domain, "MX"):
            result["mx"].append(str(rdata.exchange))
    except Exception:
        pass

    try:
        for rdata in dns.resolver.resolve(domain, "NS"):
            result["ns"].append(str(rdata.target))
    except Exception:
        pass

    return result


def reverse_dns(ip: str) -> dict:
    """Reverse DNS lookup."""

    try:
        host, _, _ = socket.gethostbyaddr(ip)
        return {"ip": ip, "hostname": host}
    except Exception as e:
        return {"ip": ip, "error": str(e)}


def dns_enum_subdomains(domain: str) -> dict:
    """Basic subdomain enumeration using common wordlist."""

    found = []

    for sub in COMMON_SUBDOMAINS:
        candidate = f"{sub}.{domain}"

        try:
            socket.gethostbyname(candidate)
            found.append(candidate)
        except Exception:
            continue

    return {
        "domain": domain,
        "subdomains": found,
        "count": len(found),
    }


def dns_enum(domain: str) -> dict:
    """Full DNS enumeration wrapper."""

    return {
        "lookup": dns_lookup(domain),
        "subdomains": dns_enum_subdomains(domain),
    }
