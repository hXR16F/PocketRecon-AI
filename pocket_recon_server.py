import os
import sys
import logging
import argparse
import traceback
import subprocess
from typing import Dict, Any

from flask import Flask, request, jsonify

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.StreamHandler(sys.stderr)
    ]
)

logger = logging.getLogger(__name__)

DEFAULT_HOST = "0.0.0.0"
DEFAULT_PORT = 5005

app = Flask(__name__)


def success(result):
    return jsonify({
        "success": True,
        "result": result
    })


def failure(error):
    return jsonify({
        "success": False,
        "error": str(error)
    }), 500


@app.route("/api/ping", methods=["POST"])
def api_ping():
    try:
        from tools.ping import ping_target

        data = request.json or {}

        result = ping_target(
            target=data["target"],
            count=data.get("count", 4)
        )

        return success(result)

    except Exception as e:
        logger.error(traceback.format_exc())
        return failure(e)


@app.route("/api/nmap", methods=["POST"])
def api_nmap():
    try:
        from tools.nmap import run_nmap

        data = request.json or {}

        if "target" not in data:
            return failure(ValueError("Missing required field: target"))

        result = run_nmap(
            target=data["target"],
            ports=data.get("ports", ""),
            scan_type=data.get("scan_type", "syn"),
            os_detection=data.get("os_detection", True),
            service_detection=data.get("service_detection", True),
            script_scan=data.get("script_scan", False),
            scripts=data.get("scripts", None),
            script_args=data.get("script_args", None),
            top_ports_count=data.get("top_ports_count", 1000),
            timing=data.get("timing", 3),
            extra_args=data.get("extra_args", None),
        )

        return success(result)

    except Exception as e:
        import traceback
        logger.error(traceback.format_exc())
        return failure(str(e))


@app.route("/api/netcat", methods=["POST"])
def api_netcat():
    try:
        from tools.netcat import netcat_connect

        data = request.json or {}

        result = netcat_connect(
            target=data["target"],
            port=data["port"],
            data=data.get("data")
        )

        return success(result)

    except Exception as e:
        logger.error(traceback.format_exc())
        return failure(e)


@app.route("/api/traceroute", methods=["POST"])
def api_traceroute():
    try:
        from tools.traceroute import trace_route

        data = request.json or {}

        result = trace_route(
            target=data["target"]
        )

        return success(result)

    except Exception as e:
        logger.error(traceback.format_exc())
        return failure(e)


@app.route("/api/whois", methods=["POST"])
def api_whois():
    try:
        from tools.whois import whois_lookup

        data = request.json or {}

        result = whois_lookup(
            domain=data["domain"]
        )

        return success(result)

    except Exception as e:
        logger.error(traceback.format_exc())
        return failure(e)


@app.route("/api/curl", methods=["POST"])
def api_curl():
    try:
        from tools.curl import curl_request

        data = request.json or {}

        result = curl_request(
            url=data["url"],
            method=data.get("method", "GET"),

            data=data.get("data"),
            json_body=data.get("json_body", False),

            headers=data.get("headers"),
            query_params=data.get("query_params"),
            cookies=data.get("cookies"),

            follow_redirects=data.get("follow_redirects", False),
            timeout=data.get("timeout", 30),
            connect_timeout=data.get("connect_timeout", 10),
            verbose=data.get("verbose", False),

            extra_args=data.get("extra_args"),
        )

        return success(result)

    except Exception as e:
        logger.error(traceback.format_exc())
        return failure(e)


@app.route("/api/dirbuster", methods=["POST"])
def api_dirbuster():
    try:
        from tools.dirbuster import dirbuster_scan

        data = request.json or {}

        result = dirbuster_scan(
            target=data["target"]
        )

        return success(result)

    except Exception as e:
        logger.error(traceback.format_exc())
        return failure(e)


@app.route("/api/http_request", methods=["POST"])
def api_http_request():
    try:
        from tools.http_client import HttpClient

        data = request.json or {}

        client = HttpClient()

        result = client.request(
            method=data["method"],
            url=data["url"],
            headers=data.get("headers"),
            params=data.get("params"),
            data=data.get("data"),
            json=data.get("json"),
            follow_redirects=data.get("follow_redirects", True),
            max_redirects=data.get("max_redirects", 10)
        )

        return success(result)

    except Exception as e:
        logger.error(traceback.format_exc())
        return failure(e)


@app.route("/api/whatweb", methods=["POST"])
def api_whatweb():
    try:
        from tools.whatweb import run_whatweb

        data = request.json or {}

        result = run_whatweb(
            target=data["target"]
        )

        return success(result)

    except Exception as e:
        logger.error(traceback.format_exc())
        return failure(e)


@app.route("/api/dns_enum", methods=["POST"])
def api_dns_enum():
    try:
        from tools.dns_enum import dns_enum

        data = request.json or {}

        result = dns_enum(
            data["domain"]
        )

        return success(result)

    except Exception as e:
        logger.error(traceback.format_exc())
        return failure(e)


@app.route("/api/header_security_audit", methods=["POST"])
def api_header_security_audit():
    try:
        from tools.header_security_audit import header_security_audit

        data = request.json or {}

        url = data.get("url")

        if not url:
            return failure("Missing 'url' parameter"), 400

        result = header_security_audit(url)

        return success(result)

    except Exception as e:
        logger.error(traceback.format_exc())
        return failure(str(e)), 500


@app.route("/api/cve_lookup", methods=["POST"])
def api_cve_lookup():
    try:
        from tools.cve_lookup import cve_lookup

        data = request.json or {}

        result = cve_lookup(
            product=data["product"],
            version=data.get("version")
        )

        return success(result)

    except Exception as e:
        logger.error(traceback.format_exc())
        return failure(e)


@app.route("/api/abuseipdb_checker", methods=["POST"])
def api_abuseipdb_checker():
    try:
        from tools.abuseipdb_checker import abuseipdb_check

        data = request.json or {}

        result = abuseipdb_check(
            data["ip"]
        )

        return success(result)

    except Exception as e:
        logger.error(traceback.format_exc())
        return failure(e)


@app.route("/api/visit_website", methods=["POST"])
def api_visit_website():
    try:
        from tools.visit_website import visit_website

        data = request.json or {}

        if "url" not in data:
            return failure(ValueError("Missing required field: url"))

        result = visit_website(
            url=data["url"],
            max_links=data.get("max_links", 50),
            content_limit=data.get("content_limit", 3000),
            timeout=data.get("timeout", 10),
        )

        return success(result)

    except Exception as e:
        logger.error(traceback.format_exc())
        return failure(e)


@app.route("/api/web_search", methods=["POST"])
def api_web_search():
    try:
        from tools.web_search import web_search

        data = request.json or {}

        if "query" not in data:
            return failure(ValueError("Missing required field: query"))

        result = web_search(
            query=data["query"],
            limit=data.get("limit", 10),
        )

        return success(result)

    except Exception as e:
        logger.error(traceback.format_exc())
        return failure(e)


def parse_args():
    parser = argparse.ArgumentParser()

    parser.add_argument(
        "--host",
        type=str,
        default=DEFAULT_HOST
    )

    parser.add_argument(
        "--port",
        type=int,
        default=DEFAULT_PORT
    )

    return parser.parse_args()


def main():
    args = parse_args()

    logger.info(
        f"Starting PocketRecon-AI API server on {args.host}:{args.port}"
    )

    app.run(
        host=args.host,
        port=args.port,
        debug=False
    )


if __name__ == "__main__":
    main()
